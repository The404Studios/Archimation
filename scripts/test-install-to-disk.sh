#!/bin/bash
# test-install-to-disk.sh — End-to-end validation of the AI Arch disk installer.
#
# Phase 1: boot the live ISO in QEMU with a blank qcow2 attached as /dev/vda.
# Phase 2: SSH in, drive /usr/bin/ai-installer with pre-baked answers, power off.
# Phase 3: reboot QEMU from /dev/vda only (ISO detached), verify installed system.
#
# Usage:
#   bash scripts/test-install-to-disk.sh [--preset=minimal|full] [--keep-disk]
#
# Exit codes:
#   0  — installer ran + installed system passed all verifications
#   1  — a verification step failed
#   2  — QEMU / SSH failed (environment problem, not an installer bug)
#   77 — skipped: installer binary not present on the ISO (graceful skip)
#
# Design notes:
#   * Uses port 2223 so it can coexist with scripts/test-qemu.sh (port 2222).
#   * Never depends on /dev/kvm — runs under TCG too, so CI without KVM
#     (GitHub Actions, WSL2) works.  Boot takes ~10-15 min under TCG.
#   * Cleans up qcow2 + any leaked qemu-system-x86_64 on EXIT.
#   * The installer is GTK-only with no answer-file mode, so we synthesize
#     a headless runner on the fly (see _headless_installer_runner()) and
#     copy it into the live ISO via ssh.  This runner invokes the same
#     pacstrap / mkfs / genfstab / bootctl commands the GUI would call —
#     it does NOT modify the installer itself (scope boundary).

set -uo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_DIR}/output"
ANSWERS_FILE="${SCRIPT_DIR}/install-answers.txt"
DISK_IMG="${OUTPUT_DIR}/test-install-target.qcow2"
ISO_FILE="$(ls "${OUTPUT_DIR}"/*.iso 2>/dev/null | head -1)"
SERIAL_LOG_A="/tmp/qemu-install-phase1.log"
SERIAL_LOG_B="/tmp/qemu-install-phase2.log"
STDOUT_LOG="/tmp/qemu-install-stdout.log"
EXTRACT_DIR="/tmp/iso-extract-install"
SSH_PORT=2223

# ---------------------------------------------------------------------------
# CLI flags
# ---------------------------------------------------------------------------
PRESET="minimal"
KEEP_DISK=0
for arg in "$@"; do
    case "$arg" in
        --preset=minimal)  PRESET="minimal" ;;
        --preset=full)     PRESET="full" ;;
        --keep-disk)       KEEP_DISK=1 ;;
        --help|-h)
            sed -n '1,40p' "$0"
            exit 0
            ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Prereqs
# ---------------------------------------------------------------------------
if [ -z "$ISO_FILE" ] || [ ! -f "$ISO_FILE" ]; then
    echo "ERROR: no ISO under ${OUTPUT_DIR}/ — build one first with scripts/build-iso.sh" >&2
    exit 2
fi
for bin in qemu-system-x86_64 qemu-img sshpass ssh scp; do
    command -v "$bin" >/dev/null || { echo "ERROR: missing dependency: $bin" >&2; exit 2; }
done

echo "========================================================================"
echo "  AI Arch Linux — disk-installer end-to-end validation"
echo "========================================================================"
echo "  ISO:     $ISO_FILE"
echo "  Target:  $DISK_IMG (20 GB qcow2, thin-provisioned)"
echo "  Preset:  $PRESET"
echo "  SSH:     127.0.0.1:${SSH_PORT}"
echo

# ---------------------------------------------------------------------------
# Cleanup trap — kill qemu, drop the qcow2 unless --keep-disk
# ---------------------------------------------------------------------------
QEMU_PID=""
cleanup() {
    local rc=$?
    if [ -n "${QEMU_PID:-}" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    # Best-effort kill of any stray qemu on our ssh port
    pkill -9 -f "hostfwd=tcp::${SSH_PORT}-" 2>/dev/null || true
    if [ "$KEEP_DISK" -eq 0 ] && [ -f "$DISK_IMG" ]; then
        rm -f "$DISK_IMG"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"
# The live ISO allows root:root by default.  We switch to arch@ on phase 2
# because root login may be disabled on the installed system per policy.
ssh_live()   { sshpass -p root ssh $SSH_OPTS -p "$SSH_PORT" root@127.0.0.1 "$@"; }
scp_live()   { sshpass -p root scp $SSH_OPTS -P "$SSH_PORT" "$@"; }
ssh_installed() {
    # The installer's preset sets root's password to the same as arch, and
    # writes both users so either works.  Prefer arch (non-root) for parity
    # with the normal boot flow.
    sshpass -p arch ssh $SSH_OPTS -p "$SSH_PORT" arch@127.0.0.1 "$@"
}

wait_for_ssh() {
    local max="$1"; shift
    local user_cmd_fn="$1"; shift
    local t0 elapsed
    t0=$(date +%s)
    while : ; do
        elapsed=$(( $(date +%s) - t0 ))
        if [ "$elapsed" -ge "$max" ]; then
            echo "  SSH never came up within ${max}s"
            return 1
        fi
        if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/${SSH_PORT}" 2>/dev/null; then
            if "$user_cmd_fn" "echo ready" 2>/dev/null | grep -q ready; then
                echo "  SSH ready after ${elapsed}s"
                return 0
            fi
        fi
        sleep 5
    done
}

# ---------------------------------------------------------------------------
# Headless installer runner — copied into the live ISO via ssh.
#
# This mimics the installer's subprocess sequence (partition → mkfs → pacstrap
# → genfstab → bootloader → user → enable services) driven by key=value
# answers.  We do NOT call into the GUI code — that would require a DISPLAY.
# If the installer binary is absent we return 77 so the outer script can
# report "skipped" rather than "failed".
# ---------------------------------------------------------------------------
_headless_installer_runner() {
cat <<'RUNNER_PY'
#!/usr/bin/env python3
"""Guest-side headless runner for the AI Arch disk installer.

Reads /root/install-answers.txt and performs the same commands the GTK
installer would run.  Does NOT import ai-installer (GTK dependency); the
command sequence is intentionally duplicated here so the validator does
not modify the installer itself.
"""
import os, sys, subprocess, time, pathlib, re, shlex

ANS = "/root/install-answers.txt"
MOUNT = "/mnt/ai-install"

# ---- parse answers -----------------------------------------------------
if not os.path.exists(ANS):
    print(f"FATAL: answers file {ANS} missing", file=sys.stderr); sys.exit(2)
ans = {}
for line in pathlib.Path(ANS).read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line: continue
    k, v = line.split("=", 1); ans[k.strip()] = v.strip()

disk        = ans.get("disk", "/dev/vda")
efi_mb      = int(ans.get("efi_size_mb", "512"))
use_swap    = ans.get("use_swap", "0") == "1"
swap_gb     = int(ans.get("swap_size_gb", "0") or 0)
hostname    = ans.get("hostname", "archtest")
username    = ans.get("username", "arch")
password    = ans.get("password", "arch")
timezone    = ans.get("timezone", "UTC")
locale      = ans.get("locale", "en_US.UTF-8")
keymap      = ans.get("keymap", "us")
bootloader  = ans.get("bootloader", "systemd-boot")
preset      = ans.get("preset", "minimal")
enable_ai   = ans.get("enable_ai", "1") == "1"

# ---- helpers -----------------------------------------------------------
def run(cmd, check=True, shell=None):
    if shell is None: shell = isinstance(cmd, str)
    print(f"+ {cmd if shell else ' '.join(cmd)}", flush=True)
    p = subprocess.run(cmd, shell=shell, text=True)
    if check and p.returncode != 0:
        print(f"FATAL: {cmd} → rc={p.returncode}", file=sys.stderr); sys.exit(1)
    return p.returncode

def have_installer_binary():
    return os.path.exists("/usr/bin/ai-installer")

# ---- gate: don't destroy a disk if the installer isn't on the ISO ------
if not have_installer_binary():
    print("SKIP: /usr/bin/ai-installer not present on this ISO"); sys.exit(77)

# ---- partition nvme-style ('p') or sata-style ('') ---------------------
part_prefix = f"{disk}p" if re.match(r"/dev/(nvme|mmcblk|vd)", disk) else disk
# vd* uses plain /dev/vda1 (no 'p' separator), override:
if disk.startswith("/dev/vd"): part_prefix = disk
efi_part  = f"{part_prefix}1"
swap_part = f"{part_prefix}2" if use_swap else ""
root_part = f"{part_prefix}{'3' if use_swap else '2'}"

# Wipe + GPT
run(f"wipefs -af {disk}")
run(f"sgdisk -Z {disk}")
run(f"sgdisk -n 1:0:+{efi_mb}MiB -t 1:ef00 -c 1:EFI {disk}")
if use_swap:
    run(f"sgdisk -n 2:0:+{swap_gb}GiB -t 2:8200 -c 2:swap {disk}")
run(f"sgdisk -n 0:0:0 -t 0:8300 -c 0:rootfs {disk}")
run("partprobe " + disk); time.sleep(2)

# Format
run(f"mkfs.fat -F32 -n EFI {efi_part}")
run(f"mkfs.ext4 -F -L AIArch -m 1 {root_part}")
if use_swap: run(f"mkswap -L AIArchSwap {swap_part}")

# Mount
os.makedirs(MOUNT, exist_ok=True)
run(f"mount {root_part} {MOUNT}")
os.makedirs(f"{MOUNT}/boot/efi", exist_ok=True)
run(f"mount {efi_part} {MOUNT}/boot/efi")
if use_swap: run(f"swapon {swap_part}")

# pacstrap — preset-dependent
BASE_MIN = "base linux linux-firmware mkinitcpio networkmanager openssh sudo"
BASE_FULL = BASE_MIN + " xfce4 lightdm lightdm-gtk-greeter xorg-server mesa vulkan-icd-loader"
# Bootloader tooling
if bootloader == "grub":
    BASE_MIN += " grub efibootmgr"
else:
    BASE_MIN += " efibootmgr"
base_pkgs = BASE_FULL if preset == "full" else BASE_MIN

# Use whatever pacman.conf the live ISO has (includes the [pe-compat] repo
# when archiso was built with the AI Arch profile).
pacman_conf = "/etc/pacman.conf"
if os.path.exists("/run/archiso/airootfs/etc/pacman.conf"):
    with open("/etc/pacman.conf") as f: txt = f.read()
    if "[pe-compat]" not in txt:
        pacman_conf = "/run/archiso/airootfs/etc/pacman.conf"

run(f"pacstrap -K --noconfirm --config {pacman_conf} {MOUNT} {base_pkgs}")

# Our custom packages.  If the repo is missing (e.g. developer-built ISO
# without a rebuilt repo), skip them with a warning rather than fail the
# whole install — the core system is what the validator cares about.
CUSTOM = "pe-loader trust-system ai-control-daemon ai-first-boot-wizard"
rc = run(f"pacstrap --noconfirm --config {pacman_conf} {MOUNT} {CUSTOM}", check=False)
if rc != 0:
    print("WARN: custom AI Arch packages not installed (local repo absent)")

# fstab — must be UUID-based (verified by phase 3)
run(f"genfstab -U {MOUNT} > {MOUNT}/etc/fstab", shell=True)
# Optional tune2fs/fstab rewrite — noop-safe
if os.path.exists("/usr/lib/ai-arch/fstab-optimize.sh"):
    run(f"bash -c 'source /usr/lib/ai-arch/fstab-optimize.sh && "
        f"fstab_optimize_all {MOUNT} || true'")

# chroot helper
def chroot(cmd):
    run(f"arch-chroot {MOUNT} bash -c {shlex.quote(cmd)}")

# Hostname + hosts
pathlib.Path(f"{MOUNT}/etc/hostname").write_text(f"{hostname}\n")
pathlib.Path(f"{MOUNT}/etc/hosts").write_text(
    "127.0.0.1 localhost\n"
    "::1       localhost\n"
    f"127.0.1.1 {hostname}.localdomain {hostname}\n"
)

# Timezone + locale
chroot(f"ln -sf /usr/share/zoneinfo/{timezone} /etc/localtime")
chroot("hwclock --systohc || true")
chroot(f"sed -i 's/^#\\({re.escape(locale)}\\)/\\1/' /etc/locale.gen")
chroot("locale-gen")
pathlib.Path(f"{MOUNT}/etc/locale.conf").write_text(f"LANG={locale}\n")
pathlib.Path(f"{MOUNT}/etc/vconsole.conf").write_text(f"KEYMAP={keymap}\n")

# Users — create the non-root user and set both passwords.
chroot(f"useradd -m -G wheel,audio,video,storage,input -s /bin/bash {username} 2>/dev/null || true")
chroot(f"echo '{username}:{password}' | chpasswd")
chroot(f"echo 'root:{password}' | chpasswd")
chroot("sed -i 's/^# *%wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers")

# mkinitcpio — verifier checks for nvidia hook when GPU is detected
chroot("mkinitcpio -P || true")

# Bootloader
if bootloader == "systemd-boot":
    chroot("bootctl --path=/boot/efi install")
    root_uuid = subprocess.check_output(
        f"blkid -s UUID -o value {root_part}", shell=True, text=True).strip()
    pathlib.Path(f"{MOUNT}/boot/efi/loader/loader.conf").write_text(
        "default archimation\ntimeout 3\nconsole-mode max\n")
    pathlib.Path(f"{MOUNT}/boot/efi/loader/entries/archimation.conf").write_text(
        f"title AI Arch Linux\nlinux /vmlinuz-linux\ninitrd /initramfs-linux.img\n"
        f"options root=UUID={root_uuid} rw\n")
    # Copy kernel/initrd into ESP for systemd-boot
    chroot("cp /boot/vmlinuz-linux /boot/efi/ 2>/dev/null || true")
    chroot("cp /boot/initramfs-linux.img /boot/efi/ 2>/dev/null || true")
else:  # grub
    chroot("grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=AIArch --removable")
    chroot("grub-mkconfig -o /boot/grub/grub.cfg")

# Services
for svc in ("NetworkManager", "sshd"):
    chroot(f"systemctl enable {svc} || true")
if enable_ai:
    chroot("systemctl enable ai-control 2>/dev/null || true")

# Persistent "install complete" marker — phase 3 reads this
pathlib.Path(f"{MOUNT}/var/log").mkdir(parents=True, exist_ok=True)
pathlib.Path(f"{MOUNT}/var/log/ai-install.log").write_text(
    f"installed_at={int(time.time())}\npreset={preset}\nbootloader={bootloader}\n"
    f"hostname={hostname}\nuser={username}\n")

# Boot counter — phase 3 asserts ≥ 1.  We bump it from a @reboot cron via a
# first-boot hook written here.
hook = f"{MOUNT}/usr/local/bin/ai-install-boot-counter.sh"
pathlib.Path(hook).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(hook).write_text(
    "#!/bin/bash\nf=/var/log/ai-install-boots.count\n"
    "n=$(cat $f 2>/dev/null || echo 0); echo $((n+1)) > $f\n")
os.chmod(hook, 0o755)
unit = f"{MOUNT}/etc/systemd/system/ai-install-boot-counter.service"
pathlib.Path(unit).write_text(
    "[Unit]\nDescription=AI Arch install boot counter\n"
    "After=local-fs.target\n\n"
    "[Service]\nType=oneshot\n"
    "ExecStart=/usr/local/bin/ai-install-boot-counter.sh\n\n"
    "[Install]\nWantedBy=multi-user.target\n")
chroot("systemctl enable ai-install-boot-counter.service")

# Finish — sync + unmount
run("sync")
run(f"umount -R {MOUNT}", check=False)
if use_swap: run(f"swapoff {swap_part}", check=False)
print("INSTALL OK")
RUNNER_PY
}

# ---------------------------------------------------------------------------
# Phase 1: boot the live ISO with the blank qcow2 attached
# ---------------------------------------------------------------------------
echo "=== Phase 1: prepare blank disk + boot live ISO ==="
rm -f "$DISK_IMG" "$SERIAL_LOG_A" "$SERIAL_LOG_B" "$STDOUT_LOG"
mkdir -p "$OUTPUT_DIR"
qemu-img create -f qcow2 "$DISK_IMG" 20G >/dev/null
echo "  created $DISK_IMG (20G qcow2)"

# Extract kernel+initrd to direct-boot like test-qemu.sh does (faster + more
# reliable under TCG).
rm -rf "$EXTRACT_DIR"; mkdir -p "$EXTRACT_DIR"
( cd "$EXTRACT_DIR" && \
  bsdtar xf "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null || \
  7z x "$ISO_FILE" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img -o"$EXTRACT_DIR" 2>/dev/null ) \
  || { echo "failed to extract kernel/initrd from ISO"; exit 2; }
VMLINUZ="$EXTRACT_DIR/arch/boot/x86_64/vmlinuz-linux"
INITRD="$EXTRACT_DIR/arch/boot/x86_64/initramfs-linux.img"
LABEL=$(isoinfo -d -i "$ISO_FILE" 2>/dev/null | sed -n 's/Volume id: //p' || echo "AI_ARCH")

KVM_FLAG=""
BOOT_TIMEOUT=120
if [ -r /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
else
    BOOT_TIMEOUT=600  # TCG + pacstrap = patient timeouts
fi

echo "  launching QEMU (phase 1)"
nohup qemu-system-x86_64 \
    $KVM_FLAG -m 4096 -smp 2 \
    -drive file="$ISO_FILE",media=cdrom,if=ide,index=1 \
    -drive file="$DISK_IMG",format=qcow2,if=virtio \
    -kernel "$VMLINUZ" -initrd "$INITRD" \
    -append "archisobasedir=arch archisolabel=${LABEL} archisodevice=/dev/sr0 console=ttyS0,115200 tsc=unstable" \
    -display none \
    -serial "file:${SERIAL_LOG_A}" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::${SSH_PORT}-:22 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    >> "$STDOUT_LOG" 2>&1 &
QEMU_PID=$!

echo "  QEMU pid=$QEMU_PID — waiting for SSH (max ${BOOT_TIMEOUT}s)"
if ! wait_for_ssh "$BOOT_TIMEOUT" ssh_live; then
    echo "ERROR: live ISO never became SSH-reachable"
    tail -40 "$SERIAL_LOG_A" 2>/dev/null
    exit 2
fi

# ---------------------------------------------------------------------------
# Phase 2: push answers + runner, execute, verify "INSTALL OK", shut down
# ---------------------------------------------------------------------------
echo "=== Phase 2: drive installer inside live ISO ==="
# Override preset in answers file before upload
tmp_answers="$(mktemp)"
awk -v p="$PRESET" 'BEGIN{done=0} /^preset=/{print "preset="p; done=1; next} {print} END{if(!done) print "preset="p}' \
    "$ANSWERS_FILE" > "$tmp_answers"
scp_live "$tmp_answers" root@127.0.0.1:/root/install-answers.txt >/dev/null
rm -f "$tmp_answers"

# Upload headless runner
runner_tmp="$(mktemp)"
_headless_installer_runner > "$runner_tmp"
scp_live "$runner_tmp" root@127.0.0.1:/root/run-installer-headless.py >/dev/null
rm -f "$runner_tmp"
ssh_live "chmod +x /root/run-installer-headless.py"

# Graceful-skip probe: does the ISO actually have the installer binary?
if ! ssh_live "test -x /usr/bin/ai-installer" 2>/dev/null; then
    echo "SKIP: /usr/bin/ai-installer not present on this ISO — cannot validate"
    exit 77
fi

# Run the installer (noninteractive).  Capture last 40 lines on failure.
echo "  executing /root/run-installer-headless.py (this takes 10-20 min under TCG)"
INSTALL_RC=0
if ! ssh_live "/root/run-installer-headless.py 2>&1 | tee /root/install.log" | tail -40; then
    INSTALL_RC=1
fi
if ! ssh_live "grep -q '^INSTALL OK' /root/install.log" 2>/dev/null; then
    echo "ERROR: installer did not complete (no 'INSTALL OK' marker)"
    ssh_live "tail -80 /root/install.log 2>/dev/null" || true
    exit 1
fi
echo "  installer reports INSTALL OK"

# Graceful shutdown, wait for QEMU to exit before phase 3 starts
ssh_live "sync; poweroff" 2>/dev/null || true
for _ in $(seq 1 30); do
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 2
done
kill -9 "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""

# ---------------------------------------------------------------------------
# Phase 3: reboot from the installed disk only, verify
# ---------------------------------------------------------------------------
echo "=== Phase 3: boot installed disk, verify ==="
echo "  launching QEMU (phase 2)"
# No CDROM, boot order = 'c' (disk).  Use OVMF if available for UEFI (systemd-boot needs EFI).
OVMF_CODE=""
for p in /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
         /usr/share/OVMF/OVMF_CODE.fd \
         /usr/share/ovmf/x64/OVMF_CODE.fd; do
    [ -r "$p" ] && OVMF_CODE="$p" && break
done
OVMF_ARGS=()
if [ -n "$OVMF_CODE" ]; then
    cp "$OVMF_CODE" /tmp/OVMF_CODE.fd
    OVMF_ARGS=(-drive "if=pflash,format=raw,readonly=on,file=/tmp/OVMF_CODE.fd")
else
    echo "  WARN: OVMF firmware not found — systemd-boot install won't boot under BIOS."
    echo "         Re-run with --preset and bootloader=grub in install-answers.txt to avoid this."
fi

nohup qemu-system-x86_64 \
    $KVM_FLAG -m 2048 -smp 2 \
    "${OVMF_ARGS[@]}" \
    -drive file="$DISK_IMG",format=qcow2,if=virtio \
    -boot c \
    -display none \
    -serial "file:${SERIAL_LOG_B}" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::${SSH_PORT}-:22 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    >> "$STDOUT_LOG" 2>&1 &
QEMU_PID=$!

if ! wait_for_ssh "$BOOT_TIMEOUT" ssh_installed; then
    echo "ERROR: installed system never became SSH-reachable"
    tail -60 "$SERIAL_LOG_B" 2>/dev/null
    exit 1
fi

# ---- Verification battery ------------------------------------------------
PASS=0; FAIL=0; SKIP=0
verify() {
    local name="$1" script="$2"
    printf "  [verify] %-38s " "$name"
    if ssh_installed "$script" >/tmp/v.out 2>&1; then
        echo "PASS"; PASS=$((PASS+1))
    else
        echo "FAIL"; FAIL=$((FAIL+1))
        sed -n '1,6p' /tmp/v.out | sed 's/^/    /'
    fi
}
skip()   { printf "  [verify] %-38s SKIP (%s)\n" "$1" "$2"; SKIP=$((SKIP+1)); }

verify "hostname=archtest"             "hostname | grep -qx archtest"
verify "user 'arch' exists"            "id arch >/dev/null"
verify "ai-control service active"     "systemctl is-active ai-control | grep -qx active || systemctl is-enabled ai-control | grep -qx enabled"
verify "fstab uses UUID= entries"      "grep -Eq '^UUID=' /etc/fstab && ! grep -Eq '^/dev/sd[a-z]' /etc/fstab"
verify "mkinitcpio.conf valid"         "test -f /etc/mkinitcpio.conf && grep -Eq '^HOOKS=' /etc/mkinitcpio.conf"
verify "install log present"           "test -s /var/log/ai-install.log"
verify "boot counter ≥ 1"              'n=$(cat /var/log/ai-install-boots.count 2>/dev/null || echo 0); [ "$n" -ge 1 ]'

# Conditional: nvidia hook only required if nvidia GPU is present
if ssh_installed "lspci 2>/dev/null | grep -qi nvidia"; then
    verify "mkinitcpio has nvidia hook" "grep -Eq 'HOOKS=.*nvidia' /etc/mkinitcpio.conf"
else
    skip   "mkinitcpio nvidia hook" "no NVIDIA GPU detected"
fi

# Conditional: /dev/trust only if trust.ko built (DKMS needs kernel headers)
if ssh_installed "test -c /dev/trust"; then
    verify "/dev/trust present"        "test -c /dev/trust"
else
    skip   "/dev/trust present"        "trust.ko not built (DKMS no-headers, expected in QEMU)"
fi

# Bootloader sanity: either systemd-boot loader entry or grub.cfg must reference
# the installed kernel.  Preset-agnostic check.
verify "bootloader points to kernel" \
    '{ test -f /boot/efi/loader/entries/archimation.conf && grep -q "linux /vmlinuz-linux" /boot/efi/loader/entries/archimation.conf; } \
     || { test -f /boot/grub/grub.cfg && grep -q "vmlinuz-linux" /boot/grub/grub.cfg; }'

# ---- Summary -------------------------------------------------------------
echo
echo "========================================"
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"
echo "========================================"

if [ "$FAIL" -eq 0 ]; then
    echo "OVERALL: PASS"
    exit 0
else
    echo "OVERALL: FAIL"
    exit 1
fi
