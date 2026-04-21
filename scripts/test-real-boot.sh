#!/bin/bash
# Test REAL boot path - diagnose syslinux failure
# -u catches typo'd vars (we have an `$i` loop below that would silently
# expand to empty without this), pipefail ensures `mount | grep` style chains
# don't hide early failures in diagnostic output.
set -euo pipefail

ISO="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/output/archimation-2026.04.12-x86_64.iso"
SERIAL="/tmp/qemu-real-boot.log"

rm -f "$SERIAL"
pkill -9 qemu-system 2>/dev/null || true
sleep 2

echo "=== DIAGNOSIS: Why does syslinux fail to boot the kernel? ==="
echo ""

# Mount ISO and check sizes
MNTDIR=$(mktemp -d)
mount -o loop,ro "$ISO" "$MNTDIR" 2>/dev/null

echo "=== Kernel and initramfs sizes ==="
ls -lh "$MNTDIR/arch/boot/x86_64/vmlinuz-linux" 2>/dev/null
ls -lh "$MNTDIR/arch/boot/x86_64/initramfs-linux.img" 2>/dev/null
ls -lh "$MNTDIR/arch/boot/intel-ucode.img" 2>/dev/null
ls -lh "$MNTDIR/arch/boot/amd-ucode.img" 2>/dev/null

echo ""
echo "=== Total initrd size (all images combined) ==="
TOTAL=0
for f in "$MNTDIR/arch/boot/intel-ucode.img" "$MNTDIR/arch/boot/amd-ucode.img" "$MNTDIR/arch/boot/x86_64/initramfs-linux.img"; do
    if [ -f "$f" ]; then
        SZ=$(stat -c%s "$f")
        echo "  $(basename $f): $SZ bytes ($(echo "scale=1; $SZ/1048576" | bc)M)"
        TOTAL=$((TOTAL + SZ))
    fi
done
echo "  TOTAL: $TOTAL bytes ($(echo "scale=1; $TOTAL/1048576" | bc)M)"
echo ""
echo "NOTE: ISOLINUX/syslinux has a ~128MB-256MB combined initramfs limit"
echo "      depending on version and available low memory. 163M initramfs alone may hit this."

echo ""
echo "=== syslinux.cfg ==="
cat "$MNTDIR/boot/syslinux/syslinux.cfg"

echo ""
echo "=== Checking kernel file is valid ==="
file "$MNTDIR/arch/boot/x86_64/vmlinuz-linux" 2>/dev/null

echo ""
echo "=== Checking initramfs is valid ==="
file "$MNTDIR/arch/boot/x86_64/initramfs-linux.img" 2>/dev/null

echo ""
echo "=== Checking GRUB (EFI) config ==="
cat "$MNTDIR/boot/grub/grub.cfg" 2>/dev/null || echo "(no grub.cfg)"
echo ""
echo "=== systemd-boot entries ==="
for f in "$MNTDIR"/loader/entries/*.conf; do
    echo "--- $(basename $f) ---"
    cat "$f" 2>/dev/null
    echo ""
done

echo ""
echo "=== loader.conf ==="
cat "$MNTDIR/loader/loader.conf" 2>/dev/null || echo "(none)"

echo ""
echo "=== EFI directory structure ==="
ls -la "$MNTDIR/EFI/" 2>/dev/null || echo "(no EFI/)"
ls -laR "$MNTDIR/EFI/" 2>/dev/null | head -30 || true

umount "$MNTDIR" 2>/dev/null || true
rmdir "$MNTDIR" 2>/dev/null || true

echo ""
echo "=== Now testing with direct kernel boot (for comparison) ==="
echo "This bypasses syslinux and boots the kernel directly via QEMU"

# Mount ISO again to get paths
MNTDIR2=$(mktemp -d)
mount -o loop,ro "$ISO" "$MNTDIR2" 2>/dev/null

timeout 120 qemu-system-x86_64 \
    -m 4096 -smp 2 \
    -cdrom "$ISO" \
    -kernel "$MNTDIR2/arch/boot/x86_64/vmlinuz-linux" \
    -initrd "$MNTDIR2/arch/boot/x86_64/initramfs-linux.img" \
    -append "archisobasedir=arch archisolabel=ARCHWIN_202604 console=ttyS0,115200 systemd.log_level=info plymouth.enable=0" \
    -display none \
    -serial file:"$SERIAL" \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot &

QEMU_PID=$!
echo "QEMU PID: $QEMU_PID (direct kernel boot)"

SSH_OK=0
for i in $(seq 1 24); do
    sleep 5
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "QEMU exited after $((i*5))s"
        break
    fi
    # Check SSH banner
    BANNER=$(timeout 3 bash -c "cat < /dev/tcp/127.0.0.1/2222" 2>/dev/null | head -1)
    if echo "$BANNER" | grep -qi "ssh"; then
        echo "SSH OK after $((i*5))s: $BANNER"
        SSH_OK=1
        break
    fi
    echo "Waiting... $((i*5))s (serial: $(wc -c < "$SERIAL" 2>/dev/null || echo 0) bytes)"
done

echo ""
echo "=== DIRECT KERNEL BOOT - SERIAL LOG (last 80 lines) ==="
tail -80 "$SERIAL" 2>/dev/null
echo "=== END ==="

umount "$MNTDIR2" 2>/dev/null || true
rmdir "$MNTDIR2" 2>/dev/null || true
kill $QEMU_PID 2>/dev/null || true
wait $QEMU_PID 2>/dev/null || true
