#!/bin/bash
# qemu_pe_corpus.sh -- Boot newest ISO, ship PE corpus + run_corpus.sh, run on live ISO.
# Mirrors set_smoke_run.sh structure for QEMU plumbing.

set +e

ISO_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/output"
ISO=$(ls -t "$ISO_DIR"/*.iso 2>/dev/null | grep -v '\.bak\|\.pkg' | head -1)
EXTRACT=/tmp/iso-pe-corpus
SERIAL=/tmp/serial-pe-corpus.log
RESULT=/tmp/pe_corpus_qemu.json
SSH_PORT=2244
DAEMON_PORT=8434

CORPUS_SRC_DIR="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/tests/pe-loader/sources"
RUN_CORPUS="/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/tests/pe-loader/run_corpus.sh"

echo "ISO=$ISO"
mkdir -p "$EXTRACT"
cd "$EXTRACT" || exit 1
bsdtar xf "$ISO" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img 2>/dev/null

# Truncate serial log to avoid stale-match from prior runs.
: > "$SERIAL"

qemu-system-x86_64 -m 4096 -smp 2 \
    -drive file="$ISO",media=cdrom,if=ide,index=1 \
    -kernel "$EXTRACT/arch/boot/x86_64/vmlinuz-linux" \
    -initrd "$EXTRACT/arch/boot/x86_64/initramfs-linux.img" \
    -append "archisobasedir=arch archisolabel=AI_ARCH_202604 archisodevice=/dev/sr0 console=ttyS0,115200 tsc=unstable" \
    -display none -serial "file:$SERIAL" \
    -net nic,model=virtio -net "user,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${DAEMON_PORT}-:8420" \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 -no-reboot >/dev/null 2>&1 &
QEMU=$!
echo "QEMU_PID=$QEMU"

echo "Waiting up to 300s for boot + SSH..."

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p $SSH_PORT)
SSH_USER=""
# Poll-for-SSH (up to 60 attempts × 5s = 300s) instead of blind sleep 150.
for _i in $(seq 1 60); do
    sleep 5
    if sshpass -p root ssh "${SSH_OPTS[@]}" root@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
        SSH_USER=root; SSH_PASS=root; break
    elif sshpass -p arch ssh "${SSH_OPTS[@]}" arch@127.0.0.1 "echo SSHOK" 2>/dev/null | grep -q SSHOK; then
        SSH_USER=arch; SSH_PASS=arch; break
    fi
done

if [ -z "$SSH_USER" ]; then
    echo "SSH FAILED after 300s polling"; kill $QEMU 2>/dev/null; exit 1
fi
echo "SSH_USER=$SSH_USER"

SSH_BASE=(sshpass -p "$SSH_PASS" ssh "${SSH_OPTS[@]}" "${SSH_USER}@127.0.0.1")
SCP_BASE=(sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P $SSH_PORT)

# Prepare /tmp/corpus on VM and ship .exe binaries + run_corpus.sh
echo "Preparing /tmp/corpus on VM..."
"${SSH_BASE[@]}" "mkdir -p /tmp/corpus/sources && rm -f /tmp/corpus/sources/*"

# Ship every .exe (sources directory layout matches what run_corpus.sh expects)
echo "Copying .exe binaries..."
for exe in "$CORPUS_SRC_DIR"/*.exe; do
    [ -f "$exe" ] || continue
    "${SCP_BASE[@]}" "$exe" "${SSH_USER}@127.0.0.1:/tmp/corpus/sources/" 2>/dev/null
done

# Ship run_corpus.sh as /tmp/run_corpus.sh, but tell it to run from /tmp/corpus
echo "Copying run_corpus.sh..."
"${SCP_BASE[@]}" "$RUN_CORPUS" "${SSH_USER}@127.0.0.1:/tmp/corpus/run_corpus.sh"

# Verify peloader presence on the live ISO
LOADER_PRESENT=$("${SSH_BASE[@]}" "ls -la /usr/bin/peloader 2>/dev/null || echo MISSING")
echo "peloader on VM: $LOADER_PRESENT"

# Run corpus (run_corpus.sh derives SCRIPT_DIR via dirname; it'll find /tmp/corpus/sources)
echo "Running corpus on VM..."
"${SSH_BASE[@]}" "cd /tmp/corpus && bash run_corpus.sh --no-build 2>&1" > /tmp/pe_corpus_stdout.log 2>&1
RC=$?
echo "Corpus exit: $RC"

# Pull JSON result
"${SCP_BASE[@]}" "${SSH_USER}@127.0.0.1:/tmp/pe_corpus_result.json" "$RESULT" 2>/dev/null

kill $QEMU 2>/dev/null
wait $QEMU 2>/dev/null

echo ""
echo "============================================================"
echo "  PE CORPUS ON LIVE ISO"
echo "============================================================"
cat /tmp/pe_corpus_stdout.log
echo ""
echo "  result json: $RESULT (size=$(wc -c < "$RESULT" 2>/dev/null || echo 0))"

exit $RC
