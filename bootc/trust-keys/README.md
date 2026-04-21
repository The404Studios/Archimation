# ARCHIMATION trust-keys — project MOK key lifecycle

This directory is where the project's **Machine Owner Key (MOK)** for signing
`trust.ko` lives during a CI build or a local developer build. **No actual
keys are committed to git** — `.gitignore` in this directory rejects every
`*.pem`, `*.key`, `*.priv`, `*.der`. Treat a leaked private key as a distro-
wide security incident requiring SBAT revocation, cert rotation, and
coordinated bootc image rebuild.

Read order if you are onboarding:

1. `S72 research doc` — `docs/research/s72_beta_dkms_bootc.md`
2. This README
3. `packages/trust-dkms/trust-dkms.install` (archiso runtime path)
4. `bootc/build-trust-module.sh` (bootc image-build-time path)
5. Agent alpha's `Containerfile` (where keys are consumed during image build)

---

## 1. Why this directory exists

Today: `packages/trust-dkms/PKGBUILD` ships **22 kernel `.c` files + headers +
a DKMS stanza**. `trust-dkms.install` runs `dkms build` on **first boot** using
kernel headers already on disk. The built `trust.ko` is **unsigned**.

Consequences:

- `lockdown=integrity` (what `linux-hardened` enforces by default; what any
  Secure Boot + MOK-enrolled system enforces) refuses to `insmod` an unsigned
  module. `trust.ko` never loads. The whole stack collapses to software-only.
- There is no integrity anchor: an attacker who replaces the `.c` files on disk
  (or MITMs pacman) controls the Root of Authority. All proofs above it are
  built on a lie.
- bootc / OCI images are **immutable at runtime**. First-boot DKMS build
  violates the bootc contract — you can't run `dkms build` in a read-only
  rootfs with no kernel headers layered in.

Solution (S72 Phase 1): **sign `trust.ko` at image-build time, with the project
MOK key, pinned against the kernel version the image ships.** The signed `.ko`
becomes part of the immutable image at `/usr/lib/modules/<ver>/extra/trust.ko`.
The user enrolls the project public cert once (`mokutil --import`) and from
that point on, `trust.ko` loads across reboots without any dkms build.

Backward compat: `trust-dkms.install` retains the legacy archiso path. When
a DKMS rebuild happens on the target (kernel upgrade, etc.), the install hook
tries to sign the result with keys at `/var/lib/ai-control/trust-*.{der,pem}`
if present, OR a site-override at `/etc/ai-control/signing.conf`, OR it warns
and emits an unsigned module. Old-hardware users with `lockdown=none` still get
a working system. Secure-Boot users can re-sign manually post-build.

---

## 2. The three keys involved (do not confuse them)

| Key                              | Scope             | Private lives...                   | Public ships in image... | Used for...                              |
|----------------------------------|-------------------|------------------------------------|--------------------------|------------------------------------------|
| **Project MOK**                  | ARCHIMATION-wide  | CI secret (`TRUST_MOK_PRIV`)       | `/usr/share/archimation/trust-pub.der` | Signing `trust.ko` at image build; enrolled via mokutil on user machines |
| **Per-install MOK**              | single machine    | `/var/lib/dkms/mok.key` (600, root) | `/var/lib/dkms/mok.pub`  | Signing DKMS rebuilds on-target (archiso path only)                      |
| **sbctl / UEFI db signing key**  | single machine    | `/var/lib/sbctl/keys/db/db.key`    | `/var/lib/sbctl/keys/db/db.pem` | Signing the UKI / GRUB EFI binaries (Agent gamma scope)                 |

**This directory covers only the first row.** The second row lives at
install-time; the third row is Agent gamma's territory.

---

## 3. Project MOK generation (one time)

Run this **on the CI runner's secret-vault host**, not on a dev laptop unless
you are personally the project release manager. The private key must be
rotated annually (see Section 7).

```bash
# Working dir — never commit this output
cd /tmp/archimation-mok-gen
rm -rf ./*

# Config file that openssl will read
cat > mok.conf <<EOF
[ req ]
default_bits        = 4096
default_md          = sha256
distinguished_name  = req_dn
prompt              = no
x509_extensions     = v3_ca

[ req_dn ]
CN = ARCHIMATION Project trust.ko Signing
O  = ARCHIMATION
OU = Trust Root Authority
emailAddress = trust-root@archimation.invalid

[ v3_ca ]
basicConstraints        = critical,CA:FALSE
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer
keyUsage                = critical,digitalSignature
extendedKeyUsage        = critical,codeSigning
EOF

# 4096-bit RSA key + self-signed cert valid 13 months (annual rotation + slack)
openssl req -new -x509 -nodes \
    -newkey rsa:4096 \
    -sha256 \
    -days 395 \
    -outform PEM \
    -keyout trust-priv.pem \
    -out    trust-pub.pem \
    -config mok.conf

# Also emit DER form of the public cert — mokutil needs DER, sign-file
# wants PEM priv + DER pub, systemd-boot wants PEM db cert. We ship DER.
openssl x509 -in trust-pub.pem -outform DER -out trust-pub.der

# Sanity: verify signing roundtrip (requires sign-file from linux-headers)
cp /usr/lib/modules/$(uname -r)/build/scripts/sign-file .
dd if=/dev/zero of=dummy.ko bs=1 count=1
./sign-file sha256 trust-priv.pem trust-pub.der dummy.ko
tail -c 28 dummy.ko   # should print "Module signature appended"
rm dummy.ko sign-file mok.conf
```

After running:

- `trust-priv.pem` goes into CI secret store (GitHub Actions Secret name
  `TRUST_MOK_PRIV_PEM`, base64-encoded).
- `trust-pub.der` is copied into the bootc image at image-build time to
  `/usr/share/archimation/trust-pub.der` where `mokutil --import` can find it.
- `trust-pub.pem` is kept with the private key in CI for audit purposes;
  do NOT ship it in the image (DER is smaller and is what mokutil wants).
- Everything in `/tmp/archimation-mok-gen` except the CI-vault upload is
  `shred`ded. Never push any of it to git.

---

## 4. How CI uses the key

`Containerfile` (Agent α) does:

```dockerfile
# Build stage — kernel headers layer + trust sources
FROM archimation-build-base:latest AS trust-build
ARG KERNEL_VERSION
COPY trust/ /src/trust/
COPY bootc/build-trust-module.sh /usr/local/bin/
RUN --mount=type=secret,id=trust_mok_priv,target=/tmp/trust-priv.pem \
    --mount=type=secret,id=trust_mok_pub,target=/tmp/trust-pub.der \
    KERNEL_VERSION="$KERNEL_VERSION" \
    SIGNING_KEY_PEM=/tmp/trust-priv.pem \
    SIGNING_CERT_DER=/tmp/trust-pub.der \
    BOOTC_MODE=bootc \
    /usr/local/bin/build-trust-module.sh

# Runtime stage
FROM archimation-base:latest
COPY --from=trust-build /usr/lib/modules/${KERNEL_VERSION}/extra/trust.ko \
                        /usr/lib/modules/${KERNEL_VERSION}/extra/trust.ko
COPY bootc/trust-keys/trust-pub.der /usr/share/archimation/trust-pub.der
RUN depmod -a ${KERNEL_VERSION}
```

Note the `--mount=type=secret` — keys are bind-mounted into the build
stage only, never captured into a layer. `podman build --secret` or
`buildah bud --secret` supply them from the CI vault.

---

## 5. User-side enrollment (first boot, once per machine)

When a user boots the bootc image the first time:

```bash
# 1. Copy the project pub cert to a location shim can read
sudo cp /usr/share/archimation/trust-pub.der /boot/efi/archimation-trust.der

# 2. Queue the MOK import — shim's MokManager will prompt on reboot
sudo mokutil --import /boot/efi/archimation-trust.der
# ENTER a one-time password (8+ chars) — shim's blue screen will ask for it

# 3. Reboot
sudo systemctl reboot

# --- on reboot, shim interrupts with a blue MokManager screen ---
# Enroll MOK → Continue → Enter password → Reboot
#
# After this, `mokutil --list-enrolled` includes the ARCHIMATION cert.
# `trust.ko` now passes signature verification and loads under lockdown.
```

ARCHIMATION ships an optional first-boot wizard (`archimation-enroll-mok`)
that walks the user through this with plain-English explanations of what
the blue MokManager screen means. Users can also decline enrollment —
in that case the system boots with `lockdown=none` (see Section 8) and
`trust.ko` loads unsigned; the chain-of-custody guarantee is gone but
the system still works.

---

## 6. Verifying a signed trust.ko

Anywhere (on a running system, on a build host, inside CI):

```bash
# Is it signed at all?
tail -c 28 /usr/lib/modules/$(uname -r)/extra/trust.ko
# → "Module signature appended~"

# Is the signer the project MOK?
modinfo /usr/lib/modules/$(uname -r)/extra/trust.ko | grep -E 'sig|signer'

# Is the certificate itself the one we expect?
openssl x509 -inform DER -in /usr/share/archimation/trust-pub.der \
    -noout -subject -fingerprint -sha256
# Subject: CN = ARCHIMATION Project trust.ko Signing, ...
# SHA256 Fingerprint: <expected value from the current active key>

# Has the kernel loaded it?
dmesg | grep -iE 'trust|signature'
# → "trust: module verification succeeded"   (good)
# → "trust: module verification failed: signature and/or required key missing - tainting kernel"
#   (bad — cert not enrolled)

# What keyring does it chain to?
keyctl list %:.platform
keyctl list %:.machine    # MOK-enrolled keys land here on 5.13+
```

---

## 7. Rotation policy

**Manual rotation every 12 months** (the cert is valid 395 days to give 30
days of grace for CI scheduling drift).

Rotation procedure:

1. Announce in `CHANGELOG.md` and on the release channel **30 days ahead**:
   "MOK rotating on YYYY-MM-DD. The new `trust-pub.der` ships in the
   YYYY.MM.DD image; users must re-enroll via mokutil during the first
   boot of the new image. Systems still on the previous image remain
   working — old signatures remain valid until their cert expires."
2. Generate new keypair via Section 3. Upload new private key to CI secret
   `TRUST_MOK_PRIV_PEM_V<n+1>`. Keep old secret named
   `TRUST_MOK_PRIV_PEM_V<n>` for at least one image release cycle so
   rollback images can still be rebuilt.
3. Update `Containerfile` to reference the new secret name.
4. Next build signs with new key; ships new pub cert alongside the old one
   at `/usr/share/archimation/trust-pub-v<n>.der` and
   `/usr/share/archimation/trust-pub-v<n+1>.der`.
5. `archimation-enroll-mok` wizard imports both on first boot; user sees
   two MokManager enroll prompts (one per key). This means rollback to
   an older image still works without wiping MOK state.
6. After **two full release cycles** with the new key as default, the old
   pub cert is removed from the image and the old CI secret is deleted.
   Users who went three cycles without updating now need to re-enroll
   during their next image update.

**Emergency rotation** (key compromise suspected): run rotation procedure
above in a single day; submit SBAT bump to revoke signatures chained to
the compromised key; push an `archimation-trust-revoke` hotfix package
that `dbxupdate` the hashes of any known-signed `trust.ko` binaries built
against the compromised key. Target-users MUST update within 7 days or
their disks will be refused at next kernel-lockdown boot.

---

## 8. Graceful degradation — no key, no Secure Boot, no TPM

There are three distinct "no enrollment" paths, and each of them must
work. The project's promise is that `trust.ko` always loads **when the
user explicitly accepts the reduced security posture**.

### 8a. Secure Boot OFF, `lockdown=none`

Kernel cmdline contains `lockdown=none` (or just no `lockdown=` at all
on a kernel that doesn't default to integrity). Unsigned modules load
freely. `trust.ko` loads regardless of whether it is signed.

Use case: pre-2013 hardware with no UEFI; systems with SB disabled in
firmware for any reason; dev boxes; VMs without UEFI.

UX: ARCHIMATION prints on first boot
> `NOTICE: trust.ko loaded without signature verification (lockdown=none). Authority root is software-only; enable Secure Boot + enroll MOK for hardware-strength.`

### 8b. Secure Boot ON, MOK not enrolled, `lockdown=integrity`

This is the failure mode we most want to prevent. Kernel refuses to load
`trust.ko`. AI control daemon sees the missing `/dev/trust` device and
emits a loud SCM error; cortex disables trust-mediated paths; system
boots to a functional but degraded state.

UX: ARCHIMATION firstboot wizard detects `mokutil --sb-state` ==
`SecureBoot enabled` and `trust.ko` not loaded; pops a 3-option dialog:
  (a) Enroll MOK now (recommended)
  (b) Disable Secure Boot in firmware (press F2 on reboot, explain steps)
  (c) Proceed without trust.ko (trust-mediated features off)

### 8c. Secure Boot ON, MOK enrolled

Happy path. `trust.ko` loads signed. `mokutil --list-enrolled` shows
our cert. `dmesg` has `trust: module verification succeeded`.

---

## 9. What's in this directory, for real

```
bootc/trust-keys/
├── README.md          ← this file
├── .gitignore         ← rejects *.pem, *.key, *.priv, *.der (except *.example.der)
└── (at CI runtime only)
    ├── trust-priv.pem    ← mounted from CI secret, deleted after build
    ├── trust-pub.der     ← mounted from CI secret, copied into image
    └── trust-pub.pem     ← mounted from CI secret, kept for audit
```

There is no `bootc/trust-keys/trust-priv.pem` in this repo. There will
never be. If you ever see one: `git rm` it immediately, force-push, and
rotate per Section 7 emergency procedure.

---

## 10. References

- kernel `Documentation/admin-guide/module-signing.rst`
  (<https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html>)
- shim MOK concepts: <https://github.com/rhboot/shim/blob/main/README.md>
- `mokutil(1)` manpage
- `sign-file(1)` — shipped as `scripts/sign-file` in the kernel headers package
- Arch Wiki, Secure Boot: <https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot>
- S71-K research doc (this repo: `docs/research/s71_k_measured_boot.md`)
- S72-β research doc (this repo: `docs/research/s72_beta_dkms_bootc.md`)
