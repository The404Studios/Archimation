# Release process: pe-compat repository

How custom packages (`pe-loader`, `trust-dkms`, `ai-control-daemon`,
`windows-services`, `ai-desktop-config`, `ai-firewall`, `pe-compat-dkms`,
`trust-system`, `ai-first-boot-wizard`) travel from a working tree to a
user's installed system, and how to cut a new release.

## Why two mirrors?

Installed systems and live ISOs have different constraints, so the
custom repo declaration in `/etc/pacman.conf` lists two `Server` lines
that pacman tries in order:

```
[pe-compat]
SigLevel = Optional TrustAll
Server = https://example.invalid/pe-compat-repo/releases/download/latest/$arch
Server = file:///var/lib/pe-compat/repo
```

| Scenario | Which Server wins | Why |
|---|---|---|
| Live ISO, no network | HTTP 404 → `file://` | Packages baked into squashfs at `/var/lib/pe-compat/repo` by `customize_airootfs.sh:1547` |
| Live ISO, online | HTTP 200 → HTTP | Pulls the latest published release — useful for testing a new build on old media |
| Installed system, online | HTTP 200 → HTTP | **This is how `pacman -Syu` delivers bug fixes.** Without the HTTP line the installed system can only ever see packages that were current at install time |
| Installed system, offline | HTTP 404 → `file://` | Falls back to the squashfs copy rsync'd to disk by the installer. Stale but safe — won't brick the box |

Session 68's install audit identified the missing HTTP line as the
single biggest adoption blocker: once users installed to disk, the only
`Server` entry was `file:///var/lib/pe-compat/repo`, which still
resolved after install but never received updates — so `pacman -Syu`
silently did nothing for custom packages.

## Cutting a new release

Assuming you've landed code changes and want to ship them:

1. **Bump `pkgrel` in the affected PKGBUILD(s).** Example:
   `packages/pe-loader/PKGBUILD` `pkgrel=7` → `pkgrel=8`. For `pkgver`
   bumps, also update downstream `depends=` lines that pin versions.

2. **Rebuild.** From WSL Arch:
   ```bash
   bash scripts/build-packages.sh
   ```
   This populates `repo/x86_64/` with fresh `*.pkg.tar.zst` and rebuilds
   `pe-compat.db*` + `pe-compat.files*`.

3. **Stage for release:**
   ```bash
   bash scripts/release-to-repo.sh /tmp/pe-compat-release
   ```
   This rsyncs the repo into the target dir and emits a `manifest.json`
   with sha256sums. No network calls — purely local staging.

4. **Tag + upload.** The release script prints the final command; it
   looks like:
   ```bash
   git tag -a v2026.04.20-pkg-N -m "Session NN bake"
   git push --tags
   gh release upload v2026.04.20-pkg-N \
       /tmp/pe-compat-release/*.pkg.tar.zst \
       /tmp/pe-compat-release/pe-compat.* \
       /tmp/pe-compat-release/manifest.json
   ```
   Using a rolling `latest` tag (which the pacman.conf URL references)
   means users never have to change their `Server =` line across
   releases. The cost is lost history — operators who want pinning
   should follow "Version pinning" below.

5. **Smoke-test.** Boot an installed VM, `sudo pacman -Syu`, verify the
   new `pe-loader` / `trust-dkms` / etc. pkgrel is pulled.

## Substituting the real release URL

The Server line ships with `https://example.invalid/...` — this is
intentional. Operators MUST replace it with their actual release host
before the first real release. Edit
`profile/airootfs/etc/pacman.conf:30` to your real URL. Example for
GitHub Releases:

```
Server = https://github.com/your-org/pe-compat-repo/releases/download/latest/$arch
```

Then rebuild the ISO so the change lands in the squashfs for new
installs. Existing installs need their `/etc/pacman.conf` patched by
hand (or via an `ai-control` handler if you want to automate the
rotation — future work).

Better to ship `example.invalid` than a plausible-looking wrong URL:
DNS failure is a clear error, whereas a typo'd-but-reachable domain
could silently mislead users.

## Failure modes

- **Repo URL 404 / DNS down, installed system, offline:** pacman
  cleanly falls through to `file:///var/lib/pe-compat/repo`. User runs
  an older pkgrel until the mirror recovers. No brick.
- **Repo URL reachable but serves stale `latest` tag:** users on newer
  disk images see no upgrade candidates. Works as intended — they
  already have the newest build.
- **`pe-compat.db` missing from release:** pacman logs `failed to
  update pe-compat (no server)` and skips the repo. Other updates still
  apply. Fix: re-run `release-to-repo.sh` (it always copies the db).
- **`SigLevel = Optional TrustAll` rejects a signed package:** `Optional`
  means "unsigned is fine" — it should never reject. If it does, the
  package is corrupt; rebuild from source.

## Future work

- **GPG signing.** Current `SigLevel = Optional TrustAll` accepts
  anything. Production rollout: run `makepkg --sign` in
  `build-packages.sh`, `repo-add --sign`, ship the public key to
  `/etc/pacman.d/pe-compat-keyring`, and flip the runtime pacman.conf
  to `SigLevel = Required`. Do this once the release URL is real — no
  point signing packages that point at `example.invalid`.
- **Mirror rotation.** Add a third `Server =` line for a mirror in a
  different region / hoster. Pacman tries entries in order, so list by
  speed preference.
- **Version pinning.** Users who need a specific pkgrel can add
  `IgnorePkg = pe-loader trust-dkms` to their pacman.conf, or use
  `pacman -U` against a specific `.pkg.tar.zst` URL from the GitHub
  release archive (which keeps every tag, unlike `latest`).
- **Automated release via GitHub Actions.** `release-to-repo.sh` was
  designed to run both locally and in CI. An action that triggers on
  tag push, runs `build-packages.sh`, then `release-to-repo.sh`, then
  `gh release create` would close the loop — no more manual `gh release
  upload` step.
- **Binfmt for repo freshness checks.** AI cortex could emit a
  low-priority event when `pacman -Sy` shows a new pkgrel available,
  prompting the user to `ai-control update`. Future integration with
  the ai-health system.
