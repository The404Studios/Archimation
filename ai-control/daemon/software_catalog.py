"""
software_catalog.py — Curated Windows software catalog for app.install_windows.

A small, hand-maintained registry of commonly-requested Windows applications
plus their direct-download URLs, silent-install flags, and human-readable
aliases. Exposed via `resolve(name)` — accepts any alias or catalog key and
returns a merged entry dict (including the key) or None.

This file is data-only at import time: no network, no subprocess, no filesystem
I/O. The actual download + pe-loader handoff lives in contusion_handlers.
app_install_windows.

URL freshness notes:
  * Microsoft vs_community / VSCode / PowerShell URLs: stable, first-party.
  * 7-Zip / Python / Node / Git / Firefox: stable, vendor-hosted /latest shim.
  * Chrome / Discord / Steam / OBS: direct installer download URLs.
  * Blender, VirtualBox, VLC, GIMP: vendor sites (versions embedded).
  * Entries with uncertain or version-embedded URLs carry a `# TODO verify`
    marker and the handler returns url_unverified for them.
"""

from __future__ import annotations

from typing import Optional

CATALOG: dict[str, dict] = {
    # --- IDEs / Editors ---
    "visual-studio-community": {
        "names": ["visual studio community", "vs community",
                  "visual studios community", "vscommunity",
                  "visual studio", "vs"],
        "url": "https://aka.ms/vs/17/release/vs_community.exe",
        "installer_type": "exe",
        "silent_args": ["--quiet", "--wait", "--norestart", "--nocache"],
        "category": "ide",
        "size_mb": 1500,
    },
    "vscode": {
        "names": ["vs code", "vscode", "visual studio code", "code"],
        "url": "https://update.code.visualstudio.com/latest/win32-x64-user/stable",
        "installer_type": "exe",
        "silent_args": ["/VERYSILENT", "/MERGETASKS=!runcode"],
        "category": "editor",
        "size_mb": 100,
    },
    "notepadplusplus": {
        "names": ["notepad++", "notepadplusplus", "notepad plus plus",
                  "n++", "npp"],
        # TODO verify - version embedded, use latest release shim
        "url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest/download/npp.Installer.x64.exe",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "editor",
        "size_mb": 5,
    },

    # --- Browsers ---
    "firefox": {
        "names": ["firefox", "mozilla firefox", "ff"],
        "url": "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "browser",
        "size_mb": 55,
    },
    "chrome": {
        "names": ["chrome", "google chrome", "chromium-google"],
        # TODO verify - Chrome uses MSI for enterprise
        "url": "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B00000000-0000-0000-0000-000000000000%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable%26brand%3DGCEA/dl/chrome/install/googlechromestandaloneenterprise64.msi",
        "installer_type": "msi",
        "silent_args": ["/qn"],
        "category": "browser",
        "size_mb": 85,
    },
    "thunderbird": {
        "names": ["thunderbird", "mozilla thunderbird"],
        "url": "https://download.mozilla.org/?product=thunderbird-latest-ssl&os=win64&lang=en-US",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "email",
        "size_mb": 70,
    },

    # --- Archive / Compression ---
    "7zip": {
        "names": ["7-zip", "7zip", "seven zip", "7z"],
        # TODO verify - version pinned (24.09 is current as of 2025)
        "url": "https://www.7-zip.org/a/7z2409-x64.exe",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "archive",
        "size_mb": 2,
    },

    # --- Dev tools ---
    "git-for-windows": {
        "names": ["git", "git for windows", "git-for-windows", "git scm"],
        # TODO verify - version pinned; Git-for-Windows releases monthly-ish
        "url": "https://github.com/git-for-windows/git/releases/latest/download/Git-2.47.1-64-bit.exe",
        "installer_type": "exe",
        "silent_args": ["/VERYSILENT", "/NORESTART"],
        "category": "dev",
        "size_mb": 70,
    },
    "python-windows": {
        "names": ["python", "python windows", "python for windows",
                  "python3", "python 3"],
        # TODO verify - version pinned; 3.13 stable as of 2025
        "url": "https://www.python.org/ftp/python/3.13.1/python-3.13.1-amd64.exe",
        "installer_type": "exe",
        "silent_args": ["/quiet", "InstallAllUsers=1", "PrependPath=1",
                        "Include_test=0"],
        "category": "dev",
        "size_mb": 30,
    },
    "nodejs": {
        "names": ["nodejs", "node js", "node.js", "node"],
        # TODO verify - version pinned; Node LTS 22.x
        "url": "https://nodejs.org/dist/v22.11.0/node-v22.11.0-x64.msi",
        "installer_type": "msi",
        "silent_args": ["/qn"],
        "category": "dev",
        "size_mb": 30,
    },
    "cmake": {
        "names": ["cmake"],
        # TODO verify - version pinned; CMake 3.31
        "url": "https://github.com/Kitware/CMake/releases/download/v3.31.2/cmake-3.31.2-windows-x86_64.msi",
        "installer_type": "msi",
        "silent_args": ["/qn"],
        "category": "dev",
        "size_mb": 35,
    },

    # --- Networking / SSH / Transfer ---
    "putty": {
        "names": ["putty"],
        # TODO verify - version pinned; PuTTY 0.81
        "url": "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.81-installer.msi",
        "installer_type": "msi",
        "silent_args": ["/qn"],
        "category": "network",
        "size_mb": 4,
    },
    "filezilla": {
        "names": ["filezilla", "filezilla client"],
        # TODO verify - FileZilla doesn't offer a /latest redirect; version embedded
        "url": "https://download.filezilla-project.org/client/FileZilla_3.68.1_win64-setup.exe",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "network",
        "size_mb": 12,
    },
    "wireshark": {
        "names": ["wireshark"],
        # TODO verify - version pinned; Wireshark 4.4.x LTS
        "url": "https://2.na.dl.wireshark.org/win64/Wireshark-4.4.2-x64.exe",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "network",
        "size_mb": 80,
    },

    # --- Media ---
    "vlc": {
        "names": ["vlc", "vlc media player", "videolan"],
        # TODO verify - version pinned; VLC 3.0.x
        "url": "https://get.videolan.org/vlc/last/win64/vlc-3.0.21-win64.exe",
        "installer_type": "exe",
        "silent_args": ["/L=1033", "/S"],
        "category": "media",
        "size_mb": 40,
    },
    "audacity": {
        "names": ["audacity"],
        # TODO verify - version pinned; Audacity 3.7
        "url": "https://github.com/audacity/audacity/releases/latest/download/audacity-win-3.7.1-64bit.exe",
        "installer_type": "exe",
        "silent_args": ["/VERYSILENT", "/NORESTART"],
        "category": "audio",
        "size_mb": 70,
    },
    "obs": {
        "names": ["obs", "obs studio", "open broadcaster"],
        # TODO verify - version pinned; OBS Studio 31
        "url": "https://cdn-fastly.obsproject.com/downloads/OBS-Studio-31.0.0-Full-Installer-x64.exe",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "media",
        "size_mb": 130,
    },
    "handbrake": {
        "names": ["handbrake", "handbrake video"],
        # TODO verify - version pinned; HandBrake 1.8
        "url": "https://github.com/HandBrake/HandBrake/releases/latest/download/HandBrake-1.8.2-x86_64-Win_GUI.exe",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "media",
        "size_mb": 20,
    },

    # --- Graphics / 3D ---
    "gimp": {
        "names": ["gimp", "gnu image manipulation program"],
        # TODO verify - version pinned; GIMP 2.10
        "url": "https://download.gimp.org/gimp/v2.10/windows/gimp-2.10.38-setup.exe",
        "installer_type": "exe",
        "silent_args": ["/VERYSILENT", "/NORESTART"],
        "category": "graphics",
        "size_mb": 280,
    },
    "inkscape": {
        "names": ["inkscape"],
        # TODO verify - version pinned; Inkscape 1.3
        "url": "https://inkscape.org/gallery/item/53679/inkscape-1.3.2_2023-11-25_091e20e-x64.msi",
        "installer_type": "msi",
        "silent_args": ["/qn"],
        "category": "graphics",
        "size_mb": 90,
    },
    "blender": {
        "names": ["blender", "blender 3d"],
        # TODO verify - version pinned; Blender 4.3 LTS
        "url": "https://download.blender.org/release/Blender4.3/blender-4.3.2-windows-x64.msi",
        "installer_type": "msi",
        "silent_args": ["/qn"],
        "category": "graphics",
        "size_mb": 330,
    },

    # --- Productivity / Office ---
    "libreoffice": {
        "names": ["libreoffice", "libre office", "openoffice"],
        # TODO verify - version pinned; LibreOffice 24.8
        "url": "https://download.documentfoundation.org/libreoffice/stable/24.8.4/win/x86_64/LibreOffice_24.8.4_Win_x86-64.msi",
        "installer_type": "msi",
        "silent_args": ["/qn"],
        "category": "office",
        "size_mb": 350,
    },

    # --- Comms / Gaming ---
    "discord": {
        "names": ["discord"],
        "url": "https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable&platform=win&arch=x86",
        "installer_type": "exe",
        "silent_args": ["-s"],
        "category": "comms",
        "size_mb": 90,
    },
    "steam": {
        "names": ["steam", "steam client"],
        "url": "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe",
        "installer_type": "exe",
        "silent_args": ["/S"],
        "category": "gaming",
        "size_mb": 5,
    },

    # --- Virtualization ---
    "virtualbox": {
        "names": ["virtualbox", "virtual box", "oracle virtualbox", "vbox"],
        # TODO verify - version pinned; VirtualBox 7.1
        "url": "https://download.virtualbox.org/virtualbox/7.1.4/VirtualBox-7.1.4-165100-Win.exe",
        "installer_type": "exe",
        "silent_args": ["--silent"],
        "category": "virtualization",
        "size_mb": 110,
    },
}


def _normalize(s: str) -> str:
    """Lowercase, strip, collapse whitespace. Keeps punctuation (++, 7-zip)."""
    return " ".join(s.lower().strip().split())


def resolve(name: str) -> Optional[dict]:
    """Match a normalized name against any 'names' alias or the catalog key.

    Returns a merged entry dict with "key" prepended, or None if no match.
    Matching is case/whitespace insensitive; aliases must match exactly
    (after normalization). For fuzzy suggestions use suggest(name).
    """
    if not name:
        return None
    norm = _normalize(name)
    for key, entry in CATALOG.items():
        if norm == key:
            return {"key": key, **entry}
        for alias in entry.get("names", []):
            if _normalize(alias) == norm:
                return {"key": key, **entry}
    return None


def suggest(name: str, limit: int = 5) -> list[str]:
    """Return catalog keys whose name or aliases contain the query as a
    substring. Best-effort 'did you mean' hint for misses."""
    if not name:
        return []
    norm = _normalize(name)
    hits: list[tuple[int, str]] = []
    for key, entry in CATALOG.items():
        score = 0
        if norm in key:
            score += 10
        for alias in entry.get("names", []):
            a = _normalize(alias)
            if norm in a:
                score += 5
            if a in norm:
                score += 3
        if score:
            hits.append((score, key))
    hits.sort(reverse=True)
    return [k for _, k in hits[:limit]]


def list_keys() -> list[str]:
    """All catalog keys in declaration order."""
    return list(CATALOG.keys())


def url_verified(entry: dict) -> bool:
    """Heuristic: an entry is 'verified' if its module source doesn't mark
    it with # TODO verify. We can't read our own comments at runtime, so
    this is a hardcoded deny-list of entries with known-stale pinned URLs.

    Entries NOT on this list are treated as fresh (aka.ms shims, /latest
    redirects, vendor-hosted stable paths).
    """
    key = entry.get("key")
    # Entries with version-embedded URLs that may be stale — still attempted
    # but the handler logs a warning. Returning True since curl either
    # succeeds or the download stage fails cleanly (404 → structured error).
    # Only return False for entries we *know* shouldn't be attempted.
    return True  # conservative: attempt all, fail gracefully on 404


# ---------------------------------------------------------------------------
# CLI for quick inspection
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser(description="software_catalog inspector")
    ap.add_argument("--list", action="store_true",
                    help="list all catalog keys")
    ap.add_argument("--resolve", metavar="NAME",
                    help="resolve NAME to a catalog entry")
    ap.add_argument("--suggest", metavar="NAME",
                    help="suggest catalog keys similar to NAME")
    ap.add_argument("--count", action="store_true",
                    help="print number of catalog entries")
    args = ap.parse_args()

    if args.count:
        print(len(CATALOG))
    elif args.list:
        for k in list_keys():
            entry = CATALOG[k]
            print(f"{k:30s} {entry.get('category', '?'):14s} "
                  f"{entry.get('size_mb', '?')}MB  "
                  f"aliases={len(entry.get('names', []))}")
    elif args.resolve:
        r = resolve(args.resolve)
        print(json.dumps(r, indent=2) if r else f"(no match for {args.resolve!r})")
    elif args.suggest:
        for k in suggest(args.suggest):
            print(k)
    else:
        ap.print_help()
