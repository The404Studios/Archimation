"""
dictionary_v2.py — Template-driven NL → handler_type lookup table (Session 58).

Compiles ~80 intent templates into ~10K phrase mappings, ships as zstd-compressed
pickle, provides O(1) runtime lookup. Stdlib-only (Python 3.14 compression.zstd
preferred; gzip fallback for older runtimes).

Build (called at package time):
    python3 -m dictionary_v2 --build /usr/share/ai-control/dictionary_v2.pkl.zst

Runtime (called from contusion.py — Agent A2 owns the wiring):
    from dictionary_v2 import lookup
    result = lookup("turn down the volume")
    # {"handler_type": "audio.volume_down", "args": {}, "confidence": 0.85,
    #  "source": "v2_template"}
    # or None (no match >= threshold)

API contract is LOCKED. Do not change return shape.
"""
from __future__ import annotations

import json
import os
import pickle
import re
import stat
import sys
import threading
import time
from collections import defaultdict
from itertools import product
from typing import Any, Iterable, Optional

# ---------------------------------------------------------------------------
# Compression backends — try stdlib compression.zstd (3.14+), then external
# zstandard, then fall back to gzip. Magic bytes are sniffed at decode time.
# ---------------------------------------------------------------------------

_GZIP_MAGIC = b"\x1f\x8b"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _zstd_compress(raw: bytes) -> Optional[bytes]:
    try:
        import compression.zstd as _zstd  # type: ignore
        return _zstd.compress(raw, level=19)
    except Exception:
        pass
    try:
        import zstandard as _zstandard  # type: ignore
        return _zstandard.ZstdCompressor(level=19).compress(raw)
    except Exception:
        return None


def _zstd_decompress(blob: bytes) -> Optional[bytes]:
    try:
        import compression.zstd as _zstd  # type: ignore
        return _zstd.decompress(blob)
    except Exception:
        pass
    try:
        import zstandard as _zstandard  # type: ignore
        return _zstandard.ZstdDecompressor().decompress(blob)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Slot vocabulary — small, controlled, designed so cartesian expansion stays
# bounded (target ~5–20K total phrases).
# ---------------------------------------------------------------------------

_SLOTS: dict[str, list[str]] = {
    # politeness / hedge prefixes (often empty). Session 68 (Agent V) enriched
    # HEDGE/POLITE/VERB_*/OBJ_* to multiply across the ~116 HEDGE-using
    # templates without touching TEMPLATES. Keep entries as PURE STRINGS with
    # NO nested slot references ({...}) — the expander won't re-resolve them.
    "HEDGE":     [
        "", "can you ", "could you ", "please ", "hey ", "would you ",
        "i'd like you to ", "i want you to ", "mind if you ", "if you could ",
        "go ahead and ",
    ],
    "POLITE":    [
        "", " please", " now", " thanks",
        " for me", " right now", " real quick", " when you get a chance",
        " if possible", " if you can",
    ],
    "ART":       ["", "the ", "my ", "a "],

    # verbs — increase/decrease/toggle/on/off
    "VERB_UP":     [
        "turn up", "raise", "boost", "crank", "increase", "bump up",
        "bump", "crank up", "push up",
    ],
    "VERB_DOWN":   [
        "turn down", "lower", "reduce", "decrease", "drop", "bump down",
        "bring down", "push down",
    ],
    "VERB_TOGGLE": ["toggle", "flip", "switch", "swap"],
    "VERB_OFF":    ["turn off", "shut off", "kill", "switch off", "disable"],
    "VERB_ON":     ["turn on", "enable", "switch on", "activate"],
    "VERB_SHOW":   [
        "show", "list", "display", "give me", "what are",
        "show me", "let me see", "pull up", "render", "give me the",
        "read out", "tell me",
    ],
    "VERB_GET":    [
        "what is", "what's", "tell me", "show me", "get",
        "give me", "fetch", "return", "look up", "check", "find out",
    ],
    "VERB_OPEN":   [
        "open", "launch", "start", "run",
        "fire up", "boot up", "pop open", "bring up", "start up", "load up",
        "spin up", "kick off",
    ],
    "VERB_CLOSE":  ["close", "kill", "quit", "exit"],

    # objects — devices / nouns
    "OBJ_VOLUME":  ["volume", "the volume", "sound", "the sound", "audio", "the audio"],
    "OBJ_BRIGHT":  ["brightness", "the brightness", "my brightness", "screen brightness", "display brightness"],
    "OBJ_DISPLAY": ["display", "the display", "screen", "the screen", "monitor"],
    "OBJ_MIC":     ["mic", "the mic", "microphone", "my microphone", "the microphone"],
    "OBJ_MUSIC":   [
        "music", "the music", "song", "the song", "track", "the track", "media",
        "my music", "this song", "the audio", "the tune",
    ],
    "OBJ_SCREEN":  [
        "screen", "the screen", "display",
        "my screen", "this screen", "the monitor", "my monitor", "the display", "my display",
    ],
    "OBJ_WINDOW":  ["window", "this window", "the window", "current window"],
    "OBJ_WORKSPACE": ["workspace", "desktop", "virtual desktop"],
    "OBJ_NIGHT":   ["night light", "night mode", "blue light filter", "redshift"],
    "OBJ_BATT":    [
        "battery", "the battery", "battery level", "battery status",
        "my battery",
    ],
    "OBJ_WIFI":    [
        "wifi", "wi-fi", "wireless", "wifi signal",
        "the wifi", "my wifi", "the wireless",
    ],
    "OBJ_BT":      [
        "bluetooth", "bluetooth devices", "bt", "paired devices",
    ],
    "OBJ_GPU":     [
        "gpu", "the gpu", "graphics card", "video card",
        "my gpu", "the graphics card",
    ],
    "OBJ_CPU":     [
        "cpu", "the cpu", "processor",
        "my cpu", "the processor",
    ],
    "OBJ_FAN":     ["fan", "the fan", "fans", "cooling"],

    # script names — sample subset shipped with the ISO; user can drop more
    # into /etc/ai-control/scripts.d/ or ~/.ai/scripts.d/ at runtime (those
    # are picked up by contusion_dictionary._parse_single, NOT by the v2
    # template expansion which is built once at package time).
    "OBJ_SCRIPT_NAME": ["hello", "system-info", "disk-cleanup", "pacman-refresh"],

    # generic words
    "AGAIN":  ["again", "once more", "another time"],
    "NOW":    ["", " right now", " immediately"],

    # --append to end of SLOTS --
    # Session 68 Agent Y — file/directory automation slots.  These are small
    # controlled vocabularies used ONLY by file.* templates (see TEMPLATES
    # block immediately after system.night_light).  Keep entries SHORT and
    # PURE (no nested {SLOT} refs) so cartesian expansion stays bounded.
    "OBJ_DIR":   [
        "downloads", "my downloads", "~/Downloads",
        "documents", "my documents", "~/Documents",
        "pictures", "my pictures", "~/Pictures",
        "desktop", "my desktop", "~/Desktop",
        "home", "my home", "~",
    ],
    "DST_DIR":   [
        "/tmp", "my downloads", "my documents",
        "~/backup", "~/Desktop", "/mnt/backup",
    ],
    "TOP_N":     ["5", "10", "20", "50", "100"],
    "FILE_GLOB": [
        "png", "*.png", "jpg", "jpeg", "pdf",
        "mp3", "mp4", "txt", "log",
    ],

    # Session 68 Agent W — PE loader target noun.  Refers to the "current"
    # binary / installer being discussed; the actual path is resolved at
    # dispatch time (pe.run / pe.analyze / pe.install_msi).  Pure strings,
    # no nested slot refs.
    "PE_TARGET": [
        "this exe", "the exe", "this file",
        "this pe", "this installer", "this msi",
    ],

    # Session 68 Agent S — Windows software catalog aliases. Kept in lock-step
    # with software_catalog.CATALOG entries so `install {APP_WIN_NAME}` covers
    # every supported catalog key + its common aliases.  Pure strings, no
    # nested slot refs; reverse-mapped at dispatch time by contusion_handlers.
    # _derive_app_name against software_catalog.CATALOG.
    "APP_WIN_NAME": [
        "visual studio community", "vs community", "visual studios community",
        "vscode", "vs code", "firefox", "chrome", "7-zip", "7zip",
        "notepad++", "git", "python", "nodejs", "node js", "putty",
        "filezilla", "vlc", "discord", "steam", "obs", "audacity", "gimp",
        "inkscape", "libreoffice", "wireshark", "blender", "virtualbox",
        "thunderbird", "handbrake", "cmake",
    ],
}


# ---------------------------------------------------------------------------
# Templates — handler_type → phrase patterns.  Only no-arg handlers (the engine
# in contusion_dictionary.py covers arg-bearing ones).  Avoid destructive ops
# like power.shutdown / reboot / install_*.
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, list[str]] = {

    # ------------------------------------------------------------------ audio
    "audio.volume_up": [
        "{HEDGE}{VERB_UP} {OBJ_VOLUME}{POLITE}",
        "{OBJ_VOLUME} up{POLITE}",
        "louder{POLITE}",
        "make it louder",
        "make {OBJ_VOLUME} louder",
        "vol up",
        "{HEDGE}make {OBJ_VOLUME} louder",
        "i can barely hear it",
        "speak up",
    ],
    "audio.volume_down": [
        "{HEDGE}{VERB_DOWN} {OBJ_VOLUME}{POLITE}",
        "{OBJ_VOLUME} down{POLITE}",
        "quieter{POLITE}",
        "make it quieter",
        "make {OBJ_VOLUME} quieter",
        "softer",
        "vol down",
        "{HEDGE}make {OBJ_VOLUME} softer",
        "too loud",
        "it's too loud",
    ],
    "audio.mute_toggle": [
        "{HEDGE}{VERB_TOGGLE} mute",
        "{HEDGE}mute{POLITE}",
        "{HEDGE}unmute{POLITE}",
        "{HEDGE}mute {OBJ_VOLUME}",
        "{HEDGE}unmute {OBJ_VOLUME}",
        "silence{POLITE}",
        "shush",
        "be quiet",
        "no sound",
    ],
    "audio.mic_mute_toggle": [
        "{HEDGE}{VERB_TOGGLE} {OBJ_MIC}",
        "{HEDGE}mute {OBJ_MIC}",
        "{HEDGE}unmute {OBJ_MIC}",
        "{OBJ_MIC} off",
        "{OBJ_MIC} on",
        "mic mute",
        "mute mic",
        "push to talk off",
    ],
    "audio.sink_list": [
        "{VERB_SHOW} audio outputs",
        "{VERB_SHOW} sound outputs",
        "{VERB_SHOW} sinks",
        "{VERB_SHOW} audio devices",
        "{VERB_SHOW} speakers",
        "what audio devices",
        "list audio sinks",
    ],

    # ------------------------------------------- windows software installer
    # Session 68 Agent S — app.install_windows routes via software_catalog.
    # Templates expand {APP_WIN_NAME} against a curated alias list (~30 apps)
    # producing ~540 phrase variants.  No-arg dispatch: contusion_handlers.
    # _derive_app_name re-parses the software name from the original phrase
    # on its way through the handler (args["name"] takes precedence when
    # supplied by contusion_dictionary slot routing).
    "app.install_windows": [
        "install {APP_WIN_NAME}",
        "install {APP_WIN_NAME} for windows",
        "download {APP_WIN_NAME}",
        "download {APP_WIN_NAME} and install",
        "get {APP_WIN_NAME}",
        "get me {APP_WIN_NAME}",
        "grab {APP_WIN_NAME}",
        "add {APP_WIN_NAME}",
        "set up {APP_WIN_NAME}",
        "setup {APP_WIN_NAME}",
        "install {APP_WIN_NAME} please",
        "please install {APP_WIN_NAME}",
        "i need {APP_WIN_NAME}",
        "can you install {APP_WIN_NAME}",
        "install {APP_WIN_NAME} and run it",
        "install {APP_WIN_NAME} through pe loader",
        "install {APP_WIN_NAME} msi",
        "install {APP_WIN_NAME} exe",
    ],

    # ------------------------------------------------------------- brightness
    "brightness.up": [
        "{HEDGE}{VERB_UP} {OBJ_BRIGHT}{POLITE}",
        "{OBJ_BRIGHT} up{POLITE}",
        "turn {OBJ_BRIGHT} up{POLITE}",
        "turn brightness up",
        "brighter{POLITE}",
        "make it brighter",
        "make {OBJ_SCREEN} brighter",
        "{HEDGE}brighten {OBJ_SCREEN}",
        "increase brightness",
    ],
    "brightness.down": [
        "{HEDGE}{VERB_DOWN} {OBJ_BRIGHT}{POLITE}",
        "{OBJ_BRIGHT} down{POLITE}",
        "turn {OBJ_BRIGHT} down{POLITE}",
        "turn brightness down",
        "darker{POLITE}",
        "dimmer{POLITE}",
        "make it darker",
        "make {OBJ_SCREEN} dimmer",
        "{HEDGE}dim {OBJ_SCREEN}",
        "decrease brightness",
        "too bright",
    ],
    "brightness.get": [
        "{VERB_GET} {OBJ_BRIGHT}",
        "{OBJ_BRIGHT} level",
        "current {OBJ_BRIGHT}",
        "how bright is the screen",
        "what is the screen brightness",
    ],
    "brightness.max": [
        "{HEDGE}max {OBJ_BRIGHT}{POLITE}",
        "{HEDGE}maximum {OBJ_BRIGHT}",
        "{HEDGE}full {OBJ_BRIGHT}",
        "{OBJ_BRIGHT} to max",
        "{OBJ_BRIGHT} to 100",
        "make {OBJ_SCREEN} as bright as possible",
    ],
    "brightness.min": [
        "{HEDGE}min {OBJ_BRIGHT}",
        "{HEDGE}minimum {OBJ_BRIGHT}",
        "{OBJ_BRIGHT} to min",
        "{OBJ_BRIGHT} to lowest",
        "make {OBJ_SCREEN} as dim as possible",
    ],
    "brightness.auto": [
        "{HEDGE}auto {OBJ_BRIGHT}",
        "{HEDGE}automatic {OBJ_BRIGHT}",
        "{HEDGE}adaptive {OBJ_BRIGHT}",
        "let {OBJ_SCREEN} auto adjust",
    ],

    # ------------------------------------------------------------------ media
    "media.play": [
        "{HEDGE}play {OBJ_MUSIC}",
        "{HEDGE}play{POLITE}",
        "{HEDGE}resume {OBJ_MUSIC}",
        "{HEDGE}resume playback",
        "start the {OBJ_MUSIC}",
        "start playback",
    ],
    "media.pause": [
        "{HEDGE}pause {OBJ_MUSIC}",
        "{HEDGE}pause{POLITE}",
        "{HEDGE}pause playback",
        "stop the {OBJ_MUSIC} for a sec",
        "hold the {OBJ_MUSIC}",
    ],
    "media.play_pause": [
        "{HEDGE}{VERB_TOGGLE} playback",
        "{HEDGE}play pause",
        "play or pause",
        "play/pause",
    ],
    "media.next": [
        "{HEDGE}next {OBJ_MUSIC}",
        "{HEDGE}next track",
        "skip {OBJ_MUSIC}",
        "skip this {OBJ_MUSIC}",
        "skip ahead",
        "skip{POLITE}",
        "next song please",
        "i don't like this song",
    ],
    "media.prev": [
        "{HEDGE}previous {OBJ_MUSIC}",
        "{HEDGE}prev {OBJ_MUSIC}",
        "{HEDGE}prev track",
        "previous track",
        "{HEDGE}go back to the last {OBJ_MUSIC}",
        "play that {OBJ_MUSIC} {AGAIN}",
        "back to the last song",
    ],
    "media.stop": [
        "{HEDGE}stop {OBJ_MUSIC}",
        "{HEDGE}stop playback",
        "{HEDGE}stop the {OBJ_MUSIC}",
        "kill the {OBJ_MUSIC}",
    ],
    "media.status": [
        "what is playing",
        "what's playing",
        "what song is this",
        "what {OBJ_MUSIC} is this",
        "current {OBJ_MUSIC}",
        "now playing",
        "media status",
    ],
    "media.list_players": [
        "{VERB_SHOW} media players",
        "{VERB_SHOW} players",
        "list media players",
        "what media players are running",
    ],

    # ------------------------------------------------------------------ power
    "power.lock_screen": [
        "{HEDGE}lock {OBJ_SCREEN}{POLITE}",
        "{HEDGE}lock the computer",
        "{HEDGE}lock it",
        "lock my session",
        "lockscreen",
        "lock screen",
        "i'm stepping away",
    ],
    "power.unlock_screen": [
        "{HEDGE}unlock {OBJ_SCREEN}",
        "{HEDGE}unlock the computer",
        "{HEDGE}unlock it",
        "wake up",
    ],
    "power.screen_off": [
        "{HEDGE}{VERB_OFF} {OBJ_SCREEN}",
        "{HEDGE}{VERB_OFF} {OBJ_DISPLAY}",
        "{HEDGE}{VERB_OFF} the monitor",
        "blank {OBJ_SCREEN}",
        "{OBJ_SCREEN} sleep",
    ],
    "power.screen_on": [
        "{HEDGE}{VERB_ON} {OBJ_SCREEN}",
        "{HEDGE}{VERB_ON} {OBJ_DISPLAY}",
        "{HEDGE}{VERB_ON} the monitor",
        "wake the {OBJ_SCREEN}",
    ],

    # ----------------------------------------------------------------- system
    "system.notify": [
        "{HEDGE}send a notification",
        "{HEDGE}notify me",
        "{HEDGE}post a notification",
        "show a notification",
        "notify hello world",
        "notify {MSG}",
    ],
    "system.screenshot_full": [
        "{HEDGE}screenshot{POLITE}",
        "{HEDGE}take a screenshot",
        "{HEDGE}capture {OBJ_SCREEN}",
        "{HEDGE}capture the {OBJ_DISPLAY}",
        "{HEDGE}grab {OBJ_SCREEN}",
        "screen capture",
        "full screenshot",
        "screenshot full",
    ],
    "system.screenshot_window": [
        "{HEDGE}screenshot {OBJ_WINDOW}",
        "{HEDGE}capture {OBJ_WINDOW}",
        "{HEDGE}take a screenshot of this {OBJ_WINDOW}",
        "{HEDGE}grab this {OBJ_WINDOW}",
        "screenshot active window",
    ],
    "system.screenshot_region": [
        "{HEDGE}screenshot a region",
        "{HEDGE}capture a region",
        "{HEDGE}select a region to screenshot",
        "{HEDGE}snip {OBJ_SCREEN}",
        "snipping tool",
        "region screenshot",
    ],
    "system.night_light": [
        "{HEDGE}{VERB_TOGGLE} {OBJ_NIGHT}",
        "{HEDGE}{VERB_ON} {OBJ_NIGHT}",
        "{HEDGE}{VERB_OFF} {OBJ_NIGHT}",
        "warmer {OBJ_SCREEN}",
        "{HEDGE}reduce blue light",
        "night light on",
        "night light off",
    ],

    # ------------------------------------------------------------- file / dir
    # Session 68 (Agent Y) — file automation templates.  Paired with handlers
    # file.delete_empty_dirs / file.find_largest / file.zip_folder /
    # file.move_by_pattern / file.backup_to / file.open_path / file.list_recent
    # in contusion_handlers.py.  Destructive actions (delete/move) default to
    # dry_run=True in the handler; phrasing stays blunt.
    "file.delete_empty_dirs": [
        "delete empty folders in {OBJ_DIR}",
        "delete empty directories in {OBJ_DIR}",
        "remove empty folders from {OBJ_DIR}",
        "clean up empty folders in {OBJ_DIR}",
        "purge empty dirs in {OBJ_DIR}",
        "delete empty folders",
        "remove empty directories",
    ],
    "file.find_largest": [
        "find the 10 largest files in {OBJ_DIR}",
        "find the biggest files in {OBJ_DIR}",
        "what are my biggest files",
        "what is taking up space",
        "largest files in {OBJ_DIR}",
        "biggest files",
        "show me the largest files",
        "find huge files",
        "find the {TOP_N} largest files in {OBJ_DIR}",
    ],
    "file.zip_folder": [
        "zip {OBJ_DIR}",
        "zip my {OBJ_DIR}",
        "archive {OBJ_DIR}",
        "compress {OBJ_DIR}",
        "make a zip of {OBJ_DIR}",
        "create archive from {OBJ_DIR}",
    ],
    "file.move_by_pattern": [
        "move all {FILE_GLOB} from {OBJ_DIR} to {DST_DIR}",
        "move {FILE_GLOB} files to {DST_DIR}",
        "move all png files out of downloads",
    ],
    "file.backup_to": [
        "backup {OBJ_DIR} to {DST_DIR}",
        "backup my {OBJ_DIR}",
        "copy {OBJ_DIR} to {DST_DIR}",
        "sync {OBJ_DIR} with {DST_DIR}",
        "mirror {OBJ_DIR} to {DST_DIR}",
    ],
    "file.open_path": [
        "open {OBJ_DIR}",
        "open folder {OBJ_DIR}",
        "open the file {PE_TARGET}",
        "show me {OBJ_DIR}",
        "launch {OBJ_DIR}",
        "pop open {OBJ_DIR}",
    ],
    "file.list_recent": [
        "show recent files in {OBJ_DIR}",
        "recent files in {OBJ_DIR}",
        "list recent files",
        "recent changes",
        "what has changed recently",
        "what files did i modify recently",
    ],

    "system.clipboard_monitor": [
        "{VERB_SHOW} clipboard monitor",
        "open clipboard monitor",
        "clipboard monitor",
    ],

    # ------------------------------------------------------------- monitoring
    "monitoring.battery_percent": [
        "{VERB_GET} {OBJ_BATT}",
        "{VERB_GET} {OBJ_BATT} level",
        "{VERB_GET} {OBJ_BATT} percent",
        "{OBJ_BATT} percentage",
        "how much {OBJ_BATT} do i have",
        "how much {OBJ_BATT} is left",
        "{OBJ_BATT} left",
        "battery status",
        "battery percent",
        "battery level",
    ],
    "monitoring.battery_time": [
        "how long until {OBJ_BATT} dies",
        "{OBJ_BATT} time remaining",
        "{OBJ_BATT} time left",
        "{OBJ_BATT} estimate",
        "when will the {OBJ_BATT} die",
    ],
    "monitoring.cpu_freq": [
        "{VERB_GET} {OBJ_CPU} frequency",
        "{VERB_GET} {OBJ_CPU} speed",
        "{VERB_GET} {OBJ_CPU} clock",
        "{OBJ_CPU} freq",
        "current {OBJ_CPU} clock",
        "cpu frequency",
        "cpu speed",
    ],
    "monitoring.gpu_status": [
        "{VERB_GET} {OBJ_GPU} status",
        "{VERB_GET} {OBJ_GPU}",
        "{OBJ_GPU} info",
        "{OBJ_GPU} state",
        "how is my {OBJ_GPU} doing",
    ],
    "monitoring.gpu_temp": [
        "{VERB_GET} {OBJ_GPU} temperature",
        "{VERB_GET} {OBJ_GPU} temp",
        "how hot is the {OBJ_GPU}",
        "{OBJ_GPU} temperature",
    ],
    "monitoring.fan_speed": [
        "{VERB_GET} {OBJ_FAN} speed",
        "{VERB_GET} {OBJ_FAN}",
        "{OBJ_FAN} rpm",
        "how fast is the {OBJ_FAN} spinning",
    ],
    "monitoring.wifi_signal": [
        "{VERB_GET} {OBJ_WIFI} signal",
        "{VERB_GET} {OBJ_WIFI}",
        "{OBJ_WIFI} strength",
        "how strong is my {OBJ_WIFI}",
        "wifi quality",
        "wifi signal",
    ],
    "monitoring.bt_devices": [
        "{VERB_SHOW} {OBJ_BT}",
        "{VERB_SHOW} bluetooth devices",
        "list {OBJ_BT}",
        "what {OBJ_BT} are paired",
    ],
    # ---- Session 68 Agent U: read-only informational queries ----
    "query.disk_space": [
        "how much disk space do i have",
        "how much disk space is left",
        "how much free space",
        "{VERB_SHOW} disk space",
        "{VERB_SHOW} free space",
        "{VERB_SHOW} disk usage",
        "disk free",
        "disk usage",
        "free space",
        "check disk space",
    ],
    "query.ip_address": [
        "what is my ip",
        "what's my ip",
        "show my ip",
        "show ip address",
        "what is my ip address",
        "whats my ip",
        "what ip do i have",
        "my ip",
        "show my ip address",
        "ip addr",
    ],
    "query.uptime": [
        "how long has my system been up",
        "system uptime",
        "how long has this been running",
        "uptime",
        "show uptime",
        "how long since last reboot",
        "time since boot",
    ],
    "query.cpu_temp": [
        "cpu temperature",
        "cpu temp",
        "how hot is my cpu",
        "what is my cpu temperature",
        "cpu temp celsius",
        "show cpu temperature",
    ],
    "query.memory_top": [
        "what is using the most memory",
        "top memory users",
        "biggest memory processes",
        "what processes are using the most memory",
        "memory hogs",
        "top ram users",
    ],
    "query.wifi_peers": [
        "show wifi networks",
        "list wifi networks",
        "nearby wifi",
        "wifi list",
        "available wifi",
        "what wifi is around",
    ],
    "query.kernel_version": [
        "kernel version",
        "what kernel am i running",
        "linux version",
        "show kernel version",
        "uname",
    ],
    "query.distro_version": [
        "what distro am i on",
        "what linux am i running",
        "distro version",
        "show distro",
        "os version",
        "operating system version",
    ],
    "query.loadavg": [
        "load average",
        "system load",
        "show load",
        "current load",
        "how loaded is my system",
    ],
    "query.logged_in_users": [
        "who is logged in",
        "list logged in users",
        "active users",
        "current users",
        "who is on this system",
    ],
    "monitoring.display_list": [
        "{VERB_SHOW} {OBJ_DISPLAY}s",
        "{VERB_SHOW} displays",
        "{VERB_SHOW} monitors",
        "list connected displays",
        "what displays are connected",
    ],
    "monitoring.display_primary": [
        "{VERB_GET} primary {OBJ_DISPLAY}",
        "{VERB_GET} main {OBJ_DISPLAY}",
        "{VERB_GET} primary monitor",
        "which is my primary {OBJ_DISPLAY}",
    ],

    # ----------------------------------------------------------------- window
    "window.list": [
        "{VERB_SHOW} {OBJ_WINDOW}s",
        "{VERB_SHOW} open {OBJ_WINDOW}s",
        "list {OBJ_WINDOW}s",
        "what windows are open",
        "list open apps",
        "list windows",
    ],
    "window.minimize": [
        "{HEDGE}minimize {OBJ_WINDOW}",
        "{HEDGE}minimize this",
        "{HEDGE}min {OBJ_WINDOW}",
        "send {OBJ_WINDOW} to taskbar",
    ],
    "window.maximize": [
        "{HEDGE}maximize {OBJ_WINDOW}",
        "{HEDGE}maximize this",
        "{HEDGE}max {OBJ_WINDOW}",
    ],
    "window.restore": [
        "{HEDGE}restore {OBJ_WINDOW}",
        "{HEDGE}unmaximize {OBJ_WINDOW}",
        "{HEDGE}unmin {OBJ_WINDOW}",
    ],
    "window.close": [
        "{HEDGE}close {OBJ_WINDOW}",
        "{HEDGE}close this",
        "{HEDGE}{VERB_CLOSE} {OBJ_WINDOW}",
        "x out",
    ],
    "window.fullscreen_toggle": [
        "{HEDGE}{VERB_TOGGLE} fullscreen",
        "{HEDGE}fullscreen {OBJ_WINDOW}",
        "{HEDGE}go fullscreen",
        "{HEDGE}exit fullscreen",
        "f11",
    ],

    # -------------------------------------------------------------- workspace
    "workspace.list": [
        "{VERB_SHOW} {OBJ_WORKSPACE}s",
        "{VERB_SHOW} workspaces",
        "list {OBJ_WORKSPACE}s",
        "what workspaces exist",
    ],
    "workspace.next": [
        "{HEDGE}next {OBJ_WORKSPACE}",
        "{HEDGE}next desktop",
        "go to next {OBJ_WORKSPACE}",
        "ws next",
    ],
    "workspace.prev": [
        "{HEDGE}previous {OBJ_WORKSPACE}",
        "{HEDGE}prev {OBJ_WORKSPACE}",
        "{HEDGE}previous desktop",
        "go to previous {OBJ_WORKSPACE}",
        "ws prev",
    ],
    "workspace.new": [
        "{HEDGE}new {OBJ_WORKSPACE}",
        "{HEDGE}create {OBJ_WORKSPACE}",
        "{HEDGE}add a {OBJ_WORKSPACE}",
        "{HEDGE}make a new desktop",
    ],
    "workspace.show_all": [
        "{HEDGE}{VERB_SHOW} all {OBJ_WORKSPACE}s",
        "{HEDGE}overview",
        "{HEDGE}expose",
        "{HEDGE}mission control",
        "show all workspaces",
        "expose desktops",
    ],

    # ---------------------------------------------------------------- service
    "service.list": [
        "{VERB_SHOW} services",
        "{VERB_SHOW} systemd services",
        "list services",
        "list running services",
        "what services are running",
    ],

    # ----------------------------------------------------------------- driver
    "driver.list": [
        "{VERB_SHOW} drivers",
        "{VERB_SHOW} loaded drivers",
        "{VERB_SHOW} kernel modules",
        "list drivers",
        "list kernel modules",
        "lsmod",
        "what drivers are loaded",
    ],

    # ----------------------------------------------------------------- script
    "script.list": [
        "{VERB_SHOW} scripts",
        "{VERB_SHOW} my scripts",
        "{VERB_SHOW} available scripts",
        "list scripts",
        "what scripts are available",
        "what scripts can i run",
    ],

    # ------------------------------------------------------------------- pe
    # Session 68 Agent W — direct PE loader invocation from NL.  These all
    # route to the pe.* handlers registered in contusion_handlers.py.  The
    # actual path arg binding is done by contusion_dictionary + Agent T's
    # compound/slot engine at dispatch time.
    "pe.run": [
        "run {PE_TARGET} with pe loader",
        "run {PE_TARGET} through pe loader",
        "run {PE_TARGET} via pe loader",
        "execute {PE_TARGET} with pe loader",
        "load {PE_TARGET} in pe loader",
        "open {PE_TARGET} with pe loader",
        "launch {PE_TARGET} with peloader",
        "run {PE_TARGET} on pe loader",
        "run this exe",
        "run the exe",
        "load the exe",
        "peload {PE_TARGET}",
    ],
    "pe.analyze": [
        "analyze {PE_TARGET}",
        "analyze this pe file",
        "inspect {PE_TARGET}",
        "look at this exe",
        "what is in this exe",
        "check {PE_TARGET}",
        "is {PE_TARGET} 32 bit",
        "is {PE_TARGET} 64 bit",
        "pe info for {PE_TARGET}",
        "show pe headers for {PE_TARGET}",
    ],
    "pe.install_msi": [
        "install this msi",
        "install {PE_TARGET}",
        "run the msi",
        "install msi {PE_TARGET}",
        "install msi from {PE_TARGET}",
        "install windows package {PE_TARGET}",
        "msiexec {PE_TARGET}",
        "run msi installer",
    ],
    "pe.list_recent": [
        "list recent pe runs",
        "show recent exe runs",
        "what exes did i run",
        "pe history",
        "recent pe invocations",
    ],
    "pe.clear_cache": [
        "clear pe cache",
        "clean pe downloads",
        "empty pe download cache",
        "wipe pe cache",
    ],

    # Generic script runner (S68): discovers script name from prefix patterns
    # like "run X" / "execute X" / "show X info" / "run the X script". The
    # actual arg binding is done by contusion_dictionary when it gets the
    # handler_type back. Put these here so set_smoke's "run hello" and
    # "show system info" route to script.run and the live handler probes
    # /etc/ai-control/scripts.d/ + ~/.ai/scripts.d/ for the matching .sh.
    "script.run": [
        "run hello",
        "run system-info",
        "run system info",
        "run pacman-refresh",
        "run disk-cleanup",
        "show system info",
        "show disk cleanup",
        "run the hello script",
        "run the system-info script",
        "execute hello",
        "execute system-info",
    ],

    # PowerShell .ps1 runner (Session 65). The actual script name is
    # discovered at runtime by contusion_dictionary._parse_single — these
    # templates only need to cover a no-arg-name probe surface plus a few
    # named samples so the v2 lookup has SOMETHING to return for the
    # generic "run powershell" / "system-info.ps1" phrasing. The arg-bearing
    # router is in contusion_dictionary.
    "script.run_ps1": [
        "{HEDGE}{VERB_OPEN} powershell {OBJ_SCRIPT_NAME}{POLITE}",
        "{HEDGE}{VERB_OPEN} pwsh {OBJ_SCRIPT_NAME}{POLITE}",
        "{HEDGE}execute {OBJ_SCRIPT_NAME}.ps1{POLITE}",
        "{HEDGE}run {OBJ_SCRIPT_NAME}.ps1{POLITE}",
    ],

    # ----------------------------------------------------------------- claude
    "app.claude_status": [
        "is claude installed",
        "{VERB_GET} claude status",
        "is claude code installed",
        "claude status",
        "claude installed",
        "do i have claude",
        "do i have claude code",
        "check if claude is installed",
    ],
    "app.claude_workspace_init": [
        "{HEDGE}init claude workspace",
        "{HEDGE}initialize claude workspace",
        "{HEDGE}set up claude workspace",
        "{HEDGE}create claude workspace",
        "claude workspace init",
    ],

    # ------------------------------------------------------------------- game
    "game.list": [
        "{VERB_SHOW} {ART}games",
        "{VERB_SHOW} installed games",
        "list games",
        "list running games",
        "list all games",
        "what games are installed",
        "what games do i have",
        "my game library",
    ],
    "game.running": [
        "{VERB_SHOW} running games",
        "what games are running",
        "is a game running",
        "running games",
    ],

    # -------------------------------------------------------------- clipboard
    "clipboard.get": [
        "{VERB_GET} clipboard",
        "{VERB_GET} {ART}clipboard contents",
        "what's in my clipboard",
        "what is on my clipboard",
        "show clipboard",
        "paste preview",
    ],
    "clipboard.clear": [
        "{HEDGE}clear {ART}clipboard",
        "{HEDGE}empty {ART}clipboard",
        "wipe clipboard",
        "reset clipboard",
    ],
    "clipboard.history": [
        "{VERB_SHOW} clipboard history",
        "{VERB_SHOW} {ART}clipboard history",
        "list clipboard history",
        "clipboard history",
        "what was on my clipboard before",
    ],
    "clipboard.paste_cursor": [
        "{HEDGE}paste at cursor",
        "{HEDGE}paste here",
        "{HEDGE}paste {ART}clipboard at cursor",
        "paste it",
    ],
}


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

_WS_RE = re.compile(r"\s+")
_TRAIL_PUNCT_RE = re.compile(r"[\s\.,!?;:'\"]+$")
_LEAD_WS_RE = re.compile(r"^\s+")


def _normalize(s: str) -> str:
    """Lowercase, collapse whitespace, strip leading whitespace and trailing punctuation."""
    if s is None:
        return ""
    s = s.lower()
    s = _WS_RE.sub(" ", s)
    s = _LEAD_WS_RE.sub("", s)
    s = _TRAIL_PUNCT_RE.sub("", s)
    return s.strip()


# ---------------------------------------------------------------------------
# Slot expansion
# ---------------------------------------------------------------------------

_SLOT_REF_RE = re.compile(r"\{([A-Z_][A-Z_0-9]*)\}")


def _expand_slots(template: str) -> Iterable[str]:
    """Expand a template containing {SLOT} references into all combinations."""
    refs = _SLOT_REF_RE.findall(template)
    if not refs:
        yield template
        return

    # De-duplicate refs preserving order so the same {SLOT} appearing twice
    # binds to the same value (avoids inflating the cartesian).
    seen: dict[str, int] = {}
    ordered: list[str] = []
    for r in refs:
        if r not in seen:
            seen[r] = len(ordered)
            ordered.append(r)

    pools = []
    for name in ordered:
        pool = _SLOTS.get(name)
        if pool is None:
            # Unknown slot — leave as literal so it shows up in audits.
            pool = ["{" + name + "}"]
        pools.append(pool)

    for combo in product(*pools):
        binding = dict(zip(ordered, combo))

        def _replace(m: re.Match) -> str:
            return binding[m.group(1)]

        yield _SLOT_REF_RE.sub(_replace, template)


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def compile_phrases() -> dict[str, list[tuple[str, float]]]:
    """For each template, expand all slot combos into concrete phrases.

    Returns: {phrase_normalized: [(handler_type, confidence), ...]}.
    Confidence skews higher for shorter, more specific phrases.
    """
    out: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for handler, templates in _TEMPLATES.items():
        for template in templates:
            for expanded in _expand_slots(template):
                normalized = _normalize(expanded)
                if not normalized or len(normalized) > 200:
                    continue
                # Higher confidence for shorter (more specific) phrases.
                conf = max(0.6, min(0.95, 1.0 - len(normalized) / 200))
                out[normalized].append((handler, conf))
    return dict(out)


def _resolve_best(phrases: dict[str, list[tuple[str, float]]]
                  ) -> dict[str, tuple[str, float]]:
    """Pick highest-confidence handler per phrase (first wins on tie)."""
    resolved: dict[str, tuple[str, float]] = {}
    for phrase, cands in phrases.items():
        # Sort stable by -confidence so first listed handler wins ties.
        best = max(cands, key=lambda c: c[1])
        resolved[phrase] = best
    return resolved


# ---------------------------------------------------------------------------
# Artifact build / load
# ---------------------------------------------------------------------------

def _build_artifact(payload: dict[str, Any], path: str) -> tuple[int, int, str]:
    """Pickle + compress + write.  Returns (raw_bytes, comp_bytes, ext)."""
    raw = pickle.dumps(payload, protocol=4)
    comp = _zstd_compress(raw)
    if comp is not None:
        ext = "zst"
    else:
        import gzip
        comp = gzip.compress(raw, compresslevel=9)
        ext = "gz"
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(comp)
    return len(raw), len(comp), ext


def _validate_pickle_source(path: str) -> None:
    """Refuse to unpickle from world-writable locations (S68 hardening).

    pickle.loads() executes arbitrary code during reconstruction. Gate on
    the actual filesystem mode of both the file and its parent directory —
    private tmpdirs (pytest's tmp_path_factory, mode 0700) are safe; a plain
    /tmp drop (mode 01777) is not.
    """
    resolved_path = os.path.realpath(path)
    st = os.stat(resolved_path)
    parent_st = os.stat(os.path.dirname(resolved_path) or "/")
    # File itself must not be world-writable
    if st.st_mode & stat.S_IWOTH:
        raise PermissionError(
            f"refusing to load pickle: file is world-writable: {resolved_path}"
        )
    # Parent dir must not be world-writable (blocks /tmp drop attacks)
    if parent_st.st_mode & stat.S_IWOTH:
        raise PermissionError(
            f"refusing to load pickle: parent dir is world-writable: {resolved_path}"
        )
    # Must be owned by root or the daemon user
    if st.st_uid not in (0, os.geteuid()):
        raise PermissionError(
            f"refusing to load pickle: bad owner uid={st.st_uid}"
        )


def _load_artifact(path: str) -> dict[str, Any]:
    """Read + sniff magic + decompress + unpickle."""
    _validate_pickle_source(path)
    with open(path, "rb") as f:
        blob = f.read()
    if blob.startswith(_GZIP_MAGIC):
        import gzip
        raw = gzip.decompress(blob)
    elif blob.startswith(_ZSTD_MAGIC):
        raw = _zstd_decompress(blob)
        if raw is None:
            raise RuntimeError(
                "dictionary_v2: artifact is zstd but no zstd backend available "
                "(need Python 3.14 compression.zstd or external `zstandard`)"
            )
    else:
        # Fall back: try zstd then gzip blindly.
        raw = _zstd_decompress(blob)
        if raw is None:
            try:
                import gzip
                raw = gzip.decompress(blob)
            except Exception as e:
                raise RuntimeError(f"dictionary_v2: unknown artifact format: {e}")
    return pickle.loads(raw)


# ---------------------------------------------------------------------------
# Lazy-loaded runtime cache + lookup
# ---------------------------------------------------------------------------

_DEFAULT_PATHS = (
    "/usr/share/ai-control/dictionary_v2.pkl.zst",
    "/usr/share/ai-control/dictionary_v2.pkl.gz",
    "/var/cache/ai-control/dictionary_v2.pkl.zst",
    "/var/cache/ai-control/dictionary_v2.pkl.gz",
)

_LOAD_LOCK = threading.Lock()
_PHRASES: Optional[dict[str, tuple[str, float]]] = None
_LOAD_PATH: Optional[str] = None
_LOAD_ERROR: Optional[str] = None


def _find_artifact() -> Optional[str]:
    env = os.environ.get("AICONTROL_DICTIONARY_V2_PATH")
    if env and os.path.exists(env):
        return env
    for p in _DEFAULT_PATHS:
        if os.path.exists(p):
            return p
    return None


def _ensure_loaded() -> None:
    """Lazy-load the artifact under a lock."""
    global _PHRASES, _LOAD_PATH, _LOAD_ERROR
    if _PHRASES is not None:
        return
    with _LOAD_LOCK:
        if _PHRASES is not None:
            return
        path = _find_artifact()
        if path is None:
            _LOAD_ERROR = "no dictionary_v2 artifact found in default paths"
            _PHRASES = {}
            return
        try:
            payload = _load_artifact(path)
            phrases = payload.get("phrases", {})
            # Normalize value shape: tuple(handler, conf) or list -> tuple
            cleaned: dict[str, tuple[str, float]] = {}
            for k, v in phrases.items():
                if isinstance(v, (list, tuple)) and len(v) >= 2:
                    cleaned[k] = (str(v[0]), float(v[1]))
            _PHRASES = cleaned
            _LOAD_PATH = path
        except Exception as e:
            _LOAD_ERROR = f"failed to load {path}: {e!r}"
            _PHRASES = {}


def lookup(phrase: str, threshold: float = 0.7) -> Optional[dict[str, Any]]:
    """Look up a normalized phrase. Returns dict on hit, None on miss.

    On hit:
        {"handler_type": str, "args": {}, "confidence": float, "source": "v2_template"}
    """
    if not phrase:
        return None
    _ensure_loaded()
    assert _PHRASES is not None
    norm = _normalize(phrase)
    hit = _PHRASES.get(norm)
    if hit is None:
        return None
    handler, conf = hit
    if conf < threshold:
        return None
    return {
        "handler_type": handler,
        "args": {},
        "confidence": conf,
        "source": "v2_template",
    }


def lookup_multi(phrase: str, top_k: int = 3, threshold: float = 0.0
                 ) -> list[dict[str, Any]]:
    """Return top-K candidate handlers for an (often short/ambiguous) phrase.

    Used by contusion._maybe_clarify() to detect ambiguity. Unlike lookup()
    which returns the single best exact-match handler, lookup_multi() also
    probes prefix + containment matches so that a short input like "volume"
    or "up" surfaces MULTIPLE handlers with comparable confidence.

    Matching cascade (per handler):
      1. Exact normalized phrase → full stored confidence.
      2. Input is a prefix of a stored phrase → 0.85 * stored_conf.
      3. Stored phrase is a prefix of input → 0.80 * stored_conf.
      4. Whole-word substring match either direction → 0.60 * stored_conf.

    For each handler_type we keep the HIGHEST confidence match across all
    matching phrases, then sort-desc and truncate to top_k.

    Args:
        phrase: user instruction (pre-normalization).
        top_k: max number of candidates to return.
        threshold: minimum confidence (after scaling) for a candidate to be
                   included.  Default 0.0 = include everything; caller
                   (contusion._maybe_clarify) applies its own thresholds.

    Returns:
        list of {"handler_type": str, "confidence": float,
                 "source": "v2_template", "example_phrase": str}
        sorted by confidence desc, length <= top_k. Empty list on miss.
    """
    if not phrase:
        return []
    _ensure_loaded()
    assert _PHRASES is not None
    if not _PHRASES:
        return []
    norm = _normalize(phrase)
    if not norm:
        return []

    # best[handler] = (confidence, example_phrase)
    best: dict[str, tuple[float, str]] = {}

    def _consider(handler: str, conf: float, example: str) -> None:
        prev = best.get(handler)
        if prev is None or conf > prev[0]:
            best[handler] = (conf, example)

    # 1. exact hit (full confidence)
    exact = _PHRASES.get(norm)
    if exact is not None:
        handler, conf = exact
        _consider(handler, conf, norm)

    # 2-4. scan — O(N) over ~7K phrases is ~sub-millisecond and only fires on
    #      ambiguous short inputs (contusion._maybe_clarify gates this).
    norm_space = " " + norm + " "
    for p, (handler, conf) in _PHRASES.items():
        if p == norm:
            continue  # already handled above
        scaled = None
        if p.startswith(norm + " ") or p.startswith(norm):
            # input is prefix of stored
            scaled = 0.85 * conf
        elif norm.startswith(p + " ") or norm.startswith(p):
            # stored is prefix of input
            scaled = 0.80 * conf
        else:
            # whole-word substring either direction
            p_space = " " + p + " "
            if p_space in norm_space or norm_space in p_space:
                scaled = 0.60 * conf
        if scaled is not None and scaled >= threshold:
            _consider(handler, scaled, p)

    if not best:
        return []

    ranked = sorted(
        (
            {
                "handler_type": h,
                "confidence": round(c, 4),
                "source": "v2_template",
                "example_phrase": ex,
            }
            for h, (c, ex) in best.items()
        ),
        key=lambda d: d["confidence"],
        reverse=True,
    )
    return ranked[:top_k]


def stats() -> dict[str, Any]:
    """Diagnostic info — for /diagnostics or `ai diag`."""
    _ensure_loaded()
    return {
        "loaded": _PHRASES is not None and bool(_PHRASES),
        "phrase_count": len(_PHRASES) if _PHRASES else 0,
        "path": _LOAD_PATH,
        "error": _LOAD_ERROR,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_build(out_path: str) -> int:
    t0 = time.perf_counter()
    phrases = compile_phrases()
    resolved = _resolve_best(phrases)
    raw_b, comp_b, ext = _build_artifact(
        {
            "version": 2,
            "compiled_at": int(time.time()),
            "phrase_count": len(resolved),
            "phrases": resolved,
        },
        out_path,
    )
    dt = time.perf_counter() - t0
    ratio = (raw_b / comp_b) if comp_b else 0.0
    print(
        f"Built {len(resolved)} phrases in {dt*1000:.1f}ms "
        f"({raw_b/1024:.1f}KB raw, {comp_b/1024:.1f}KB compressed, "
        f"{ratio:.1f}x ratio, ext={ext}, path={out_path})"
    )
    # Also report any duplicate-handler collisions as a sanity check.
    dupes = sum(1 for v in phrases.values() if len(v) > 1)
    if dupes:
        print(f"  note: {dupes} phrases mapped to multiple handlers (best-conf wins)")
    return 0


def _cli_lookup(phrase: str) -> int:
    r = lookup(phrase)
    if r is None:
        print("no match")
        return 1
    print(json.dumps(r, indent=2))
    return 0


def _cli_bench(n: int = 1000) -> int:
    # Warm-up the lazy load.
    _ensure_loaded()
    if not _PHRASES:
        print("bench: no phrases loaded")
        return 1

    samples = [
        "turn down the volume",
        "play music",
        "lock screen",
        "what is my brightness",
        "show bluetooth devices",
        "screenshot please",
        "list windows",
        "is claude installed",
        "next song",
        "battery left",
        "this is not a known phrase at all",
    ]
    times: list[float] = []
    misses = 0
    for i in range(n):
        ph = samples[i % len(samples)]
        t0 = time.perf_counter()
        r = lookup(ph)
        t1 = time.perf_counter()
        times.append(t1 - t0)
        if r is None:
            misses += 1
    times.sort()
    mean_us = sum(times) / len(times) * 1e6
    max_us = times[-1] * 1e6
    p99_us = times[int(len(times) * 0.99)] * 1e6
    p50_us = times[len(times) // 2] * 1e6
    print(
        f"bench: n={n} mean={mean_us:.2f}us p50={p50_us:.2f}us "
        f"p99={p99_us:.2f}us max={max_us:.2f}us misses={misses}"
    )
    return 0


def _main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="dictionary_v2")
    ap.add_argument("--build", help="Build .pkl.zst at this path")
    ap.add_argument("--lookup", help="Test single phrase lookup")
    ap.add_argument("--bench", action="store_true", help="Latency benchmark (1000 runs)")
    ap.add_argument("--bench-n", type=int, default=1000, help="Bench iteration count")
    ap.add_argument("--stats", action="store_true", help="Show loaded artifact info")
    args = ap.parse_args(argv)

    if args.build:
        return _cli_build(args.build)
    if args.lookup:
        return _cli_lookup(args.lookup)
    if args.bench:
        return _cli_bench(args.bench_n)
    if args.stats:
        print(json.dumps(stats(), indent=2))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
