"""
Contusion Dictionary - Comprehensive command dictionary and context engine.

Provides:
- 200+ Linux commands organized by category with security classifications
- Natural language parsing into executable action sequences
- 40+ application profiles with CLI/GUI interfaces and shortcuts
- Trust system integration: safe=100, moderate=300, dangerous=600
"""

import logging
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("ai-control.contusion")


# ---------------------------------------------------------------------------
# Security Classification
# ---------------------------------------------------------------------------

class SecurityLevel(str, Enum):
    SAFE = "safe"           # Read-only, no side effects
    MODERATE = "moderate"   # Creates/modifies files, installs packages
    DANGEROUS = "dangerous" # Deletes, formats, modifies system

# Trust thresholds matching auth.py tiers
TRUST_THRESHOLDS = {
    SecurityLevel.SAFE: 100,       # TRUST_AUTH_USER
    SecurityLevel.MODERATE: 300,   # Elevated user
    SecurityLevel.DANGEROUS: 600,  # TRUST_AUTH_ADMIN
}


# ---------------------------------------------------------------------------
# Command Dictionary - 200+ commands in 12 categories
# ---------------------------------------------------------------------------

COMMANDS = {
    # ------------------------------------------------------------------
    # FILE MANAGEMENT (25 commands)
    # ------------------------------------------------------------------
    "file_management": {
        "list_files": {
            "cmd": "ls -la {path}",
            "desc": "List files in directory with details",
            "security": "safe",
            "trust": 100,
        },
        "list_tree": {
            "cmd": "tree -L {depth} {path}",
            "desc": "Show directory tree structure",
            "security": "safe",
            "trust": 100,
        },
        "copy": {
            "cmd": "cp -r {src} {dst}",
            "desc": "Copy file or directory recursively",
            "security": "moderate",
            "trust": 300,
        },
        "move": {
            "cmd": "mv {src} {dst}",
            "desc": "Move or rename file/directory",
            "security": "moderate",
            "trust": 300,
        },
        "delete": {
            "cmd": "rm {path}",
            "desc": "Delete file",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "delete_recursive": {
            "cmd": "rm -rf {path}",
            "desc": "Delete directory and all contents",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
            "confirm": True,
        },
        "find": {
            "cmd": "find {path} -name '{pattern}'",
            "desc": "Find files matching pattern",
            "security": "safe",
            "trust": 100,
        },
        "find_type": {
            "cmd": "find {path} -type {type} -name '{pattern}'",
            "desc": "Find files/dirs by type and pattern",
            "security": "safe",
            "trust": 100,
        },
        "find_modified": {
            "cmd": "find {path} -mtime -{days}",
            "desc": "Find files modified within N days",
            "security": "safe",
            "trust": 100,
        },
        "find_size": {
            "cmd": "find {path} -size +{size}",
            "desc": "Find files larger than size (e.g. 100M)",
            "security": "safe",
            "trust": 100,
        },
        "disk_usage": {
            "cmd": "du -sh {path}",
            "desc": "Check disk usage of path",
            "security": "safe",
            "trust": 100,
        },
        "disk_usage_sorted": {
            "cmd": "du -sh {path}/* | sort -rh | head -20",
            "desc": "Show largest items in directory",
            "security": "safe",
            "trust": 100,
        },
        "create_dir": {
            "cmd": "mkdir -p {path}",
            "desc": "Create directory and parents",
            "security": "moderate",
            "trust": 300,
        },
        "touch": {
            "cmd": "touch {path}",
            "desc": "Create empty file or update timestamp",
            "security": "moderate",
            "trust": 300,
        },
        "link_symbolic": {
            "cmd": "ln -s {target} {link}",
            "desc": "Create symbolic link",
            "security": "moderate",
            "trust": 300,
        },
        "link_hard": {
            "cmd": "ln {target} {link}",
            "desc": "Create hard link",
            "security": "moderate",
            "trust": 300,
        },
        "stat": {
            "cmd": "stat {path}",
            "desc": "Show detailed file information",
            "security": "safe",
            "trust": 100,
        },
        "file_type": {
            "cmd": "file {path}",
            "desc": "Determine file type",
            "security": "safe",
            "trust": 100,
        },
        "realpath": {
            "cmd": "realpath {path}",
            "desc": "Resolve absolute path",
            "security": "safe",
            "trust": 100,
        },
        "basename": {
            "cmd": "basename {path}",
            "desc": "Extract filename from path",
            "security": "safe",
            "trust": 100,
        },
        "dirname": {
            "cmd": "dirname {path}",
            "desc": "Extract directory from path",
            "security": "safe",
            "trust": 100,
        },
        "locate": {
            "cmd": "locate {pattern}",
            "desc": "Fast file search using mlocate database",
            "security": "safe",
            "trust": 100,
        },
        "which": {
            "cmd": "which {command}",
            "desc": "Show full path of command",
            "security": "safe",
            "trust": 100,
        },
        "read_file": {
            "cmd": "cat {path}",
            "desc": "Display file contents",
            "security": "safe",
            "trust": 100,
        },
        "write_file": {
            "cmd": "tee {path}",
            "desc": "Write stdin to file",
            "security": "moderate",
            "trust": 300,
        },
    },

    # ------------------------------------------------------------------
    # PACKAGE MANAGEMENT (20 commands)
    # ------------------------------------------------------------------
    "package_management": {
        "install": {
            "cmd": "sudo pacman -S --noconfirm {package}",
            "desc": "Install package from official repos",
            "security": "moderate",
            "trust": 300,
        },
        "remove": {
            "cmd": "sudo pacman -Rns {package}",
            "desc": "Remove package and dependencies",
            "security": "moderate",
            "trust": 300,
        },
        "update": {
            "cmd": "sudo pacman -Syu --noconfirm",
            "desc": "Full system update",
            "security": "moderate",
            "trust": 300,
        },
        "search": {
            "cmd": "pacman -Ss {query}",
            "desc": "Search official repositories",
            "security": "safe",
            "trust": 100,
        },
        "info": {
            "cmd": "pacman -Si {package}",
            "desc": "Show package information",
            "security": "safe",
            "trust": 100,
        },
        "info_local": {
            "cmd": "pacman -Qi {package}",
            "desc": "Show installed package information",
            "security": "safe",
            "trust": 100,
        },
        "list_installed": {
            "cmd": "pacman -Q",
            "desc": "List all installed packages",
            "security": "safe",
            "trust": 100,
        },
        "list_explicit": {
            "cmd": "pacman -Qe",
            "desc": "List explicitly installed packages",
            "security": "safe",
            "trust": 100,
        },
        "list_orphans": {
            "cmd": "pacman -Qdt",
            "desc": "List orphaned packages",
            "security": "safe",
            "trust": 100,
        },
        "remove_orphans": {
            "cmd": "sudo pacman -Rns $(pacman -Qdtq)",
            "desc": "Remove all orphaned packages",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "files_owned": {
            "cmd": "pacman -Ql {package}",
            "desc": "List files owned by package",
            "security": "safe",
            "trust": 100,
        },
        "file_owner": {
            "cmd": "pacman -Qo {path}",
            "desc": "Find which package owns a file",
            "security": "safe",
            "trust": 100,
        },
        "clean_cache": {
            "cmd": "sudo pacman -Sc --noconfirm",
            "desc": "Clean package cache",
            "security": "moderate",
            "trust": 300,
        },
        "clean_cache_all": {
            "cmd": "sudo pacman -Scc --noconfirm",
            "desc": "Remove all cached packages",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "downgrade": {
            "cmd": "sudo pacman -U {path}",
            "desc": "Install/downgrade from local package file",
            "security": "moderate",
            "trust": 300,
        },
        "aur_install": {
            "cmd": "yay -S --noconfirm {package}",
            "desc": "Install package from AUR via yay",
            "security": "moderate",
            "trust": 300,
        },
        "aur_search": {
            "cmd": "yay -Ss {query}",
            "desc": "Search AUR packages",
            "security": "safe",
            "trust": 100,
        },
        "check_updates": {
            "cmd": "checkupdates",
            "desc": "Check for available updates",
            "security": "safe",
            "trust": 100,
        },
        "mirror_update": {
            "cmd": "sudo reflector --latest 20 --sort rate --save /etc/pacman.d/mirrorlist",
            "desc": "Update mirror list with fastest mirrors",
            "security": "moderate",
            "trust": 300,
        },
        "pacman_log": {
            "cmd": "tail -n {lines} /var/log/pacman.log",
            "desc": "Show recent pacman activity",
            "security": "safe",
            "trust": 100,
        },
    },

    # ------------------------------------------------------------------
    # NETWORK (22 commands)
    # ------------------------------------------------------------------
    "network": {
        "ip_address": {
            "cmd": "ip addr show",
            "desc": "Show all network interfaces and addresses",
            "security": "safe",
            "trust": 100,
        },
        "ip_route": {
            "cmd": "ip route show",
            "desc": "Show routing table",
            "security": "safe",
            "trust": 100,
        },
        "ping": {
            "cmd": "ping -c {count} {host}",
            "desc": "Ping a host",
            "security": "safe",
            "trust": 100,
        },
        "traceroute": {
            "cmd": "traceroute {host}",
            "desc": "Trace route to host",
            "security": "safe",
            "trust": 100,
        },
        "dns_lookup": {
            "cmd": "dig {domain}",
            "desc": "DNS lookup",
            "security": "safe",
            "trust": 100,
        },
        "dns_reverse": {
            "cmd": "dig -x {ip}",
            "desc": "Reverse DNS lookup",
            "security": "safe",
            "trust": 100,
        },
        "nslookup": {
            "cmd": "nslookup {domain}",
            "desc": "Query DNS nameserver",
            "security": "safe",
            "trust": 100,
        },
        "curl": {
            "cmd": "curl -sS {url}",
            "desc": "Fetch URL content",
            "security": "safe",
            "trust": 100,
        },
        "curl_headers": {
            "cmd": "curl -sI {url}",
            "desc": "Fetch HTTP headers only",
            "security": "safe",
            "trust": 100,
        },
        "wget": {
            "cmd": "wget -O {output} {url}",
            "desc": "Download file from URL",
            "security": "moderate",
            "trust": 300,
        },
        "ss_listen": {
            "cmd": "ss -tlnp",
            "desc": "Show listening TCP ports",
            "security": "safe",
            "trust": 100,
        },
        "ss_established": {
            "cmd": "ss -tnp",
            "desc": "Show established TCP connections",
            "security": "safe",
            "trust": 100,
        },
        "netstat": {
            "cmd": "ss -tulnp",
            "desc": "Show all listening sockets (TCP+UDP)",
            "security": "safe",
            "trust": 100,
        },
        "nmcli_status": {
            "cmd": "nmcli general status",
            "desc": "Show NetworkManager status",
            "security": "safe",
            "trust": 100,
        },
        "nmcli_connections": {
            "cmd": "nmcli connection show",
            "desc": "List network connections",
            "security": "safe",
            "trust": 100,
        },
        "nmcli_wifi_list": {
            "cmd": "nmcli device wifi list",
            "desc": "List available WiFi networks",
            "security": "safe",
            "trust": 100,
        },
        "nmcli_wifi_connect": {
            "cmd": "sudo nmcli device wifi connect '{ssid}' password '{password}'",
            "desc": "Connect to WiFi network",
            "security": "moderate",
            "trust": 300,
        },
        "nmcli_disconnect": {
            "cmd": "nmcli connection down '{connection}'",
            "desc": "Disconnect a network connection",
            "security": "moderate",
            "trust": 300,
        },
        "firewall_status": {
            "cmd": "sudo nft list ruleset",
            "desc": "Show current firewall rules",
            "security": "safe",
            "trust": 100,
        },
        "firewall_add": {
            "cmd": "sudo nft add rule inet filter input tcp dport {port} accept",
            "desc": "Open a firewall port",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "iptables_list": {
            "cmd": "sudo iptables -L -n -v",
            "desc": "List iptables rules (legacy)",
            "security": "safe",
            "trust": 100,
        },
        "bandwidth_test": {
            "cmd": "curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python3",
            "desc": "Run internet speed test",
            "security": "safe",
            "trust": 100,
        },
    },

    # ------------------------------------------------------------------
    # SYSTEM (22 commands)
    # ------------------------------------------------------------------
    "system": {
        "hostname": {
            "cmd": "hostnamectl",
            "desc": "Show system hostname and OS info",
            "security": "safe",
            "trust": 100,
        },
        "set_hostname": {
            "cmd": "sudo hostnamectl set-hostname {name}",
            "desc": "Set system hostname",
            "security": "dangerous",
            "trust": 600,
        },
        "uptime": {
            "cmd": "uptime",
            "desc": "Show system uptime and load",
            "security": "safe",
            "trust": 100,
        },
        "uname": {
            "cmd": "uname -a",
            "desc": "Show kernel and system info",
            "security": "safe",
            "trust": 100,
        },
        "dmesg": {
            "cmd": "sudo dmesg --human --color=always | tail -50",
            "desc": "Show recent kernel messages",
            "security": "safe",
            "trust": 100,
        },
        "lsblk": {
            "cmd": "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT",
            "desc": "List block devices",
            "security": "safe",
            "trust": 100,
        },
        "lscpu": {
            "cmd": "lscpu",
            "desc": "Show CPU information",
            "security": "safe",
            "trust": 100,
        },
        "lsmem": {
            "cmd": "free -h",
            "desc": "Show memory usage",
            "security": "safe",
            "trust": 100,
        },
        "lspci": {
            "cmd": "lspci -v",
            "desc": "List PCI devices (GPU, NIC, etc.)",
            "security": "safe",
            "trust": 100,
        },
        "lsusb": {
            "cmd": "lsusb",
            "desc": "List USB devices",
            "security": "safe",
            "trust": 100,
        },
        "env_vars": {
            "cmd": "env | sort",
            "desc": "Show environment variables",
            "security": "safe",
            "trust": 100,
        },
        "date": {
            "cmd": "date '+%Y-%m-%d %H:%M:%S %Z'",
            "desc": "Show current date and time",
            "security": "safe",
            "trust": 100,
        },
        "set_timezone": {
            "cmd": "sudo timedatectl set-timezone {timezone}",
            "desc": "Set system timezone",
            "security": "moderate",
            "trust": 300,
        },
        "reboot": {
            "cmd": "sudo systemctl reboot",
            "desc": "Reboot the system",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
            "confirm": True,
        },
        "shutdown": {
            "cmd": "sudo systemctl poweroff",
            "desc": "Shut down the system",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
            "confirm": True,
        },
        "suspend": {
            "cmd": "sudo systemctl suspend",
            "desc": "Suspend the system",
            "security": "moderate",
            "trust": 300,
        },
        "journalctl_recent": {
            "cmd": "journalctl -n {lines} --no-pager",
            "desc": "Show recent system log entries",
            "security": "safe",
            "trust": 100,
        },
        "journalctl_unit": {
            "cmd": "journalctl -u {unit} -n {lines} --no-pager",
            "desc": "Show logs for a systemd unit",
            "security": "safe",
            "trust": 100,
        },
        "journalctl_boot": {
            "cmd": "journalctl -b --no-pager | tail -100",
            "desc": "Show current boot log",
            "security": "safe",
            "trust": 100,
        },
        "kernel_modules": {
            "cmd": "lsmod",
            "desc": "List loaded kernel modules",
            "security": "safe",
            "trust": 100,
        },
        "load_module": {
            "cmd": "sudo modprobe {module}",
            "desc": "Load a kernel module",
            "security": "dangerous",
            "trust": 600,
        },
        "unload_module": {
            "cmd": "sudo modprobe -r {module}",
            "desc": "Unload a kernel module",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
    },

    # ------------------------------------------------------------------
    # USER MANAGEMENT (16 commands)
    # ------------------------------------------------------------------
    "user_management": {
        "whoami": {
            "cmd": "whoami",
            "desc": "Show current user",
            "security": "safe",
            "trust": 100,
        },
        "id": {
            "cmd": "id {user}",
            "desc": "Show user identity and groups",
            "security": "safe",
            "trust": 100,
        },
        "who": {
            "cmd": "who",
            "desc": "Show logged-in users",
            "security": "safe",
            "trust": 100,
        },
        "last": {
            "cmd": "last -n {count}",
            "desc": "Show recent logins",
            "security": "safe",
            "trust": 100,
        },
        "add_user": {
            "cmd": "sudo useradd -m -s /bin/bash {username}",
            "desc": "Create a new user",
            "security": "dangerous",
            "trust": 600,
        },
        "delete_user": {
            "cmd": "sudo userdel -r {username}",
            "desc": "Delete user and home directory",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
            "confirm": True,
        },
        "set_password": {
            "cmd": "echo '{username}:{password}' | sudo chpasswd",
            "desc": "Set user password",
            "security": "dangerous",
            "trust": 600,
        },
        "add_to_group": {
            "cmd": "sudo usermod -aG {group} {username}",
            "desc": "Add user to group",
            "security": "moderate",
            "trust": 300,
        },
        "remove_from_group": {
            "cmd": "sudo gpasswd -d {username} {group}",
            "desc": "Remove user from group",
            "security": "moderate",
            "trust": 300,
        },
        "list_groups": {
            "cmd": "groups {username}",
            "desc": "List user groups",
            "security": "safe",
            "trust": 100,
        },
        "create_group": {
            "cmd": "sudo groupadd {group}",
            "desc": "Create a new group",
            "security": "moderate",
            "trust": 300,
        },
        "delete_group": {
            "cmd": "sudo groupdel {group}",
            "desc": "Delete a group",
            "security": "dangerous",
            "trust": 600,
        },
        "passwd_expire": {
            "cmd": "sudo chage -l {username}",
            "desc": "Show password aging information",
            "security": "safe",
            "trust": 100,
        },
        "lock_user": {
            "cmd": "sudo usermod -L {username}",
            "desc": "Lock user account",
            "security": "dangerous",
            "trust": 600,
        },
        "unlock_user": {
            "cmd": "sudo usermod -U {username}",
            "desc": "Unlock user account",
            "security": "dangerous",
            "trust": 600,
        },
        "sudoers_edit": {
            "cmd": "sudo EDITOR=nano visudo",
            "desc": "Edit sudoers file safely",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
    },

    # ------------------------------------------------------------------
    # SERVICE MANAGEMENT (18 commands)
    # ------------------------------------------------------------------
    "service_management": {
        "status": {
            "cmd": "systemctl status {service}",
            "desc": "Show service status",
            "security": "safe",
            "trust": 100,
        },
        "start": {
            "cmd": "sudo systemctl start {service}",
            "desc": "Start a service",
            "security": "moderate",
            "trust": 300,
        },
        "stop": {
            "cmd": "sudo systemctl stop {service}",
            "desc": "Stop a service",
            "security": "moderate",
            "trust": 300,
        },
        "restart": {
            "cmd": "sudo systemctl restart {service}",
            "desc": "Restart a service",
            "security": "moderate",
            "trust": 300,
        },
        "reload": {
            "cmd": "sudo systemctl reload {service}",
            "desc": "Reload service configuration",
            "security": "moderate",
            "trust": 300,
        },
        "enable": {
            "cmd": "sudo systemctl enable {service}",
            "desc": "Enable service at boot",
            "security": "moderate",
            "trust": 300,
        },
        "disable": {
            "cmd": "sudo systemctl disable {service}",
            "desc": "Disable service at boot",
            "security": "moderate",
            "trust": 300,
        },
        "mask": {
            "cmd": "sudo systemctl mask {service}",
            "desc": "Mask service (prevent starting)",
            "security": "dangerous",
            "trust": 600,
        },
        "unmask": {
            "cmd": "sudo systemctl unmask {service}",
            "desc": "Unmask a masked service",
            "security": "moderate",
            "trust": 300,
        },
        "list_running": {
            "cmd": "systemctl list-units --type=service --state=running",
            "desc": "List running services",
            "security": "safe",
            "trust": 100,
        },
        "list_failed": {
            "cmd": "systemctl list-units --type=service --state=failed",
            "desc": "List failed services",
            "security": "safe",
            "trust": 100,
        },
        "list_enabled": {
            "cmd": "systemctl list-unit-files --type=service --state=enabled",
            "desc": "List enabled services",
            "security": "safe",
            "trust": 100,
        },
        "list_timers": {
            "cmd": "systemctl list-timers --all",
            "desc": "List all systemd timers",
            "security": "safe",
            "trust": 100,
        },
        "daemon_reload": {
            "cmd": "sudo systemctl daemon-reload",
            "desc": "Reload systemd unit files",
            "security": "moderate",
            "trust": 300,
        },
        "logs": {
            "cmd": "journalctl -u {service} -f",
            "desc": "Follow service logs in real time",
            "security": "safe",
            "trust": 100,
        },
        "is_active": {
            "cmd": "systemctl is-active {service}",
            "desc": "Check if service is running",
            "security": "safe",
            "trust": 100,
        },
        "is_enabled": {
            "cmd": "systemctl is-enabled {service}",
            "desc": "Check if service is enabled",
            "security": "safe",
            "trust": 100,
        },
        "show_unit": {
            "cmd": "systemctl show {service}",
            "desc": "Show all properties of a service",
            "security": "safe",
            "trust": 100,
        },
    },

    # ------------------------------------------------------------------
    # GIT (20 commands)
    # ------------------------------------------------------------------
    "git": {
        "status": {
            "cmd": "git status",
            "desc": "Show working tree status",
            "security": "safe",
            "trust": 100,
        },
        "log": {
            "cmd": "git log --oneline -n {count}",
            "desc": "Show recent commits",
            "security": "safe",
            "trust": 100,
        },
        "log_graph": {
            "cmd": "git log --oneline --graph --all -n 30",
            "desc": "Show commit graph",
            "security": "safe",
            "trust": 100,
        },
        "diff": {
            "cmd": "git diff",
            "desc": "Show unstaged changes",
            "security": "safe",
            "trust": 100,
        },
        "diff_staged": {
            "cmd": "git diff --cached",
            "desc": "Show staged changes",
            "security": "safe",
            "trust": 100,
        },
        "add": {
            "cmd": "git add {path}",
            "desc": "Stage files for commit",
            "security": "moderate",
            "trust": 300,
        },
        "add_all": {
            "cmd": "git add -A",
            "desc": "Stage all changes",
            "security": "moderate",
            "trust": 300,
        },
        "commit": {
            "cmd": "git commit -m '{message}'",
            "desc": "Create a commit",
            "security": "moderate",
            "trust": 300,
        },
        "push": {
            "cmd": "git push {remote} {branch}",
            "desc": "Push to remote repository",
            "security": "moderate",
            "trust": 300,
        },
        "pull": {
            "cmd": "git pull {remote} {branch}",
            "desc": "Pull from remote repository",
            "security": "moderate",
            "trust": 300,
        },
        "clone": {
            "cmd": "git clone {url} {path}",
            "desc": "Clone a repository",
            "security": "moderate",
            "trust": 300,
        },
        "branch_list": {
            "cmd": "git branch -a",
            "desc": "List all branches",
            "security": "safe",
            "trust": 100,
        },
        "branch_create": {
            "cmd": "git checkout -b {branch}",
            "desc": "Create and switch to new branch",
            "security": "moderate",
            "trust": 300,
        },
        "branch_delete": {
            "cmd": "git branch -d {branch}",
            "desc": "Delete a branch",
            "security": "moderate",
            "trust": 300,
        },
        "checkout": {
            "cmd": "git checkout {branch}",
            "desc": "Switch to branch",
            "security": "moderate",
            "trust": 300,
        },
        "merge": {
            "cmd": "git merge {branch}",
            "desc": "Merge branch into current",
            "security": "moderate",
            "trust": 300,
        },
        "stash": {
            "cmd": "git stash",
            "desc": "Stash working changes",
            "security": "moderate",
            "trust": 300,
        },
        "stash_pop": {
            "cmd": "git stash pop",
            "desc": "Apply and remove latest stash",
            "security": "moderate",
            "trust": 300,
        },
        "reset_hard": {
            "cmd": "git reset --hard {ref}",
            "desc": "Discard all changes to ref",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
            "confirm": True,
        },
        "remote_list": {
            "cmd": "git remote -v",
            "desc": "List remote repositories",
            "security": "safe",
            "trust": 100,
        },
    },

    # ------------------------------------------------------------------
    # TEXT PROCESSING (20 commands)
    # ------------------------------------------------------------------
    "text_processing": {
        "grep": {
            "cmd": "grep -rn '{pattern}' {path}",
            "desc": "Search for pattern in files",
            "security": "safe",
            "trust": 100,
        },
        "grep_ignore_case": {
            "cmd": "grep -rni '{pattern}' {path}",
            "desc": "Case-insensitive search in files",
            "security": "safe",
            "trust": 100,
        },
        "grep_count": {
            "cmd": "grep -rc '{pattern}' {path}",
            "desc": "Count pattern matches in files",
            "security": "safe",
            "trust": 100,
        },
        "sed_replace": {
            "cmd": "sed -i 's/{old}/{new}/g' {path}",
            "desc": "Find and replace in file",
            "security": "moderate",
            "trust": 300,
        },
        "awk_columns": {
            "cmd": "awk '{{print ${columns}}}' {path}",
            "desc": "Extract columns from file",
            "security": "safe",
            "trust": 100,
        },
        "sort": {
            "cmd": "sort {path}",
            "desc": "Sort file contents",
            "security": "safe",
            "trust": 100,
        },
        "sort_unique": {
            "cmd": "sort -u {path}",
            "desc": "Sort and deduplicate",
            "security": "safe",
            "trust": 100,
        },
        "uniq": {
            "cmd": "uniq -c {path}",
            "desc": "Show unique lines with counts",
            "security": "safe",
            "trust": 100,
        },
        "wc": {
            "cmd": "wc -l {path}",
            "desc": "Count lines in file",
            "security": "safe",
            "trust": 100,
        },
        "head": {
            "cmd": "head -n {lines} {path}",
            "desc": "Show first N lines of file",
            "security": "safe",
            "trust": 100,
        },
        "tail": {
            "cmd": "tail -n {lines} {path}",
            "desc": "Show last N lines of file",
            "security": "safe",
            "trust": 100,
        },
        "tail_follow": {
            "cmd": "tail -f {path}",
            "desc": "Follow file output in real time",
            "security": "safe",
            "trust": 100,
        },
        "cut": {
            "cmd": "cut -d'{delimiter}' -f{fields} {path}",
            "desc": "Extract fields from delimited file",
            "security": "safe",
            "trust": 100,
        },
        "tr": {
            "cmd": "tr '{from}' '{to}'",
            "desc": "Translate/replace characters",
            "security": "safe",
            "trust": 100,
        },
        "diff_files": {
            "cmd": "diff -u {file1} {file2}",
            "desc": "Compare two files",
            "security": "safe",
            "trust": 100,
        },
        "tee_append": {
            "cmd": "tee -a {path}",
            "desc": "Append stdin to file",
            "security": "moderate",
            "trust": 300,
        },
        "xargs": {
            "cmd": "xargs -I{{}} {command}",
            "desc": "Build commands from stdin",
            "security": "moderate",
            "trust": 300,
        },
        "jq_parse": {
            "cmd": "jq '{filter}' {path}",
            "desc": "Parse and query JSON",
            "security": "safe",
            "trust": 100,
        },
        "base64_encode": {
            "cmd": "base64 {path}",
            "desc": "Base64 encode a file",
            "security": "safe",
            "trust": 100,
        },
        "base64_decode": {
            "cmd": "base64 -d {path}",
            "desc": "Base64 decode a file",
            "security": "safe",
            "trust": 100,
        },
    },

    # ------------------------------------------------------------------
    # COMPRESSION (14 commands)
    # ------------------------------------------------------------------
    "compression": {
        "tar_create": {
            "cmd": "tar -czf {archive}.tar.gz {path}",
            "desc": "Create gzipped tar archive",
            "security": "moderate",
            "trust": 300,
        },
        "tar_extract": {
            "cmd": "tar -xzf {archive} -C {dest}",
            "desc": "Extract gzipped tar archive",
            "security": "moderate",
            "trust": 300,
        },
        "tar_list": {
            "cmd": "tar -tzf {archive}",
            "desc": "List contents of tar archive",
            "security": "safe",
            "trust": 100,
        },
        "tar_xz_create": {
            "cmd": "tar -cJf {archive}.tar.xz {path}",
            "desc": "Create xz-compressed tar archive",
            "security": "moderate",
            "trust": 300,
        },
        "tar_xz_extract": {
            "cmd": "tar -xJf {archive} -C {dest}",
            "desc": "Extract xz-compressed tar archive",
            "security": "moderate",
            "trust": 300,
        },
        "zip_create": {
            "cmd": "zip -r {archive}.zip {path}",
            "desc": "Create ZIP archive",
            "security": "moderate",
            "trust": 300,
        },
        "zip_extract": {
            "cmd": "unzip {archive} -d {dest}",
            "desc": "Extract ZIP archive",
            "security": "moderate",
            "trust": 300,
        },
        "zip_list": {
            "cmd": "unzip -l {archive}",
            "desc": "List ZIP archive contents",
            "security": "safe",
            "trust": 100,
        },
        "gzip": {
            "cmd": "gzip {path}",
            "desc": "Compress file with gzip",
            "security": "moderate",
            "trust": 300,
        },
        "gunzip": {
            "cmd": "gunzip {path}",
            "desc": "Decompress gzip file",
            "security": "moderate",
            "trust": 300,
        },
        "zstd_compress": {
            "cmd": "zstd {path}",
            "desc": "Compress file with zstandard",
            "security": "moderate",
            "trust": 300,
        },
        "zstd_decompress": {
            "cmd": "zstd -d {path}",
            "desc": "Decompress zstd file",
            "security": "moderate",
            "trust": 300,
        },
        "xz_compress": {
            "cmd": "xz {path}",
            "desc": "Compress file with xz",
            "security": "moderate",
            "trust": 300,
        },
        "xz_decompress": {
            "cmd": "xz -d {path}",
            "desc": "Decompress xz file",
            "security": "moderate",
            "trust": 300,
        },
    },

    # ------------------------------------------------------------------
    # PERMISSIONS (14 commands)
    # ------------------------------------------------------------------
    "permissions": {
        "chmod": {
            "cmd": "chmod {mode} {path}",
            "desc": "Change file permissions",
            "security": "moderate",
            "trust": 300,
        },
        "chmod_recursive": {
            "cmd": "chmod -R {mode} {path}",
            "desc": "Change permissions recursively",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "chown": {
            "cmd": "sudo chown {owner}:{group} {path}",
            "desc": "Change file ownership",
            "security": "moderate",
            "trust": 300,
        },
        "chown_recursive": {
            "cmd": "sudo chown -R {owner}:{group} {path}",
            "desc": "Change ownership recursively",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "setfacl": {
            "cmd": "setfacl -m u:{user}:{perms} {path}",
            "desc": "Set file ACL for user",
            "security": "moderate",
            "trust": 300,
        },
        "getfacl": {
            "cmd": "getfacl {path}",
            "desc": "Show file ACLs",
            "security": "safe",
            "trust": 100,
        },
        "umask": {
            "cmd": "umask {mask}",
            "desc": "Set default permission mask",
            "security": "moderate",
            "trust": 300,
        },
        "suid_find": {
            "cmd": "find / -perm -4000 -type f 2>/dev/null",
            "desc": "Find files with SUID bit set",
            "security": "safe",
            "trust": 100,
        },
        "sgid_find": {
            "cmd": "find / -perm -2000 -type f 2>/dev/null",
            "desc": "Find files with SGID bit set",
            "security": "safe",
            "trust": 100,
        },
        "world_writable": {
            "cmd": "find / -perm -o+w -type f 2>/dev/null",
            "desc": "Find world-writable files",
            "security": "safe",
            "trust": 100,
        },
        "sticky_bit": {
            "cmd": "chmod +t {path}",
            "desc": "Set sticky bit on directory",
            "security": "moderate",
            "trust": 300,
        },
        "make_executable": {
            "cmd": "chmod +x {path}",
            "desc": "Make file executable",
            "security": "moderate",
            "trust": 300,
        },
        "make_readonly": {
            "cmd": "chmod 444 {path}",
            "desc": "Make file read-only",
            "security": "moderate",
            "trust": 300,
        },
        "immutable": {
            "cmd": "sudo chattr +i {path}",
            "desc": "Make file immutable (cannot be modified/deleted)",
            "security": "dangerous",
            "trust": 600,
        },
    },

    # ------------------------------------------------------------------
    # MONITORING / PROCESS (22 commands)
    # ------------------------------------------------------------------
    "monitoring": {
        "ps_all": {
            "cmd": "ps aux",
            "desc": "List all running processes",
            "security": "safe",
            "trust": 100,
        },
        "ps_tree": {
            "cmd": "ps auxf",
            "desc": "Show process tree",
            "security": "safe",
            "trust": 100,
        },
        "ps_user": {
            "cmd": "ps -u {user}",
            "desc": "List processes for user",
            "security": "safe",
            "trust": 100,
        },
        "top_snapshot": {
            "cmd": "top -bn1 | head -20",
            "desc": "Snapshot of top processes by CPU",
            "security": "safe",
            "trust": 100,
        },
        "htop": {
            "cmd": "htop",
            "desc": "Interactive process monitor",
            "security": "safe",
            "trust": 100,
        },
        "kill_pid": {
            "cmd": "kill {pid}",
            "desc": "Send SIGTERM to process",
            "security": "moderate",
            "trust": 300,
        },
        "kill_force": {
            "cmd": "kill -9 {pid}",
            "desc": "Force kill process (SIGKILL)",
            "security": "dangerous",
            "trust": 600,
        },
        "killall": {
            "cmd": "killall {name}",
            "desc": "Kill all processes by name",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "pkill": {
            "cmd": "pkill -f '{pattern}'",
            "desc": "Kill processes matching pattern",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "pgrep": {
            "cmd": "pgrep -af '{pattern}'",
            "desc": "Find processes matching pattern",
            "security": "safe",
            "trust": 100,
        },
        "nice": {
            "cmd": "nice -n {priority} {command}",
            "desc": "Run command with adjusted priority",
            "security": "moderate",
            "trust": 300,
        },
        "renice": {
            "cmd": "sudo renice -n {priority} -p {pid}",
            "desc": "Change running process priority",
            "security": "moderate",
            "trust": 300,
        },
        "memory_info": {
            "cmd": "free -h",
            "desc": "Show memory usage",
            "security": "safe",
            "trust": 100,
        },
        "memory_detailed": {
            "cmd": "cat /proc/meminfo",
            "desc": "Detailed memory information",
            "security": "safe",
            "trust": 100,
        },
        "cpu_usage": {
            "cmd": "mpstat -P ALL 1 1",
            "desc": "Per-CPU usage statistics",
            "security": "safe",
            "trust": 100,
        },
        "iostat": {
            "cmd": "iostat -xh 1 1",
            "desc": "Disk I/O statistics",
            "security": "safe",
            "trust": 100,
        },
        "vmstat": {
            "cmd": "vmstat 1 5",
            "desc": "Virtual memory statistics",
            "security": "safe",
            "trust": 100,
        },
        "load_average": {
            "cmd": "cat /proc/loadavg",
            "desc": "Show system load average",
            "security": "safe",
            "trust": 100,
        },
        "strace": {
            "cmd": "strace -p {pid} -e trace={syscalls}",
            "desc": "Trace system calls of process",
            "security": "moderate",
            "trust": 300,
        },
        "lsof_port": {
            "cmd": "lsof -i :{port}",
            "desc": "Show process using a port",
            "security": "safe",
            "trust": 100,
        },
        "lsof_file": {
            "cmd": "lsof {path}",
            "desc": "Show processes using a file",
            "security": "safe",
            "trust": 100,
        },
        "gpu_status": {
            "cmd": "nvidia-smi",
            "desc": "Show NVIDIA GPU status and usage",
            "security": "safe",
            "trust": 100,
        },
    },

    # ------------------------------------------------------------------
    # DISK (16 commands)
    # ------------------------------------------------------------------
    "disk": {
        "df": {
            "cmd": "df -h",
            "desc": "Show disk space usage",
            "security": "safe",
            "trust": 100,
        },
        "df_inodes": {
            "cmd": "df -i",
            "desc": "Show inode usage",
            "security": "safe",
            "trust": 100,
        },
        "mount_list": {
            "cmd": "mount | column -t",
            "desc": "List mounted filesystems",
            "security": "safe",
            "trust": 100,
        },
        "mount_device": {
            "cmd": "sudo mount {device} {mountpoint}",
            "desc": "Mount a device",
            "security": "moderate",
            "trust": 300,
        },
        "umount": {
            "cmd": "sudo umount {mountpoint}",
            "desc": "Unmount a filesystem",
            "security": "moderate",
            "trust": 300,
        },
        "fdisk_list": {
            "cmd": "sudo fdisk -l",
            "desc": "List disk partitions",
            "security": "safe",
            "trust": 100,
        },
        "blkid": {
            "cmd": "sudo blkid",
            "desc": "Show block device attributes (UUID, type)",
            "security": "safe",
            "trust": 100,
        },
        "mkfs": {
            "cmd": "sudo mkfs.{fstype} {device}",
            "desc": "Create filesystem on device",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
            "confirm": True,
        },
        "fsck": {
            "cmd": "sudo fsck {device}",
            "desc": "Check and repair filesystem",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
        },
        "fstab_show": {
            "cmd": "cat /etc/fstab",
            "desc": "Show filesystem mount table",
            "security": "safe",
            "trust": 100,
        },
        "swap_status": {
            "cmd": "swapon --show",
            "desc": "Show swap space usage",
            "security": "safe",
            "trust": 100,
        },
        "smartctl": {
            "cmd": "sudo smartctl -a {device}",
            "desc": "Show SMART disk health data",
            "security": "safe",
            "trust": 100,
        },
        "ncdu": {
            "cmd": "ncdu {path}",
            "desc": "Interactive disk usage explorer",
            "security": "safe",
            "trust": 100,
        },
        "fallocate": {
            "cmd": "fallocate -l {size} {path}",
            "desc": "Allocate file of given size",
            "security": "moderate",
            "trust": 300,
        },
        "dd": {
            "cmd": "sudo dd if={input} of={output} bs={blocksize} status=progress",
            "desc": "Block-level copy (disk image, etc.)",
            "security": "dangerous",
            "trust": 600,
            "dangerous": True,
            "confirm": True,
        },
        "parted": {
            "cmd": "sudo parted {device} print",
            "desc": "Show partition table details",
            "security": "safe",
            "trust": 100,
        },
    },

    # ------------------------------------------------------------------
    # PE LOADER / WINDOWS COMPAT (10 commands)
    # ------------------------------------------------------------------
    "pe_compat": {
        "run_exe": {
            "cmd": "peloader {exe_path}",
            "desc": "Run a Windows .exe via PE loader",
            "security": "moderate",
            "trust": 300,
        },
        "run_game": {
            "cmd": "pe-run-game {exe_path}",
            "desc": "Run a game with DXVK/Vulkan auto-setup",
            "security": "moderate",
            "trust": 300,
        },
        "create_shortcut": {
            "cmd": "pe-create-shortcut {exe_path}",
            "desc": "Create desktop shortcut for .exe",
            "security": "moderate",
            "trust": 300,
        },
        "pe_dump": {
            "cmd": "pe-dump {exe_path}",
            "desc": "Dump PE header information",
            "security": "safe",
            "trust": 100,
        },
        "dxvk_configure": {
            "cmd": "DXVK_LOG_LEVEL=info DXVK_STATE_CACHE=1 peloader {exe_path}",
            "desc": "Run .exe with DXVK diagnostics",
            "security": "moderate",
            "trust": 300,
        },
        "scm_status": {
            "cmd": "systemctl status scm-daemon",
            "desc": "Show Windows Service Control Manager status",
            "security": "safe",
            "trust": 100,
        },
        "scm_list": {
            "cmd": "curl -s http://localhost:8420/services | jq .",
            "desc": "List registered Windows services",
            "security": "safe",
            "trust": 100,
        },
        "trust_status": {
            "cmd": "curl -s http://localhost:8420/trust/status | jq .",
            "desc": "Show trust kernel module status",
            "security": "safe",
            "trust": 100,
        },
        "trust_subject": {
            "cmd": "curl -s http://localhost:8420/trust/subject/{pid} | jq .",
            "desc": "Query trust level of a process",
            "security": "safe",
            "trust": 100,
        },
        "ai_daemon_health": {
            "cmd": "curl -s http://localhost:8420/health | jq .",
            "desc": "Check AI control daemon health",
            "security": "safe",
            "trust": 100,
        },
    },

    # ------------------------------------------------------------------
    # MISCELLANEOUS / UTILITY (10 commands)
    # ------------------------------------------------------------------
    "utility": {
        "alias_list": {
            "cmd": "alias",
            "desc": "List shell aliases",
            "security": "safe",
            "trust": 100,
        },
        "history": {
            "cmd": "history | tail -n {count}",
            "desc": "Show recent command history",
            "security": "safe",
            "trust": 100,
        },
        "cron_list": {
            "cmd": "crontab -l",
            "desc": "List cron jobs for current user",
            "security": "safe",
            "trust": 100,
        },
        "cron_edit": {
            "cmd": "crontab -e",
            "desc": "Edit crontab",
            "security": "moderate",
            "trust": 300,
        },
        "at_schedule": {
            "cmd": "echo '{command}' | at {time}",
            "desc": "Schedule a one-time command",
            "security": "moderate",
            "trust": 300,
        },
        "md5sum": {
            "cmd": "md5sum {path}",
            "desc": "Calculate MD5 checksum",
            "security": "safe",
            "trust": 100,
        },
        "sha256sum": {
            "cmd": "sha256sum {path}",
            "desc": "Calculate SHA-256 checksum",
            "security": "safe",
            "trust": 100,
        },
        "watch": {
            "cmd": "watch -n {interval} {command}",
            "desc": "Run command periodically and show output",
            "security": "safe",
            "trust": 100,
        },
        "screen_new": {
            "cmd": "screen -S {name}",
            "desc": "Start a named screen session",
            "security": "moderate",
            "trust": 300,
        },
        "tmux_new": {
            "cmd": "tmux new-session -s {name}",
            "desc": "Start a named tmux session",
            "security": "moderate",
            "trust": 300,
        },
    },
}


# ---------------------------------------------------------------------------
# Application Profiles - 40+ apps with CLI/GUI interfaces
# ---------------------------------------------------------------------------

@dataclass
class AppProfile:
    name: str
    launch_cmd: str
    app_type: str               # "gui", "cli", "tui", "service"
    package: str                # Arch package name
    description: str
    categories: list[str] = field(default_factory=list)
    shortcuts: dict = field(default_factory=dict)   # key-combo -> action
    operations: dict = field(default_factory=dict)   # name -> command
    kill_cmd: str = ""
    config_path: str = ""
    desktop_file: str = ""


APP_PROFILES: dict[str, AppProfile] = {
    # ---- Web Browsers ----
    "firefox": AppProfile(
        name="Firefox",
        launch_cmd="firefox",
        app_type="gui",
        package="firefox",
        description="Mozilla Firefox web browser",
        categories=["browser", "internet"],
        shortcuts={
            "Ctrl+T": "new tab",
            "Ctrl+W": "close tab",
            "Ctrl+L": "focus address bar",
            "Ctrl+R": "reload page",
            "Ctrl+Shift+T": "reopen closed tab",
            "Ctrl+Tab": "next tab",
            "Ctrl+Shift+Tab": "previous tab",
            "Ctrl+D": "bookmark page",
            "Ctrl+H": "history",
            "Ctrl+Shift+P": "private window",
            "F11": "fullscreen",
            "F5": "reload",
            "Alt+Left": "back",
            "Alt+Right": "forward",
        },
        operations={
            "open_url": "firefox {url}",
            "open_private": "firefox --private-window {url}",
            "new_window": "firefox --new-window",
            "screenshot": "firefox --screenshot {output} {url}",
            "safe_mode": "firefox --safe-mode",
            "profile_manager": "firefox --ProfileManager",
        },
        kill_cmd="pkill firefox",
        config_path="~/.mozilla/firefox/",
        desktop_file="firefox.desktop",
    ),

    "chromium": AppProfile(
        name="Chromium",
        launch_cmd="chromium",
        app_type="gui",
        package="chromium",
        description="Chromium web browser (open-source Chrome)",
        categories=["browser", "internet"],
        shortcuts={
            "Ctrl+T": "new tab",
            "Ctrl+W": "close tab",
            "Ctrl+L": "focus address bar",
            "Ctrl+N": "new window",
            "Ctrl+Shift+N": "incognito window",
            "Ctrl+Shift+T": "reopen closed tab",
            "Ctrl+Tab": "next tab",
            "F12": "developer tools",
        },
        operations={
            "open_url": "chromium {url}",
            "incognito": "chromium --incognito {url}",
            "kiosk": "chromium --kiosk {url}",
            "headless_screenshot": "chromium --headless --screenshot={output} {url}",
            "disable_gpu": "chromium --disable-gpu",
        },
        kill_cmd="pkill chromium",
        config_path="~/.config/chromium/",
        desktop_file="chromium.desktop",
    ),

    # ---- Communication ----
    "discord": AppProfile(
        name="Discord",
        launch_cmd="discord",
        app_type="gui",
        package="discord",
        description="Discord voice and text chat",
        categories=["communication", "gaming"],
        shortcuts={
            "Ctrl+K": "quick switcher",
            "Ctrl+Shift+M": "toggle mute",
            "Ctrl+Shift+D": "toggle deafen",
            "Alt+Up": "previous channel",
            "Alt+Down": "next channel",
        },
        operations={
            "launch": "discord",
            "minimize_tray": "discord --start-minimized",
        },
        kill_cmd="pkill -f discord",
        config_path="~/.config/discord/",
        desktop_file="discord.desktop",
    ),

    # ---- Gaming ----
    "steam": AppProfile(
        name="Steam",
        launch_cmd="steam",
        app_type="gui",
        package="steam",
        description="Valve Steam game platform",
        categories=["gaming", "store"],
        shortcuts={
            "Shift+Tab": "overlay (in-game)",
            "F12": "screenshot (in-game)",
        },
        operations={
            "launch": "steam",
            "big_picture": "steam -bigpicture",
            "run_game": "steam steam://rungameid/{appid}",
            "install_game": "steam steam://install/{appid}",
            "validate": "steam steam://validate/{appid}",
            "console": "steam -console",
            "offline": "steam -offline",
        },
        kill_cmd="pkill -f steam",
        config_path="~/.steam/",
        desktop_file="steam.desktop",
    ),

    "lutris": AppProfile(
        name="Lutris",
        launch_cmd="lutris",
        app_type="gui",
        package="lutris",
        description="Open gaming platform (manages games and runners)",
        categories=["gaming"],
        operations={
            "launch": "lutris",
            "run_game": "lutris lutris:rungame/{slug}",
            "install": "lutris lutris:install/{slug}",
            "list_games": "lutris -l",
        },
        kill_cmd="pkill lutris",
        config_path="~/.config/lutris/",
        desktop_file="net.lutris.Lutris.desktop",
    ),

    "gamemode": AppProfile(
        name="GameMode",
        launch_cmd="gamemoderun {command}",
        app_type="cli",
        package="gamemode",
        description="Feral Interactive game optimizer daemon",
        categories=["gaming", "performance"],
        operations={
            "run_with": "gamemoderun {command}",
            "status": "gamemoded -s",
            "test": "gamemoded -t",
        },
    ),

    "mangohud": AppProfile(
        name="MangoHud",
        launch_cmd="mangohud {command}",
        app_type="cli",
        package="mangohud",
        description="Vulkan/OpenGL performance overlay",
        categories=["gaming", "monitoring"],
        operations={
            "run_with": "mangohud {command}",
            "config_edit": "$EDITOR ~/.config/MangoHud/MangoHud.conf",
        },
        config_path="~/.config/MangoHud/",
    ),

    # ---- File Manager ----
    "thunar": AppProfile(
        name="Thunar",
        launch_cmd="thunar",
        app_type="gui",
        package="thunar",
        description="XFCE file manager",
        categories=["file_manager", "utility"],
        shortcuts={
            "Ctrl+L": "address bar",
            "Ctrl+E": "open terminal here",
            "Ctrl+H": "toggle hidden files",
            "Alt+Home": "home directory",
            "Alt+Up": "parent directory",
            "F2": "rename",
            "Delete": "trash",
            "Shift+Delete": "permanent delete",
            "Ctrl+N": "new window",
        },
        operations={
            "open_dir": "thunar {path}",
            "bulk_rename": "thunar --bulk-rename {files}",
        },
        kill_cmd="pkill thunar",
        config_path="~/.config/Thunar/",
        desktop_file="thunar.desktop",
    ),

    "nautilus": AppProfile(
        name="Nautilus",
        launch_cmd="nautilus",
        app_type="gui",
        package="nautilus",
        description="GNOME Files file manager",
        categories=["file_manager", "utility"],
        operations={
            "open_dir": "nautilus {path}",
        },
        desktop_file="org.gnome.Nautilus.desktop",
    ),

    # ---- Terminal Emulators ----
    "xfce4_terminal": AppProfile(
        name="XFCE Terminal",
        launch_cmd="xfce4-terminal",
        app_type="gui",
        package="xfce4-terminal",
        description="XFCE terminal emulator",
        categories=["terminal", "utility"],
        shortcuts={
            "Ctrl+Shift+T": "new tab",
            "Ctrl+Shift+N": "new window",
            "Ctrl+Shift+C": "copy",
            "Ctrl+Shift+V": "paste",
            "Ctrl+Shift+W": "close tab",
            "Ctrl+Shift+Q": "close window",
            "F11": "fullscreen",
        },
        operations={
            "open": "xfce4-terminal",
            "open_dir": "xfce4-terminal --working-directory={path}",
            "run_command": "xfce4-terminal -e '{command}'",
            "new_tab": "xfce4-terminal --tab",
        },
        config_path="~/.config/xfce4/terminal/",
        desktop_file="xfce4-terminal.desktop",
    ),

    "alacritty": AppProfile(
        name="Alacritty",
        launch_cmd="alacritty",
        app_type="gui",
        package="alacritty",
        description="GPU-accelerated terminal emulator",
        categories=["terminal", "utility"],
        shortcuts={
            "Ctrl+Shift+C": "copy",
            "Ctrl+Shift+V": "paste",
            "Ctrl+Shift+Space": "vi mode",
            "Ctrl+Plus": "increase font size",
            "Ctrl+Minus": "decrease font size",
            "Ctrl+0": "reset font size",
        },
        operations={
            "open": "alacritty",
            "open_dir": "alacritty --working-directory {path}",
            "run_command": "alacritty -e {command}",
        },
        config_path="~/.config/alacritty/alacritty.toml",
        desktop_file="Alacritty.desktop",
    ),

    "kitty": AppProfile(
        name="Kitty",
        launch_cmd="kitty",
        app_type="gui",
        package="kitty",
        description="GPU-based terminal emulator",
        categories=["terminal", "utility"],
        shortcuts={
            "Ctrl+Shift+Enter": "new window",
            "Ctrl+Shift+T": "new tab",
            "Ctrl+Shift+C": "copy",
            "Ctrl+Shift+V": "paste",
        },
        operations={
            "open": "kitty",
            "open_dir": "kitty --directory {path}",
            "ssh": "kitty +kitten ssh {host}",
            "diff": "kitty +kitten diff {file1} {file2}",
        },
        config_path="~/.config/kitty/kitty.conf",
        desktop_file="kitty.desktop",
    ),

    # ---- Text Editors / IDEs ----
    "vscode": AppProfile(
        name="Visual Studio Code",
        launch_cmd="code",
        app_type="gui",
        package="code",
        description="Microsoft Visual Studio Code editor",
        categories=["editor", "development"],
        shortcuts={
            "Ctrl+P": "quick open file",
            "Ctrl+Shift+P": "command palette",
            "Ctrl+`": "toggle terminal",
            "Ctrl+B": "toggle sidebar",
            "Ctrl+Shift+E": "explorer",
            "Ctrl+Shift+F": "search in files",
            "Ctrl+Shift+G": "source control",
            "Ctrl+Shift+X": "extensions",
            "Ctrl+K Ctrl+S": "keyboard shortcuts",
            "F5": "start debugging",
        },
        operations={
            "open_file": "code {path}",
            "open_dir": "code {path}",
            "diff": "code --diff {file1} {file2}",
            "install_ext": "code --install-extension {id}",
            "list_ext": "code --list-extensions",
            "new_window": "code --new-window",
        },
        kill_cmd="pkill -f 'code'",
        config_path="~/.config/Code/",
        desktop_file="code.desktop",
    ),

    "vim": AppProfile(
        name="Vim",
        launch_cmd="vim",
        app_type="tui",
        package="vim",
        description="Vi Improved text editor",
        categories=["editor"],
        shortcuts={
            "i": "insert mode",
            "Esc": "normal mode",
            ":w": "save",
            ":q": "quit",
            ":wq": "save and quit",
            ":q!": "quit without saving",
            "dd": "delete line",
            "yy": "yank (copy) line",
            "p": "paste",
            "/pattern": "search forward",
            "u": "undo",
            "Ctrl+R": "redo",
        },
        operations={
            "open_file": "vim {path}",
            "open_at_line": "vim +{line} {path}",
            "diff": "vimdiff {file1} {file2}",
            "readonly": "vim -R {path}",
        },
        config_path="~/.vimrc",
    ),

    "nano": AppProfile(
        name="Nano",
        launch_cmd="nano",
        app_type="tui",
        package="nano",
        description="Simple terminal text editor",
        categories=["editor"],
        shortcuts={
            "Ctrl+O": "save",
            "Ctrl+X": "exit",
            "Ctrl+W": "search",
            "Ctrl+K": "cut line",
            "Ctrl+U": "paste",
            "Ctrl+G": "help",
        },
        operations={
            "open_file": "nano {path}",
            "open_at_line": "nano +{line} {path}",
        },
        config_path="~/.nanorc",
    ),

    "neovim": AppProfile(
        name="Neovim",
        launch_cmd="nvim",
        app_type="tui",
        package="neovim",
        description="Hyperextensible Vim-based editor",
        categories=["editor", "development"],
        operations={
            "open_file": "nvim {path}",
            "open_at_line": "nvim +{line} {path}",
            "diff": "nvim -d {file1} {file2}",
            "headless_cmd": "nvim --headless -c '{command}' -c 'qa'",
        },
        config_path="~/.config/nvim/",
    ),

    # ---- Media ----
    "vlc": AppProfile(
        name="VLC",
        launch_cmd="vlc",
        app_type="gui",
        package="vlc",
        description="VLC media player",
        categories=["media", "video", "audio"],
        shortcuts={
            "Space": "play/pause",
            "F": "fullscreen",
            "Ctrl+H": "minimal interface",
            "Alt+Left": "jump back 10s",
            "Alt+Right": "jump forward 10s",
            "+": "faster",
            "-": "slower",
            "=": "normal speed",
            "M": "mute",
            "Ctrl+Up": "volume up",
            "Ctrl+Down": "volume down",
        },
        operations={
            "play": "vlc {path}",
            "play_url": "vlc {url}",
            "headless": "cvlc {path}",
            "enqueue": "vlc --playlist-enqueue {path}",
            "stream": "vlc {input} --sout '#transcode{{vcodec=h264}}:standard{{access=http,mux=ts,dst=:8080}}'",
        },
        kill_cmd="pkill vlc",
        config_path="~/.config/vlc/",
        desktop_file="vlc.desktop",
    ),

    "mpv": AppProfile(
        name="MPV",
        launch_cmd="mpv",
        app_type="gui",
        package="mpv",
        description="Minimalist media player",
        categories=["media", "video", "audio"],
        shortcuts={
            "Space": "play/pause",
            "F": "fullscreen",
            "Q": "quit and save position",
            "q": "quit",
            "Left": "seek back 5s",
            "Right": "seek forward 5s",
            "9/0": "volume down/up",
            "m": "mute",
        },
        operations={
            "play": "mpv {path}",
            "play_url": "mpv {url}",
            "audio_only": "mpv --no-video {path}",
            "loop": "mpv --loop=inf {path}",
            "screenshot": "mpv --screenshot-format=png {path}",
        },
        config_path="~/.config/mpv/",
    ),

    # ---- Image Editing ----
    "gimp": AppProfile(
        name="GIMP",
        launch_cmd="gimp",
        app_type="gui",
        package="gimp",
        description="GNU Image Manipulation Program",
        categories=["graphics", "image_editing"],
        shortcuts={
            "Ctrl+N": "new image",
            "Ctrl+O": "open image",
            "Ctrl+S": "save",
            "Ctrl+Shift+E": "export as",
            "Ctrl+Z": "undo",
            "Ctrl+Y": "redo",
            "R": "rectangle select",
            "E": "ellipse select",
            "P": "paintbrush",
            "Shift+O": "color picker",
        },
        operations={
            "open": "gimp {path}",
            "batch_resize": "gimp -i -b '(let* ((image (car (gimp-file-load RUN-NONINTERACTIVE \"{input}\" \"{input}\"))) (drawable (car (gimp-image-get-active-drawable image)))) (gimp-image-scale-full image {width} {height} INTERPOLATION-CUBIC) (gimp-file-overwrite RUN-NONINTERACTIVE image drawable \"{output}\" \"{output}\") (gimp-image-delete image))' -b '(gimp-quit 0)'",
        },
        kill_cmd="pkill gimp",
        config_path="~/.config/GIMP/",
        desktop_file="gimp.desktop",
    ),

    "imagemagick": AppProfile(
        name="ImageMagick",
        launch_cmd="convert",
        app_type="cli",
        package="imagemagick",
        description="CLI image manipulation toolkit",
        categories=["graphics", "image_editing"],
        operations={
            "resize": "convert {input} -resize {geometry} {output}",
            "crop": "convert {input} -crop {geometry} {output}",
            "rotate": "convert {input} -rotate {degrees} {output}",
            "format_convert": "convert {input} {output}",
            "thumbnail": "convert {input} -thumbnail {size} {output}",
            "info": "identify {path}",
            "montage": "montage {inputs} -geometry +5+5 {output}",
        },
    ),

    # ---- Office ----
    "libreoffice": AppProfile(
        name="LibreOffice",
        launch_cmd="libreoffice",
        app_type="gui",
        package="libreoffice-fresh",
        description="LibreOffice office suite",
        categories=["office", "productivity"],
        shortcuts={
            "Ctrl+N": "new document",
            "Ctrl+O": "open",
            "Ctrl+S": "save",
            "Ctrl+P": "print",
            "Ctrl+Z": "undo",
            "Ctrl+Y": "redo",
        },
        operations={
            "writer": "libreoffice --writer {path}",
            "calc": "libreoffice --calc {path}",
            "impress": "libreoffice --impress {path}",
            "convert_pdf": "libreoffice --headless --convert-to pdf {path}",
            "convert_docx": "libreoffice --headless --convert-to docx {path}",
            "convert_csv": "libreoffice --headless --convert-to csv {path}",
        },
        kill_cmd="pkill soffice",
        config_path="~/.config/libreoffice/",
        desktop_file="libreoffice-startcenter.desktop",
    ),

    # ---- System Tools ----
    "htop_app": AppProfile(
        name="htop",
        launch_cmd="htop",
        app_type="tui",
        package="htop",
        description="Interactive process viewer",
        categories=["monitoring", "system"],
        shortcuts={
            "F1": "help",
            "F2": "setup",
            "F3": "search",
            "F4": "filter",
            "F5": "tree view",
            "F6": "sort by column",
            "F9": "kill process",
            "F10": "quit",
            "u": "filter by user",
            "t": "toggle tree",
        },
        operations={
            "open": "htop",
            "filter_user": "htop -u {user}",
            "sort_memory": "htop --sort-key=PERCENT_MEM",
        },
    ),

    "btop": AppProfile(
        name="btop++",
        launch_cmd="btop",
        app_type="tui",
        package="btop",
        description="Resource monitor (CPU, memory, disk, network, processes)",
        categories=["monitoring", "system"],
        operations={
            "open": "btop",
        },
        config_path="~/.config/btop/",
    ),

    "neofetch": AppProfile(
        name="Neofetch",
        launch_cmd="neofetch",
        app_type="cli",
        package="neofetch",
        description="System info display with ASCII art",
        categories=["system", "utility"],
        operations={
            "run": "neofetch",
            "custom": "neofetch --ascii_distro {distro}",
        },
        config_path="~/.config/neofetch/config.conf",
    ),

    # ---- Network Tools ----
    "wireshark": AppProfile(
        name="Wireshark",
        launch_cmd="wireshark",
        app_type="gui",
        package="wireshark-qt",
        description="Network protocol analyzer",
        categories=["network", "security"],
        shortcuts={
            "Ctrl+E": "start/stop capture",
            "Ctrl+K": "capture options",
            "Ctrl+F": "find packet",
        },
        operations={
            "open": "wireshark",
            "open_pcap": "wireshark {path}",
            "capture_cli": "tshark -i {interface} -w {output}",
            "read_cli": "tshark -r {path}",
        },
        kill_cmd="pkill wireshark",
        desktop_file="org.wireshark.Wireshark.desktop",
    ),

    "nmap": AppProfile(
        name="Nmap",
        launch_cmd="nmap",
        app_type="cli",
        package="nmap",
        description="Network scanner and security auditor",
        categories=["network", "security"],
        operations={
            "quick_scan": "nmap -sn {target}",
            "port_scan": "nmap -sV {target}",
            "full_scan": "sudo nmap -sS -sV -O -A {target}",
            "script_scan": "nmap --script={script} {target}",
            "udp_scan": "sudo nmap -sU {target}",
        },
    ),

    # ---- Multimedia ----
    "obs": AppProfile(
        name="OBS Studio",
        launch_cmd="obs",
        app_type="gui",
        package="obs-studio",
        description="Open Broadcaster Software for streaming/recording",
        categories=["media", "streaming"],
        shortcuts={
            "Ctrl+Shift+1-9": "switch scene",
        },
        operations={
            "launch": "obs",
            "start_recording": "obs --startrecording",
            "start_streaming": "obs --startstreaming",
            "minimize": "obs --minimize-to-tray",
        },
        kill_cmd="pkill obs",
        config_path="~/.config/obs-studio/",
        desktop_file="com.obsproject.Studio.desktop",
    ),

    "ffmpeg": AppProfile(
        name="FFmpeg",
        launch_cmd="ffmpeg",
        app_type="cli",
        package="ffmpeg",
        description="Multimedia framework for video/audio processing",
        categories=["media", "video", "audio"],
        operations={
            "convert": "ffmpeg -i {input} {output}",
            "extract_audio": "ffmpeg -i {input} -vn -acodec copy {output}",
            "resize_video": "ffmpeg -i {input} -vf scale={width}:{height} {output}",
            "trim": "ffmpeg -i {input} -ss {start} -to {end} -c copy {output}",
            "concat": "ffmpeg -f concat -safe 0 -i {list_file} -c copy {output}",
            "gif": "ffmpeg -i {input} -vf 'fps=10,scale=320:-1' {output}.gif",
            "screen_record": "ffmpeg -f x11grab -i :0 -framerate 30 {output}",
            "webcam": "ffmpeg -f v4l2 -i /dev/video0 {output}",
        },
    ),

    "audacity": AppProfile(
        name="Audacity",
        launch_cmd="audacity",
        app_type="gui",
        package="audacity",
        description="Audio editor and recorder",
        categories=["media", "audio"],
        shortcuts={
            "Space": "play/pause",
            "R": "record",
            "Ctrl+Z": "undo",
            "Ctrl+D": "duplicate selection",
            "Ctrl+I": "split",
        },
        operations={
            "open": "audacity {path}",
            "record": "audacity",
        },
        kill_cmd="pkill audacity",
        desktop_file="audacity.desktop",
    ),

    # ---- Development Tools ----
    "docker": AppProfile(
        name="Docker",
        launch_cmd="docker",
        app_type="cli",
        package="docker",
        description="Container platform",
        categories=["development", "devops"],
        operations={
            "ps": "docker ps",
            "ps_all": "docker ps -a",
            "images": "docker images",
            "run": "docker run {options} {image}",
            "run_interactive": "docker run -it {image} /bin/bash",
            "stop": "docker stop {container}",
            "rm": "docker rm {container}",
            "rmi": "docker rmi {image}",
            "logs": "docker logs -f {container}",
            "exec": "docker exec -it {container} {command}",
            "build": "docker build -t {tag} {path}",
            "compose_up": "docker compose up -d",
            "compose_down": "docker compose down",
            "system_prune": "docker system prune -af",
        },
    ),

    "python": AppProfile(
        name="Python",
        launch_cmd="python3",
        app_type="cli",
        package="python",
        description="Python interpreter",
        categories=["development", "scripting"],
        operations={
            "repl": "python3",
            "run_script": "python3 {path}",
            "pip_install": "pip install {package}",
            "pip_list": "pip list",
            "venv_create": "python3 -m venv {path}",
            "venv_activate": "source {path}/bin/activate",
            "http_server": "python3 -m http.server {port}",
        },
    ),

    "gcc": AppProfile(
        name="GCC",
        launch_cmd="gcc",
        app_type="cli",
        package="gcc",
        description="GNU C compiler",
        categories=["development", "compiler"],
        operations={
            "compile": "gcc -o {output} {input}",
            "compile_debug": "gcc -g -O0 -o {output} {input}",
            "compile_optimized": "gcc -O2 -o {output} {input}",
            "compile_shared": "gcc -shared -fPIC -o {output} {input}",
            "preprocess": "gcc -E {input}",
            "assembly": "gcc -S {input}",
        },
    ),

    "make": AppProfile(
        name="GNU Make",
        launch_cmd="make",
        app_type="cli",
        package="make",
        description="Build automation tool",
        categories=["development", "build"],
        operations={
            "build": "make",
            "build_target": "make {target}",
            "clean": "make clean",
            "parallel": "make -j$(nproc)",
            "verbose": "make V=1",
        },
    ),

    "gdb": AppProfile(
        name="GDB",
        launch_cmd="gdb",
        app_type="tui",
        package="gdb",
        description="GNU Debugger",
        categories=["development", "debugging"],
        operations={
            "debug": "gdb {binary}",
            "debug_core": "gdb {binary} {core}",
            "attach": "gdb -p {pid}",
            "run_args": "gdb --args {binary} {args}",
        },
    ),

    # ---- Downloading ----
    "yt_dlp": AppProfile(
        name="yt-dlp",
        launch_cmd="yt-dlp",
        app_type="cli",
        package="yt-dlp",
        description="Video downloader (YouTube, etc.)",
        categories=["internet", "media"],
        operations={
            "download": "yt-dlp {url}",
            "audio_only": "yt-dlp -x --audio-format mp3 {url}",
            "best_quality": "yt-dlp -f 'bestvideo+bestaudio' {url}",
            "list_formats": "yt-dlp -F {url}",
            "subtitles": "yt-dlp --write-subs --sub-lang en {url}",
            "playlist": "yt-dlp -o '%(playlist_index)s-%(title)s.%(ext)s' {url}",
        },
    ),

    "aria2": AppProfile(
        name="aria2",
        launch_cmd="aria2c",
        app_type="cli",
        package="aria2",
        description="Multi-protocol download utility",
        categories=["internet", "download"],
        operations={
            "download": "aria2c {url}",
            "multi_conn": "aria2c -x{connections} {url}",
            "torrent": "aria2c {torrent_file}",
            "metalink": "aria2c {metalink_file}",
        },
    ),

    # ---- Backup ----
    "rsync": AppProfile(
        name="rsync",
        launch_cmd="rsync",
        app_type="cli",
        package="rsync",
        description="Fast incremental file transfer",
        categories=["backup", "file_management"],
        operations={
            "sync": "rsync -avh {src} {dst}",
            "sync_delete": "rsync -avh --delete {src} {dst}",
            "dry_run": "rsync -avhn {src} {dst}",
            "remote_push": "rsync -avhz {src} {user}@{host}:{dst}",
            "remote_pull": "rsync -avhz {user}@{host}:{src} {dst}",
            "exclude": "rsync -avh --exclude='{pattern}' {src} {dst}",
        },
    ),

    # ---- PDF ----
    "evince": AppProfile(
        name="Evince",
        launch_cmd="evince",
        app_type="gui",
        package="evince",
        description="GNOME document viewer (PDF, DjVu, etc.)",
        categories=["office", "viewer"],
        operations={
            "open": "evince {path}",
        },
        desktop_file="org.gnome.Evince.desktop",
    ),

    # ---- Screenshot ----
    "scrot": AppProfile(
        name="Scrot",
        launch_cmd="scrot",
        app_type="cli",
        package="scrot",
        description="Screenshot capture tool",
        categories=["utility", "screenshot"],
        operations={
            "fullscreen": "scrot {output}",
            "selection": "scrot -s {output}",
            "window": "scrot -u {output}",
            "delay": "scrot -d {seconds} {output}",
        },
    ),

    "flameshot": AppProfile(
        name="Flameshot",
        launch_cmd="flameshot gui",
        app_type="gui",
        package="flameshot",
        description="Powerful screenshot tool with annotation",
        categories=["utility", "screenshot"],
        operations={
            "gui": "flameshot gui",
            "full": "flameshot full -p {output_dir}",
            "screen": "flameshot screen -p {output_dir}",
            "config": "flameshot config",
        },
        desktop_file="org.flameshot.Flameshot.desktop",
    ),
}


# ---------------------------------------------------------------------------
# Action dataclass used by the context engine
# ---------------------------------------------------------------------------

@dataclass
class Action:
    """A single executable action returned by the context engine."""
    type: str                   # "run", "launch", "type", "press", "wait", "click"
    value: str                  # Command string, app name, keypress, URL, etc.
    description: str = ""
    security: str = "safe"
    trust: int = 100
    confirm: bool = False       # Requires user confirmation before execution


# ---------------------------------------------------------------------------
# Context Engine - Natural language -> Action sequences
# ---------------------------------------------------------------------------

# Keyword -> (category, command_key) quick lookup for common verbs
_VERB_MAP: dict[str, list[tuple[str, str]]] = {
    # file ops
    "list": [("file_management", "list_files")],
    "ls": [("file_management", "list_files")],
    "copy": [("file_management", "copy")],
    "cp": [("file_management", "copy")],
    "move": [("file_management", "move")],
    "mv": [("file_management", "move")],
    "rename": [("file_management", "move")],
    "delete": [("file_management", "delete")],
    "remove": [("file_management", "delete")],
    "rm": [("file_management", "delete")],
    "find": [("file_management", "find")],
    "search": [("text_processing", "grep"), ("package_management", "search")],
    "mkdir": [("file_management", "create_dir")],
    "touch": [("file_management", "touch")],
    "cat": [("file_management", "read_file")],
    "read": [("file_management", "read_file")],

    # packages
    "install": [("package_management", "install")],
    "uninstall": [("package_management", "remove")],
    "update": [("package_management", "update")],
    "upgrade": [("package_management", "update")],

    # services
    "start": [("service_management", "start")],
    "stop": [("service_management", "stop")],
    "restart": [("service_management", "restart")],
    "enable": [("service_management", "enable")],
    "disable": [("service_management", "disable")],
    "status": [("service_management", "status")],

    # system
    "reboot": [("system", "reboot")],
    "shutdown": [("system", "shutdown")],
    "suspend": [("system", "suspend")],

    # network
    "ping": [("network", "ping")],
    "download": [("network", "wget")],
    "curl": [("network", "curl")],

    # git
    "commit": [("git", "commit")],
    "push": [("git", "push")],
    "pull": [("git", "pull")],
    "clone": [("git", "clone")],
    "diff": [("git", "diff")],

    # process
    "kill": [("monitoring", "kill_pid")],
    "ps": [("monitoring", "ps_all")],

    # compression
    "compress": [("compression", "tar_create")],
    "extract": [("compression", "tar_extract")],
    "unzip": [("compression", "zip_extract")],
    "zip": [("compression", "zip_create")],

    # permissions
    "chmod": [("permissions", "chmod")],
    "chown": [("permissions", "chown")],

    # PE
    "run": [("pe_compat", "run_exe")],
    "execute": [("pe_compat", "run_exe")],
}

# Patterns for extracting entities from natural language
_PATH_RE = re.compile(r'(?:(?:~|/)[^\s"\']+|[A-Z]:\\[^\s"\']+)')
_URL_RE = re.compile(r'https?://[^\s"\']+')
_PACKAGE_NAMES_RE = re.compile(r'\b(?:install|remove|uninstall)\s+(\S+)')
_SERVICE_NAMES_RE = re.compile(r'\b(?:start|stop|restart|enable|disable|status)\s+(\S+)')
_NUMBER_RE = re.compile(r'\b(\d+)\b')


class ContextEngine:
    """Parse natural language requests into executable Action sequences."""

    def __init__(self):
        # Build a flat index of all command descriptions for fuzzy matching
        self._desc_index: list[tuple[str, str, dict]] = []
        for cat, cmds in COMMANDS.items():
            for key, entry in cmds.items():
                self._desc_index.append((cat, key, entry))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_request(self, text: str) -> list[Action]:
        """Parse a natural-language request into a sequence of Actions.

        Examples:
            "open firefox and go to github.com"
            -> [Action(launch, firefox), Action(wait, 3),
                Action(type, "github.com"), Action(press, "Return")]

            "install discord"
            -> [Action(run, "sudo pacman -S --noconfirm discord")]

            "show me the largest files in /home"
            -> [Action(run, "du -sh /home/* | sort -rh | head -20")]
        """
        text_lower = text.lower().strip()
        actions: list[Action] = []

        # Try compound request splitting on "and" / "then" / ","
        parts = re.split(r'\b(?:and then|then|and|,)\b', text_lower)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            sub_actions = self._parse_single(part, text)
            actions.extend(sub_actions)

        return actions if actions else [self._fallback_action(text)]

    def lookup_command(self, category: str, name: str) -> Optional[dict]:
        """Look up a specific command by category and name."""
        cat = COMMANDS.get(category, {})
        return cat.get(name)

    def search_commands(self, query: str) -> list[dict]:
        """Search all commands by keyword in name or description."""
        query_lower = query.lower()
        results = []
        for cat, key, entry in self._desc_index:
            score = 0
            if query_lower in key:
                score += 10
            if query_lower in entry.get("desc", "").lower():
                score += 5
            if query_lower in cat:
                score += 3
            if score > 0:
                results.append({
                    "category": cat,
                    "name": key,
                    "score": score,
                    **entry,
                })
        results.sort(key=lambda r: r["score"], reverse=True)
        return results[:20]

    def get_app_profile(self, name: str) -> Optional[AppProfile]:
        """Get application profile by name (case-insensitive, partial match)."""
        name_lower = name.lower()
        # Exact key match
        if name_lower in APP_PROFILES:
            return APP_PROFILES[name_lower]
        # Match on display name
        for key, profile in APP_PROFILES.items():
            if name_lower == profile.name.lower():
                return profile
        # Partial match
        for key, profile in APP_PROFILES.items():
            if name_lower in key or name_lower in profile.name.lower():
                return profile
        return None

    def list_categories(self) -> list[dict]:
        """List all command categories with command counts."""
        return [
            {"category": cat, "count": len(cmds)}
            for cat, cmds in COMMANDS.items()
        ]

    def list_apps(self, category: Optional[str] = None) -> list[dict]:
        """List application profiles, optionally filtered by category."""
        results = []
        for key, profile in APP_PROFILES.items():
            if category and category.lower() not in profile.categories:
                continue
            results.append({
                "key": key,
                "name": profile.name,
                "type": profile.app_type,
                "package": profile.package,
                "description": profile.description,
                "categories": profile.categories,
            })
        return results

    def get_security_info(self, category: str, name: str) -> dict:
        """Get security classification for a command."""
        entry = self.lookup_command(category, name)
        if not entry:
            return {"error": "Command not found"}
        sec = entry.get("security", "safe")
        return {
            "command": entry.get("cmd", ""),
            "security": sec,
            "trust_required": entry.get("trust", TRUST_THRESHOLDS.get(
                SecurityLevel(sec), 100)),
            "dangerous": entry.get("dangerous", False),
            "confirm": entry.get("confirm", False),
        }

    # ------------------------------------------------------------------
    # Internal parsing
    # ------------------------------------------------------------------

    def _parse_single(self, part: str, original: str) -> list[Action]:
        """Parse a single clause of a request."""
        actions: list[Action] = []

        # --- App launch detection ---
        launch_match = re.match(
            r'(?:open|launch|start|run)\s+(.+?)(?:\s+(?:and|then)|\s*$)', part
        )
        if launch_match:
            app_name = launch_match.group(1).strip()
            # Check for URL after app name  ("open firefox and go to github.com")
            profile = self.get_app_profile(app_name.split()[0])
            if profile and profile.app_type == "gui":
                # Check if there's a URL in the original text
                url_match = _URL_RE.search(original)
                url_words = re.search(
                    r'(?:go to|navigate to|visit|browse)\s+(\S+)', original.lower()
                )
                if url_match:
                    url = url_match.group(0)
                    open_op = profile.operations.get("open_url",
                                                      profile.launch_cmd)
                    actions.append(Action(
                        type="launch",
                        value=open_op.replace("{url}", url),
                        description=f"Open {profile.name} with {url}",
                        security="safe",
                        trust=100,
                    ))
                elif url_words:
                    target = url_words.group(1)
                    if "." not in target:
                        target = target + ".com"
                    if not target.startswith("http"):
                        target = "https://" + target
                    open_op = profile.operations.get("open_url",
                                                      profile.launch_cmd)
                    actions.append(Action(
                        type="launch",
                        value=open_op.replace("{url}", target),
                        description=f"Open {profile.name} to {target}",
                        security="safe",
                        trust=100,
                    ))
                    # Type URL and press enter for browsers
                    if any(c in profile.categories for c in ["browser"]):
                        actions.append(Action(
                            type="wait", value="2",
                            description="Wait for browser to open",
                        ))
                else:
                    actions.append(Action(
                        type="launch",
                        value=profile.launch_cmd,
                        description=f"Launch {profile.name}",
                        security="safe",
                        trust=100,
                    ))
                return actions
            # Check if it is an .exe
            if app_name.endswith(".exe") or ".exe " in app_name:
                exe_path = app_name
                path_match = _PATH_RE.search(original)
                if path_match:
                    exe_path = path_match.group(0)
                actions.append(Action(
                    type="run",
                    value=f"pe-run-game {shlex.quote(exe_path)}",
                    description=f"Run Windows executable {exe_path}",
                    security="moderate",
                    trust=300,
                ))
                return actions

        # --- Package management ---
        pkg_match = re.match(
            r'(?:install|uninstall|remove)\s+(.+)', part
        )
        if pkg_match:
            pkg = pkg_match.group(1).strip()
            # Strip articles
            pkg = re.sub(r'^(?:the|a|an)\s+', '', pkg)
            verb = part.split()[0]
            if verb in ("uninstall", "remove"):
                entry = COMMANDS["package_management"]["remove"]
                cmd = entry["cmd"].replace("{package}", shlex.quote(pkg))
            else:
                entry = COMMANDS["package_management"]["install"]
                cmd = entry["cmd"].replace("{package}", shlex.quote(pkg))
            actions.append(Action(
                type="run",
                value=cmd,
                description=entry["desc"] + f": {pkg}",
                security=entry["security"],
                trust=entry["trust"],
            ))
            return actions

        # --- Service management ---
        svc_match = re.match(
            r'(?:start|stop|restart|enable|disable)\s+(?:the\s+)?(\S+?)(?:\s+service)?$',
            part,
        )
        if svc_match:
            service = svc_match.group(1)
            verb = part.split()[0]
            entry = COMMANDS["service_management"].get(verb)
            if entry:
                cmd = entry["cmd"].replace("{service}", shlex.quote(service))
                actions.append(Action(
                    type="run",
                    value=cmd,
                    description=f"{verb.title()} service {service}",
                    security=entry["security"],
                    trust=entry["trust"],
                ))
                return actions

        # --- Largest files query ---
        if re.search(r'(?:largest|biggest|heaviest)\s+files?', part):
            path = "/"
            path_match = _PATH_RE.search(original)
            if path_match:
                path = path_match.group(0)
            actions.append(Action(
                type="run",
                value=f"du -sh {shlex.quote(path)}/* | sort -rh | head -20",
                description=f"Show largest items in {path}",
                security="safe",
                trust=100,
            ))
            return actions

        # --- Disk usage query ---
        if re.search(r'(?:disk\s+(?:space|usage)|free\s+space|storage)', part):
            actions.append(Action(
                type="run", value="df -h",
                description="Show disk space usage",
                security="safe", trust=100,
            ))
            return actions

        # --- System info ---
        if re.search(r'(?:system\s+info|about\s+(?:this|my)\s+(?:system|computer|machine))', part):
            actions.append(Action(
                type="run", value="neofetch",
                description="Show system information",
                security="safe", trust=100,
            ))
            return actions

        # --- Network info ---
        if re.search(r'(?:my\s+ip|ip\s+address|network\s+(?:info|status))', part):
            actions.append(Action(
                type="run", value="ip addr show",
                description="Show network interfaces",
                security="safe", trust=100,
            ))
            return actions

        # --- Process listing ---
        if re.search(r'(?:running\s+processes?|what.?s\s+running|list\s+processes?)', part):
            actions.append(Action(
                type="run", value="ps aux --sort=-%cpu | head -20",
                description="List top processes by CPU",
                security="safe", trust=100,
            ))
            return actions

        # --- Kill process ---
        kill_match = re.match(r'kill\s+(.+)', part)
        if kill_match:
            target = kill_match.group(1).strip()
            if target.isdigit():
                actions.append(Action(
                    type="run", value=f"kill {target}",
                    description=f"Send SIGTERM to PID {target}",
                    security="moderate", trust=300,
                ))
            else:
                actions.append(Action(
                    type="run",
                    value=f"pkill -f {shlex.quote(target)}",
                    description=f"Kill processes matching '{target}'",
                    security="dangerous", trust=600,
                    confirm=True,
                ))
            return actions

        # --- Grep / search in files ---
        grep_match = re.match(
            r'(?:search|grep|look)\s+(?:for\s+)?["\']?(.+?)["\']?\s+in\s+(\S+)',
            part,
        )
        if grep_match:
            pattern = grep_match.group(1)
            path = grep_match.group(2)
            actions.append(Action(
                type="run",
                value=f"grep -rn {shlex.quote(pattern)} {shlex.quote(path)}",
                description=f"Search for '{pattern}' in {path}",
                security="safe", trust=100,
            ))
            return actions

        # --- Verb-based lookup ---
        words = part.split()
        if words:
            verb = words[0]
            mappings = _VERB_MAP.get(verb, [])
            if mappings:
                cat, key = mappings[0]
                entry = COMMANDS[cat][key]
                cmd = entry["cmd"]
                # Try to fill in path/package/service placeholders
                path_match = _PATH_RE.search(original)
                if path_match and "{path}" in cmd:
                    cmd = cmd.replace("{path}", path_match.group(0))
                elif len(words) > 1:
                    # Use the rest as the argument
                    arg = " ".join(words[1:])
                    # Pick the first placeholder
                    placeholders = re.findall(r'\{(\w+)\}', cmd)
                    if placeholders:
                        cmd = cmd.replace(f"{{{placeholders[0]}}}", arg)

                # Remove any remaining unfilled placeholders with sane defaults
                cmd = re.sub(r'\{path\}', '.', cmd)
                cmd = re.sub(r'\{lines\}', '50', cmd)
                cmd = re.sub(r'\{count\}', '10', cmd)
                cmd = re.sub(r'\{depth\}', '3', cmd)
                cmd = re.sub(r'\{pattern\}', '*', cmd)
                cmd = re.sub(r'\{[^}]+\}', '', cmd)
                cmd = cmd.strip()

                actions.append(Action(
                    type="run",
                    value=cmd,
                    description=entry["desc"],
                    security=entry.get("security", "safe"),
                    trust=entry.get("trust", 100),
                    confirm=entry.get("confirm", False),
                ))
                return actions

        return actions

    def _fallback_action(self, text: str) -> Action:
        """When no pattern matches, try to interpret as a raw command or
        return a search suggestion."""
        # If it looks like a command (starts with common binaries or paths)
        if re.match(r'^(?:sudo\s+)?(?:/|[a-z][\w.-]*\s)', text.strip()):
            return Action(
                type="run",
                value=text.strip(),
                description="Execute as raw command",
                security="moderate",
                trust=300,
            )
        # Otherwise suggest a search
        return Action(
            type="search",
            value=text.strip(),
            description=f"Could not parse request; try searching: {text}",
            security="safe",
            trust=100,
        )


# ---------------------------------------------------------------------------
# Module-level singleton for import convenience
# ---------------------------------------------------------------------------

_engine: Optional[ContextEngine] = None


def get_engine() -> ContextEngine:
    """Get or create the singleton ContextEngine instance."""
    global _engine
    if _engine is None:
        _engine = ContextEngine()
    return _engine


def parse_request(text: str) -> list[Action]:
    """Convenience wrapper: parse natural language into Actions."""
    return get_engine().parse_request(text)


def search_commands(query: str) -> list[dict]:
    """Convenience wrapper: search all commands by keyword."""
    return get_engine().search_commands(query)


def get_app_profile(name: str) -> Optional[AppProfile]:
    """Convenience wrapper: get application profile by name."""
    return get_engine().get_app_profile(name)


# ---------------------------------------------------------------------------
# Stats helper
# ---------------------------------------------------------------------------

def get_stats() -> dict:
    """Return summary statistics about the dictionary contents."""
    total_commands = sum(len(cmds) for cmds in COMMANDS.values())
    safe = sum(
        1 for cmds in COMMANDS.values()
        for e in cmds.values()
        if e.get("security") == "safe"
    )
    moderate = sum(
        1 for cmds in COMMANDS.values()
        for e in cmds.values()
        if e.get("security") == "moderate"
    )
    dangerous = sum(
        1 for cmds in COMMANDS.values()
        for e in cmds.values()
        if e.get("security") == "dangerous"
    )
    return {
        "total_commands": total_commands,
        "categories": len(COMMANDS),
        "safe_commands": safe,
        "moderate_commands": moderate,
        "dangerous_commands": dangerous,
        "app_profiles": len(APP_PROFILES),
        "trust_thresholds": {k.value: v for k, v in TRUST_THRESHOLDS.items()},
    }
