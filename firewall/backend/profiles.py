"""
Network profile management - Windows-style public/private/domain profiles.

Each profile carries a different set of default rules.  The ``public``
profile is the most restrictive (block most inbound), ``private`` is
permissive (allow local network), and ``domain`` is for managed
environments.  Profile auto-detection examines the current network
to choose the right one.
"""

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from .nft_manager import FirewallRule, Direction, Action, Protocol

logger = logging.getLogger("firewall.profiles")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROFILES_CONFIG_DIR = "/etc/pe-compat/firewall"
PROFILES_CONFIG_FILE = os.path.join(PROFILES_CONFIG_DIR, "profiles.json")
KNOWN_NETWORKS_FILE = os.path.join(PROFILES_CONFIG_DIR, "known_networks.json")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ProfileType(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    DOMAIN = "domain"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class NetworkProfile:
    """Configuration for a single firewall profile."""

    name: str                               # public | private | domain
    display_name: str = ""
    description: str = ""
    inbound_default: str = Action.BLOCK.value
    outbound_default: str = Action.ALLOW.value
    allow_icmp: bool = True
    allow_dhcp: bool = True
    allow_dns: bool = True
    allow_local_discovery: bool = False     # mDNS, SSDP, etc.
    allow_file_sharing: bool = False        # SMB ports
    log_blocked: bool = True
    notifications: bool = True              # Prompt on new app connections
    default_rules: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkProfile":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class KnownNetwork:
    """A network that maps to a specific profile."""

    ssid: Optional[str] = None              # WiFi SSID
    gateway: Optional[str] = None           # Default gateway IP
    dns_suffix: Optional[str] = None        # e.g. "corp.example.com"
    interface: Optional[str] = None         # e.g. "eth0"
    profile: str = ProfileType.PUBLIC.value

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "KnownNetwork":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})


# ---------------------------------------------------------------------------
# Default profiles
# ---------------------------------------------------------------------------

def _default_public_profile() -> NetworkProfile:
    """Public profile - most restrictive."""
    return NetworkProfile(
        name=ProfileType.PUBLIC.value,
        display_name="Public Network",
        description=(
            "Settings for networks in public places such as airports "
            "and coffee shops. Your PC is hidden from other devices "
            "on the network and cannot be used for file and printer sharing."
        ),
        inbound_default=Action.BLOCK.value,
        outbound_default=Action.ALLOW.value,
        allow_icmp=False,
        allow_dhcp=True,
        allow_dns=True,
        allow_local_discovery=False,
        allow_file_sharing=False,
        log_blocked=True,
        notifications=True,
        default_rules=[
            # Block all inbound by default, with exceptions for DHCP/DNS
            FirewallRule(
                id="default-pub-dhcp-in",
                name="Allow DHCP Client (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=68,
                profile=ProfileType.PUBLIC.value,
                priority=10,
            ).to_dict(),
            FirewallRule(
                id="default-pub-dns-out",
                name="Allow DNS (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=53,
                profile=ProfileType.PUBLIC.value,
                priority=10,
            ).to_dict(),
            FirewallRule(
                id="default-pub-dns-tcp-out",
                name="Allow DNS over TCP (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=53,
                profile=ProfileType.PUBLIC.value,
                priority=10,
            ).to_dict(),
            FirewallRule(
                id="default-pub-http-out",
                name="Allow HTTP (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=80,
                profile=ProfileType.PUBLIC.value,
                priority=20,
            ).to_dict(),
            FirewallRule(
                id="default-pub-https-out",
                name="Allow HTTPS (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=443,
                profile=ProfileType.PUBLIC.value,
                priority=20,
            ).to_dict(),
        ],
    )


def _default_private_profile() -> NetworkProfile:
    """Private profile - permissive for home/work networks."""
    return NetworkProfile(
        name=ProfileType.PRIVATE.value,
        display_name="Private Network",
        description=(
            "Settings for home or work networks where you know and "
            "trust the people and devices on the network. Network "
            "discovery and file sharing are available."
        ),
        inbound_default=Action.BLOCK.value,
        outbound_default=Action.ALLOW.value,
        allow_icmp=True,
        allow_dhcp=True,
        allow_dns=True,
        allow_local_discovery=True,
        allow_file_sharing=True,
        log_blocked=True,
        notifications=True,
        default_rules=[
            FirewallRule(
                id="default-priv-dhcp-in",
                name="Allow DHCP Client (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=68,
                profile=ProfileType.PRIVATE.value,
                priority=10,
            ).to_dict(),
            FirewallRule(
                id="default-priv-dns-out",
                name="Allow DNS (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=53,
                profile=ProfileType.PRIVATE.value,
                priority=10,
            ).to_dict(),
            FirewallRule(
                id="default-priv-icmp-in",
                name="Allow ICMP (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.ICMP.value,
                profile=ProfileType.PRIVATE.value,
                priority=15,
            ).to_dict(),
            FirewallRule(
                id="default-priv-icmp-out",
                name="Allow ICMP (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.ICMP.value,
                profile=ProfileType.PRIVATE.value,
                priority=15,
            ).to_dict(),
            # mDNS for local discovery
            FirewallRule(
                id="default-priv-mdns-in",
                name="Allow mDNS (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=5353,
                profile=ProfileType.PRIVATE.value,
                priority=20,
            ).to_dict(),
            # SSDP for UPnP
            FirewallRule(
                id="default-priv-ssdp-in",
                name="Allow SSDP (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=1900,
                profile=ProfileType.PRIVATE.value,
                priority=20,
            ).to_dict(),
            # SMB file sharing
            FirewallRule(
                id="default-priv-smb-in",
                name="Allow SMB (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=445,
                profile=ProfileType.PRIVATE.value,
                priority=25,
            ).to_dict(),
            # HTTP/HTTPS outbound
            FirewallRule(
                id="default-priv-http-out",
                name="Allow HTTP (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=80,
                profile=ProfileType.PRIVATE.value,
                priority=20,
            ).to_dict(),
            FirewallRule(
                id="default-priv-https-out",
                name="Allow HTTPS (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=443,
                profile=ProfileType.PRIVATE.value,
                priority=20,
            ).to_dict(),
        ],
    )


def _default_domain_profile() -> NetworkProfile:
    """Domain profile - managed network environment."""
    return NetworkProfile(
        name=ProfileType.DOMAIN.value,
        display_name="Domain Network",
        description=(
            "Settings for networks with a domain controller. Rules "
            "may be managed by a network administrator."
        ),
        inbound_default=Action.BLOCK.value,
        outbound_default=Action.ALLOW.value,
        allow_icmp=True,
        allow_dhcp=True,
        allow_dns=True,
        allow_local_discovery=True,
        allow_file_sharing=True,
        log_blocked=True,
        notifications=False,
        default_rules=[
            FirewallRule(
                id="default-dom-dhcp-in",
                name="Allow DHCP Client (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=68,
                profile=ProfileType.DOMAIN.value,
                priority=10,
            ).to_dict(),
            FirewallRule(
                id="default-dom-dns-out",
                name="Allow DNS (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=53,
                profile=ProfileType.DOMAIN.value,
                priority=10,
            ).to_dict(),
            FirewallRule(
                id="default-dom-icmp-in",
                name="Allow ICMP (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.ICMP.value,
                profile=ProfileType.DOMAIN.value,
                priority=15,
            ).to_dict(),
            FirewallRule(
                id="default-dom-icmp-out",
                name="Allow ICMP (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.ICMP.value,
                profile=ProfileType.DOMAIN.value,
                priority=15,
            ).to_dict(),
            # Kerberos
            FirewallRule(
                id="default-dom-kerberos-out",
                name="Allow Kerberos (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=88,
                profile=ProfileType.DOMAIN.value,
                priority=15,
            ).to_dict(),
            # LDAP
            FirewallRule(
                id="default-dom-ldap-out",
                name="Allow LDAP (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=389,
                profile=ProfileType.DOMAIN.value,
                priority=15,
            ).to_dict(),
            # SMB
            FirewallRule(
                id="default-dom-smb-in",
                name="Allow SMB (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=445,
                profile=ProfileType.DOMAIN.value,
                priority=25,
            ).to_dict(),
            # mDNS
            FirewallRule(
                id="default-dom-mdns-in",
                name="Allow mDNS (Inbound)",
                direction=Direction.INBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.UDP.value,
                port=5353,
                profile=ProfileType.DOMAIN.value,
                priority=20,
            ).to_dict(),
            # HTTP/HTTPS
            FirewallRule(
                id="default-dom-http-out",
                name="Allow HTTP (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=80,
                profile=ProfileType.DOMAIN.value,
                priority=20,
            ).to_dict(),
            FirewallRule(
                id="default-dom-https-out",
                name="Allow HTTPS (Outbound)",
                direction=Direction.OUTBOUND.value,
                action=Action.ALLOW.value,
                protocol=Protocol.TCP.value,
                port=443,
                profile=ProfileType.DOMAIN.value,
                priority=20,
            ).to_dict(),
        ],
    )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class ProfileManager:
    """Manages Windows-style network profiles (public/private/domain).

    Auto-detects the appropriate profile based on the current network
    environment.  Each profile carries its own set of default rules
    that define baseline behaviour.
    """

    def __init__(self, config_dir: str = PROFILES_CONFIG_DIR) -> None:
        self._config_dir = config_dir
        self._profiles_file = os.path.join(config_dir, "profiles.json")
        self._known_networks_file = os.path.join(config_dir, "known_networks.json")

        # Active profile (defaults to public for safety)
        self._active_profile: ProfileType = ProfileType.PUBLIC
        self._override: Optional[ProfileType] = None

        # Profile definitions
        self._profiles: dict[str, NetworkProfile] = {}
        self._known_networks: list[KnownNetwork] = []

        self._load_defaults()
        self._load_config()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_active_profile(self) -> NetworkProfile:
        """Return the currently active network profile.

        If the profile has been manually overridden, the override is
        returned.  Otherwise, auto-detection is used.
        """
        if self._override is not None:
            profile_name = self._override.value
        else:
            profile_name = self._detect_profile().value
        return self._profiles[profile_name]

    def get_active_profile_name(self) -> str:
        """Return the name of the active profile."""
        return self.get_active_profile().name

    def set_profile(self, profile: str) -> None:
        """Manually set the active profile, overriding auto-detection.

        Parameters
        ----------
        profile:
            One of ``"public"``, ``"private"``, ``"domain"``, or
            ``"auto"`` to re-enable auto-detection.
        """
        if profile == "auto":
            self._override = None
            logger.info("Profile set to auto-detect")
        else:
            try:
                ptype = ProfileType(profile)
            except ValueError:
                raise ValueError(
                    f"Unknown profile '{profile}'. "
                    f"Expected: public, private, domain, auto"
                )
            self._override = ptype
            logger.info("Profile manually set to %s", ptype.value)

    def get_profile(self, name: str) -> Optional[NetworkProfile]:
        """Return a profile by name."""
        return self._profiles.get(name)

    def get_all_profiles(self) -> list[NetworkProfile]:
        """Return all defined profiles."""
        return list(self._profiles.values())

    def get_profile_rules(self, profile_name: Optional[str] = None) -> list[FirewallRule]:
        """Return the default rules for a profile.

        If *profile_name* is None, uses the active profile.
        """
        if profile_name is None:
            profile = self.get_active_profile()
        else:
            profile = self._profiles.get(profile_name)
            if profile is None:
                return []

        return [FirewallRule.from_dict(rd) for rd in profile.default_rules]

    def get_default_rules(self) -> list[FirewallRule]:
        """Return the default rules for the currently active profile."""
        return self.get_profile_rules()

    def set_active_profile(self, name: str) -> None:
        """Set the active profile by name.  Alias for :meth:`set_profile`."""
        self.set_profile(name)

    # ------------------------------------------------------------------
    # Known networks
    # ------------------------------------------------------------------

    def add_known_network(self, network: KnownNetwork) -> None:
        """Register a network as known and associate it with a profile."""
        self._known_networks.append(network)
        self._save_known_networks()
        logger.info(
            "Added known network (ssid=%s, gateway=%s) -> %s",
            network.ssid, network.gateway, network.profile,
        )

    def remove_known_network(self, index: int) -> bool:
        """Remove a known network by index."""
        if 0 <= index < len(self._known_networks):
            removed = self._known_networks.pop(index)
            self._save_known_networks()
            logger.info("Removed known network: %s", removed.ssid or removed.gateway)
            return True
        return False

    def get_known_networks(self) -> list[KnownNetwork]:
        """Return all known networks."""
        return list(self._known_networks)

    # ------------------------------------------------------------------
    # Profile auto-detection
    # ------------------------------------------------------------------

    def _detect_profile(self) -> ProfileType:
        """Auto-detect the network profile based on current environment.

        Detection order:
        1. Check known networks by SSID or gateway
        2. Check for domain indicators (DNS suffix, LDAP availability)
        3. Default to public
        """
        current_ssid = self._get_current_ssid()
        current_gateway = self._get_default_gateway()
        current_dns_suffix = self._get_dns_suffix()

        # Check known networks
        for net in self._known_networks:
            if net.ssid and current_ssid and net.ssid == current_ssid:
                try:
                    return ProfileType(net.profile)
                except ValueError:
                    continue
            if net.gateway and current_gateway and net.gateway == current_gateway:
                try:
                    return ProfileType(net.profile)
                except ValueError:
                    continue
            if (net.dns_suffix and current_dns_suffix
                    and current_dns_suffix.endswith(net.dns_suffix)):
                try:
                    return ProfileType(net.profile)
                except ValueError:
                    continue

        # Check for domain-like environment
        if self._looks_like_domain(current_dns_suffix):
            return ProfileType.DOMAIN

        # Default to public for maximum safety
        return ProfileType.PUBLIC

    def _looks_like_domain(self, dns_suffix: Optional[str]) -> bool:
        """Heuristic check for a managed/domain network environment."""
        if not dns_suffix:
            return False
        # Typical corporate DNS suffixes
        corp_indicators = [
            ".corp.", ".internal.", ".local.", ".ad.",
            ".domain.", ".company.",
        ]
        lower = dns_suffix.lower()
        for indicator in corp_indicators:
            if indicator in lower:
                return True
        # Check if LDAP port is reachable on the gateway
        gateway = self._get_default_gateway()
        if gateway:
            return self._is_port_open(gateway, 389, timeout=1.0)
        return False

    # ------------------------------------------------------------------
    # Network environment queries
    # ------------------------------------------------------------------

    @staticmethod
    def _get_current_ssid() -> Optional[str]:
        """Get the SSID of the currently connected WiFi network."""
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[0] == "yes":
                        return parts[1]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: try iwgetid
        try:
            result = subprocess.run(
                ["iwgetid", "-r"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    @staticmethod
    def _get_default_gateway() -> Optional[str]:
        """Get the default gateway IP address."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                # "default via 192.168.1.1 dev eth0 ..."
                parts = result.stdout.strip().split()
                if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                    return parts[2]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def _get_dns_suffix() -> Optional[str]:
        """Get the primary DNS search domain."""
        # Try systemd-resolved
        try:
            result = subprocess.run(
                ["resolvectl", "status"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "DNS Domain:" in line or "Search Domains:" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            domain = parts[1].strip().split()[0] if parts[1].strip() else None
                            if domain:
                                return domain
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: parse /etc/resolv.conf
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("search ") or line.startswith("domain "):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
        except (FileNotFoundError, PermissionError):
            pass

        return None

    @staticmethod
    def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
        """Check whether a TCP port is reachable."""
        import socket as sock
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
        except (OSError, ConnectionRefusedError, TimeoutError):
            return False
        finally:
            s.close()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_defaults(self) -> None:
        """Populate profiles with built-in defaults."""
        for factory in (
            _default_public_profile,
            _default_private_profile,
            _default_domain_profile,
        ):
            profile = factory()
            self._profiles[profile.name] = profile

    def _load_config(self) -> None:
        """Load saved profile customisations and known networks."""
        # Load profile overrides
        if os.path.isfile(self._profiles_file):
            try:
                with open(self._profiles_file, "r") as fh:
                    data = json.load(fh)
                for item in data:
                    profile = NetworkProfile.from_dict(item)
                    self._profiles[profile.name] = profile
                logger.info("Loaded %d profiles from %s", len(data), self._profiles_file)
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("Failed to load profiles config: %s", exc)

        # Load known networks
        if os.path.isfile(self._known_networks_file):
            try:
                with open(self._known_networks_file, "r") as fh:
                    data = json.load(fh)
                self._known_networks = [KnownNetwork.from_dict(d) for d in data]
                logger.info(
                    "Loaded %d known networks from %s",
                    len(self._known_networks), self._known_networks_file,
                )
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("Failed to load known networks: %s", exc)

    def save_profiles(self) -> None:
        """Persist profile configurations to disk atomically.

        Writes to a .tmp sibling and os.replace()'s over the target.  A
        direct ``open(path, 'w')`` truncates the file *before* writing;
        a crash (or power loss, OOM kill, systemd SIGKILL during
        shutdown) between truncate and flush leaves an empty or
        half-written JSON that _load_config() silently ignores, losing
        all user-configured profile overrides.
        """
        os.makedirs(self._config_dir, exist_ok=True)
        data = [p.to_dict() for p in self._profiles.values()]
        tmp = self._profiles_file + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, self._profiles_file)
        logger.info("Saved profiles to %s", self._profiles_file)

    def _save_known_networks(self) -> None:
        """Persist known networks to disk atomically (see save_profiles)."""
        os.makedirs(self._config_dir, exist_ok=True)
        data = [n.to_dict() for n in self._known_networks]
        tmp = self._known_networks_file + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, self._known_networks_file)
        logger.info("Saved known networks to %s", self._known_networks_file)
