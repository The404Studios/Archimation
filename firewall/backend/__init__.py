# Firewall backend modules
from .nft_manager import NftManager, FirewallRule, Direction, Action, Protocol
from .rule_store import RuleStore
from .connection_monitor import ConnectionMonitor
from .app_tracker import AppTracker
from .profiles import ProfileManager

# cgroup_manager is re-exported for callers that want the singleton helpers
# (ensure_slice, ensure_app_scoped, systemd_scope_run) without reaching into
# the subpackage by path.  Guarded so a build environment missing the module
# doesn't break the rest of the backend.
try:
    from . import cgroup_manager  # noqa: F401
except ImportError:  # pragma: no cover - defensive for minimal installs
    cgroup_manager = None  # type: ignore
