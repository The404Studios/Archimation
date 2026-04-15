"""
Trust-based API authentication.

Each API endpoint has a minimum trust level and required capabilities.
Callers identify themselves via JWT tokens. The trust system is consulted
on every request to determine whether the caller has sufficient trust.

Endpoints are tiered:
  - GET /health              → no auth required
  - GET /screen/*            → TRUST_AUTH_USER (trust >= 100)
  - POST /keyboard/*         → TRUST_AUTH_USER (trust >= 200)
  - POST /system/command     → TRUST_AUTH_ADMIN (trust >= 600)
  - POST /firewall/*         → TRUST_AUTH_ADMIN (trust >= 600)
  - DELETE /*                → TRUST_AUTH_ADMIN (trust >= 600)
"""

import collections
import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("ai-control.auth")

# JWT-like token secret (generated on first run, persisted)
_SECRET_PATH = "/var/lib/ai-control/auth_secret"
_secret: bytes = b""

# --- Rate limiting for auth failures ---
_RATE_LIMIT_WINDOW = 60      # seconds
_RATE_LIMIT_MAX_FAILURES = 10  # max failures per source within window
_failure_log: dict[str, list[float]] = collections.defaultdict(list)
_failure_lock = threading.Lock()


def _record_auth_failure(source: str) -> None:
    """Record an auth failure from *source* (IP or 'local')."""
    now = time.monotonic()
    with _failure_lock:
        entries = _failure_log[source]
        # Prune old entries
        cutoff = now - _RATE_LIMIT_WINDOW
        _failure_log[source] = [t for t in entries if t > cutoff]
        _failure_log[source].append(now)
        if len(_failure_log) > 10000:
            # Remove keys whose entries are all expired (empty after pruning)
            # AND keys with only stale timestamps to prevent unbounded growth
            stale = [k for k, v in _failure_log.items()
                     if not v or (v and v[-1] < cutoff)]
            for k in stale:
                del _failure_log[k]


def _is_rate_limited(source: str) -> bool:
    """Return True if *source* has exceeded the failure rate limit."""
    now = time.monotonic()
    with _failure_lock:
        entries = _failure_log.get(source, [])
        cutoff = now - _RATE_LIMIT_WINDOW
        recent = [t for t in entries if t > cutoff]
        return len(recent) >= _RATE_LIMIT_MAX_FAILURES


# --- Token revocation ---
_revoked_tokens: dict[str, float] = {}  # token_id -> revocation_time
_revoked_lock = threading.Lock()
_REVOCATION_PATH = "/var/lib/ai-control/revoked_tokens"
_REVOCATION_TTL = 7200  # Evict revoked tokens after 2h (tokens expire in <= 1h by default)
# Lazy-load state: we avoid reading the revocation file at daemon startup
# (slow disks take a measurable hit). The list is loaded on the first auth
# check and re-read only when the file's mtime changes.
_revocation_loaded: bool = False
_revocation_mtime: float = 0.0


def revoke_token(token_id: str) -> None:
    """Add a token ID (jti) to the revocation list."""
    with _revoked_lock:
        _ensure_revocation_loaded_locked()
        _revoked_tokens[token_id] = time.time()
        # Prune expired revocations to prevent unbounded growth
        _prune_revocations()
        _save_revocation_list()
    # Evict any cached verify_token() results that reference this jti so
    # a recently-issued and now-revoked token cannot ride a stale cache
    # hit for the remainder of its TTL.
    with _token_cache_lock:
        stale = [
            tok for tok, (ident, _exp) in _TOKEN_CACHE.items()
            if ident is not None and ident.jti == token_id
        ]
        for tok in stale:
            _TOKEN_CACHE.pop(tok, None)


def is_revoked(token_id: str) -> bool:
    """Return True if the given token ID has been revoked."""
    with _revoked_lock:
        _ensure_revocation_loaded_locked()
        return token_id in _revoked_tokens


def _prune_revocations():
    """Remove revoked tokens older than _REVOCATION_TTL (caller holds _revoked_lock)."""
    cutoff = time.time() - _REVOCATION_TTL
    stale = [tid for tid, ts in _revoked_tokens.items() if ts < cutoff]
    for tid in stale:
        del _revoked_tokens[tid]


def _save_revocation_list():
    """Persist the revocation list to disk."""
    try:
        os.makedirs(os.path.dirname(_REVOCATION_PATH), exist_ok=True)
        with open(_REVOCATION_PATH, 'w') as f:
            json.dump(_revoked_tokens, f)
    except OSError:
        pass


def _load_revocation_list():
    """Load the revocation list from disk (caller holds _revoked_lock)."""
    global _revoked_tokens, _revocation_mtime
    try:
        if os.path.exists(_REVOCATION_PATH):
            try:
                _revocation_mtime = os.path.getmtime(_REVOCATION_PATH)
            except OSError:
                _revocation_mtime = 0.0
            with open(_REVOCATION_PATH) as f:
                data = json.load(f)
                # Support both old format (list) and new format (dict)
                if isinstance(data, list):
                    now = time.time()
                    _revoked_tokens = {tid: now for tid in data}
                elif isinstance(data, dict):
                    _revoked_tokens = {k: float(v) for k, v in data.items()}
                else:
                    _revoked_tokens = {}
            # Prune on load
            _prune_revocations()
    except (OSError, json.JSONDecodeError):
        pass


def _ensure_revocation_loaded_locked():
    """Load (or reload) the revocation list if needed.

    Called from within _revoked_lock. Performs a one-shot load on first use
    and re-reads the file when its mtime changes so external revocations
    (e.g. by an admin CLI) take effect without restart. Startup cost on
    slow disks is avoided because this never runs until the first auth
    check actually needs it.
    """
    global _revocation_loaded, _revocation_mtime
    if not _revocation_loaded:
        _load_revocation_list()
        _revocation_loaded = True
        return
    # Cheap mtime re-check: only re-read if the file changed on disk.
    try:
        mtime = os.path.getmtime(_REVOCATION_PATH)
    except OSError:
        return
    if mtime != _revocation_mtime:
        _load_revocation_list()


def _load_or_create_secret() -> bytes:
    """Load the auth secret from disk, or create a new one."""
    global _secret
    if _secret:
        return _secret
    try:
        os.makedirs(os.path.dirname(_SECRET_PATH), exist_ok=True)
        if os.path.exists(_SECRET_PATH):
            with open(_SECRET_PATH, "rb") as f:
                _secret = f.read()
        else:
            _secret = os.urandom(32)
            with open(_SECRET_PATH, "wb") as f:
                f.write(_secret)
            os.chmod(_SECRET_PATH, 0o600)
    except OSError:
        _secret = os.urandom(32)
    # Revocation list is lazy-loaded on first auth check via
    # _ensure_revocation_loaded_locked(); don't touch disk here.
    return _secret


@dataclass
class CallerIdentity:
    """Represents an authenticated API caller."""
    subject_id: int
    name: str
    trust_level: int  # TRUST_AUTH_* level
    issued_at: float
    expires_at: float
    jti: str = ""  # JWT ID for revocation


# Endpoint trust requirements
ENDPOINT_TRUST = {
    # No auth needed
    "/health": 0,
    "/docs": 0,
    "/openapi.json": 0,
    # Read-only, low trust
    "/screen/capture": 100,
    "/screen/capture/base64": 100,
    "/screen/capture/region": 100,
    "/screen/size": 100,
    "/system/info": 200,
    "/system/processes": 200,
    "/network/ip": 100,
    "/network/dns": 100,
    "/network/routes": 100,
    # Interactive, user trust
    "/keyboard/type": 200,
    "/keyboard/press": 200,
    "/keyboard/release": 200,
    "/keyboard/tap": 200,
    "/keyboard/combo": 200,
    "/mouse/move": 200,
    "/mouse/click": 200,
    "/mouse/double_click": 200,
    "/mouse/drag": 200,
    "/mouse/scroll": 200,
    # File operations
    "/filesystem/read": 200,
    "/filesystem/list": 200,
    "/filesystem/write": 400,
    "/filesystem/delete": 400,
    "/filesystem/mkdir": 300,
    # System operations
    "/services": 200,
    "/services/status": 200,
    "/network/connections": 200,
    "/network/wifi": 200,
    "/network/wifi/scan": 200,
    "/network/wifi/status": 200,
    "/network/wifi/saved": 200,
    "/network/wifi/disconnect": 400,
    "/packages/installed": 200,
    "/packages/search": 200,
    # Elevated operations
    "/services/start": 400,
    "/services/stop": 400,
    "/services/restart": 400,
    "/network/wifi/connect": 400,
    "/network/ping": 200,
    "/packages/install": 500,
    "/packages/remove": 500,
    "/packages/update": 500,
    # Admin operations
    "/system/command": 600,
    "/firewall/status": 400,
    "/firewall/rules": 400,
    "/firewall/enable": 600,
    "/firewall/disable": 600,
    "/firewall/reload": 600,
    "/system/kill": 600,
    # Desktop automation
    "/desktop/launch": 200,
    "/desktop/launch-exe": 200,
    "/desktop/windows": 200,
    "/desktop/active-window": 200,
    "/desktop/window/focus": 200,
    "/desktop/window/move": 200,
    "/desktop/window/resize": 200,
    "/desktop/window/minimize": 200,
    "/desktop/window/maximize": 200,
    "/desktop/window/close": 300,
    "/desktop/notify": 200,
    "/desktop/clipboard": 200,
    "/desktop/wallpaper": 300,
    "/desktop/resolution": 200,
    "/desktop/shortcuts": 200,
    "/desktop/scheduled-tasks": 400,
    # Games
    "/games": 200,
    "/games/launch": 200,
    "/games/shortcut": 200,
    "/games/info": 200,
    # LLM / AI
    "/ai/status": 200,
    "/ai/models": 200,
    "/ai/load": 400,
    "/ai/unload": 400,
    "/ai/query": 200,
    # Compositor
    "/compositor/info": 200,
    "/compositor/windows": 200,
    "/compositor/active": 200,
    "/compositor/focus": 200,
    "/compositor/close": 300,
    "/compositor/layout": 300,
    "/compositor/workspaces": 200,
    # Cortex proxy
    "/cortex/status": 200,
    "/cortex/autonomy": 200,
    "/cortex/decisions": 200,
    # Automation API (AI assistant)
    "/auto/package": 500,
    "/auto/command": 600,
    "/auto/service": 400,
    "/auto/file": 400,
    "/auto/system": 200,
    "/auto/git": 400,
    # Auth token management
    "/auth/token": 600,
    "/auth/revoke": 600,
    "/auth/refresh": 200,
    # Contusion automation engine
    "/contusion": 100,                  # Root status page (GET)
    "/contusion/run": 400,
    "/contusion/pipeline": 400,
    "/contusion/macro/record": 400,
    "/contusion/macro/play": 400,
    "/contusion/macro/list": 200,
    "/contusion/apps": 200,
    "/contusion/context": 400,
    "/contusion/execute": 400,          # Alias for /contusion/context
    "/contusion/launch": 400,           # Launch app from library
    "/contusion/confirm": 600,          # Dangerous action confirmation
    "/contusion/processes": 200,
    "/contusion/dictionary/search": 200,
    "/contusion/dictionary/stats": 200,
    "/contusion/dictionary/app": 200,
    # Contusion workflow templates
    "/contusion/workflows": 200,
    "/contusion/workflows/run": 400,
    # Trust system
    "/trust/subjects": 100,
    "/trust/anomalies": 100,
    "/trust/architecture": 0,
    "/trust/observe": 300,
    # Windows services
    "/win-services": 200,
    "/win-services-scm/status": 200,
    "/win-services/start": 400,
    "/win-services/stop": 400,
    "/win-services/install": 500,
    "/win-services/details": 200,
    "/win-services/logs": 200,
    "/win-services/restart": 400,      # stop + start
    # Combined services (Windows + Linux)
    "/services/all": 200,
    # Drivers / kernel modules
    "/drivers/loaded": 200,
    # Hardware summary
    "/hardware/summary": 200,
    "/automation/tasks/cancel": 400,
    "/contusion/macro/stop": 400,
    "/contusion/window/automate": 400,
    "/contusion/clipboard": 400,
    "/contusion/screen/read": 400,
    "/contusion/window/wait": 400,
    # Audit
    "/audit/recent": 100,
    "/audit/stats": 200,
    # Trust history + Dashboard
    "/trust-history": 200,
    "/dashboard": 200,
    # Pattern scanner
    "/scanner/patterns": 200,
    "/scanner/stats": 200,
    "/scanner/scan": 400,
    "/scanner/analyze": 400,
    # Stub discovery engine
    "/discovery/profiles": 200,
    "/discovery/profile": 200,
    "/discovery/priority": 200,
    "/discovery/coverage": 200,
    "/discovery/categories": 200,
    "/discovery/analyze": 400,
    # Stub generator (auto-generate C stubs for Windows APIs)
    "/generator/generate": 400,
    "/generator/compile": 400,
    "/generator/templates": 200,
    "/generator/dll": 400,
    "/generator/generated": 200,
    # Automation engine
    "/automation/capabilities": 200,
    "/automation/task": 400,
    "/automation/quick": 400,
    "/automation/script": 600,
    "/automation/tasks": 200,
    "/automation/history": 200,
    # Memory observer (PE memory translator)
    "/memory/processes": 200,
    "/memory/process": 200,
    "/memory/anomalies": 200,
    "/memory/stats": 200,
    "/memory/scan": 400,
    # Memory diff engine (snapshot capture & comparison)
    "/memory/snapshots": 200,
    "/memory/snapshot": 400,
    "/memory/diff": 200,
    "/memory/timeline": 200,
    "/memory/diff/stats": 200,
    # Behavioral model engine (AI process analysis)
    "/behavioral/fingerprint": 200,
    "/behavioral/report": 200,
    "/behavioral/all": 200,
    "/behavioral/predict": 200,
    "/behavioral/analyze": 400,
    # Binary signature database (PE identification & dependency profiles)
    "/signatures/identify": 200,
    "/signatures/profiles": 200,
    "/signatures/stats": 200,
    "/signatures/profile": 200,
    "/signatures/contribute": 200,
    # Windows API signature database
    "/api-db/search": 200,
    "/api-db/unimplemented": 200,
    "/api-db/stats": 200,
    "/api-db/dll": 200,
    "/api-db/category": 200,
    "/api-db/complexity": 200,
    "/api-db/lookup": 200,
    "/api-db/dlls": 200,
    "/api-db/categories": 200,
    "/api-db/mark-implemented": 200,
    # Syscall-to-WinAPI translator
    "/translator/syscall": 200,
    "/translator/nt": 200,
    "/translator/ioctl": 200,
    "/translator/path": 200,
    "/translator/stats": 200,
    "/translator/search": 200,
    # Syscall monitor (live PE process tracing)
    "/syscall/processes": 200,
    "/syscall/trace": 200,
    "/syscall/stats": 200,
    "/syscall/ioctls": 200,
    "/syscall/files": 200,
    "/syscall/network": 200,
    "/syscall/behavior": 200,
    "/syscall/track": 400,          # Start/stop tracing requires elevated trust
    # Comprehensive analysis (runs all engines)
    "/analyze": 400,
}


def create_token(subject_id: int, name: str, trust_level: int,
                 ttl: int = 3600) -> str:
    """Create a signed auth token for a caller."""
    secret = _load_or_create_secret()
    now = time.time()
    payload = {
        "sub": subject_id,
        "name": name,
        "trust": trust_level,
        "iat": int(now),
        "exp": int(now + ttl),
        "jti": str(uuid.uuid4()),
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(secret, payload_json.encode(), hashlib.sha256).hexdigest()
    # Simple format: base64(payload).signature
    import base64
    token = base64.urlsafe_b64encode(payload_json.encode()).decode() + "." + sig
    return token


import base64 as _base64


def verify_token(token: str) -> Optional[CallerIdentity]:
    """Verify a token and return the caller identity, or None if invalid.

    Results are cached for the token's remaining lifetime to avoid re-HMAC
    on every request. The cache is bounded (LRU) and invalidated when the
    token expires or is revoked.
    """
    if not token:
        return None
    now = time.time()
    # LRU cache check — hit means we've already verified this exact token.
    with _token_cache_lock:
        entry = _TOKEN_CACHE.get(token)
        if entry is not None:
            identity, cached_exp = entry
            if cached_exp > now:
                # Still valid per the cached expiry; re-check revocation
                # (cheap dict lookup) so revoked tokens stop working promptly.
                if identity and identity.jti and is_revoked(identity.jti):
                    _TOKEN_CACHE.pop(token, None)
                    return None
                _TOKEN_CACHE.move_to_end(token)
                return identity
            # Expired — drop it.
            _TOKEN_CACHE.pop(token, None)

    secret = _load_or_create_secret()
    try:
        parts = token.split(".", 1)
        if len(parts) != 2:
            return None
        payload_json = _base64.urlsafe_b64decode(parts[0]).decode()
        expected_sig = hmac.new(secret, payload_json.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(parts[1], expected_sig):
            logger.warning("Invalid token signature")
            return None
        payload = json.loads(payload_json)
        exp = payload.get("exp", 0)
        if exp < now:
            logger.warning("Token expired for subject %s", payload.get("sub"))
            return None
        token_jti = payload.get("jti", "")
        if is_revoked(token_jti):
            logger.warning("Token %s has been revoked", token_jti)
            return None
        identity = CallerIdentity(
            subject_id=payload["sub"],
            name=payload.get("name", "unknown"),
            trust_level=payload.get("trust", 0),
            issued_at=payload.get("iat", 0),
            expires_at=exp,
            jti=token_jti,
        )
        # Populate LRU cache with bounded size.
        with _token_cache_lock:
            _TOKEN_CACHE[token] = (identity, float(exp))
            _TOKEN_CACHE.move_to_end(token)
            while len(_TOKEN_CACHE) > _TOKEN_CACHE_MAX:
                _TOKEN_CACHE.popitem(last=False)
        return identity
    except (ValueError, json.JSONDecodeError, KeyError, UnicodeDecodeError):
        # Malformed token payload: common case for probes and misconfigured
        # clients. Don't emit a stack trace — caller logs the auth failure.
        return None
    except Exception:
        logger.exception("Token verification failed")
        return None


# Pre-sorted prefix list for O(n) lookups instead of re-sorting on every
# request. Sorted once at module import (longest-prefix first). This matters
# because get_required_trust is called on the auth hot path for every
# request; sorting ~200 entries every time wasted ~25 µs per call.
_SORTED_PREFIXES: list[tuple[str, int]] = sorted(
    ENDPOINT_TRUST.items(), key=lambda x: -len(x[0])
)

# Bounded cache for verify_token() results so repeated requests from the
# same client don't re-HMAC the payload. Each entry is (identity_or_None,
# expires_at). We cap at 256 to match the rate-limit window; beyond that
# evict the oldest. Constant-time eviction via OrderedDict.
import collections as _collections
_TOKEN_CACHE: "_collections.OrderedDict[str, tuple[Optional['CallerIdentity'], float]]" = _collections.OrderedDict()
_TOKEN_CACHE_MAX = 256
_token_cache_lock = threading.Lock()


def get_required_trust(path: str) -> int:
    """Get the minimum trust score required for an endpoint path."""
    # Exact match — fast path, no iteration.
    trust = ENDPOINT_TRUST.get(path)
    if trust is not None:
        return trust
    # Prefix match (for parameterized routes like /services/status/{name}).
    # Uses the pre-sorted prefix list computed at import time.
    for prefix, trust in _SORTED_PREFIXES:
        if path.startswith(prefix) and (len(path) == len(prefix) or path[len(prefix)] in ('/', '?')):
            return trust
    # Fail-secure: unknown endpoints require admin trust
    return 600


def check_auth(path: str, method: str, token: Optional[str],
               trust_observer=None,
               client_ip: str = "local") -> tuple[bool, Optional[CallerIdentity], str]:
    """
    Check if a request is authorized.

    Returns (allowed, identity, reason).
    """
    required = get_required_trust(path)

    # No auth required for this endpoint
    if required == 0:
        return True, None, "no_auth_required"

    # Rate limit: reject early if this source has too many recent failures
    if _is_rate_limited(client_ip):
        logger.warning("Rate limited auth from %s", client_ip)
        return False, None, "rate_limited"

    # DELETE operations always need admin
    if method == "DELETE" and required < 600:
        required = 600

    # No token provided
    if not token:
        _record_auth_failure(client_ip)
        return False, None, "missing_token"

    # Verify token
    identity = verify_token(token)
    if not identity:
        _record_auth_failure(client_ip)
        return False, None, "invalid_token"

    # Check against trust observer for real-time score
    if trust_observer:
        subject_info = trust_observer.get_subject(identity.subject_id)
        if subject_info:
            if subject_info.get("frozen"):
                return False, identity, "subject_frozen"
            actual_score = subject_info.get("score", 0)
            adaptive_threshold = trust_observer.get_adaptive_threshold(
                identity.subject_id, required
            )
            if actual_score < adaptive_threshold:
                return False, identity, "insufficient_trust"

    return True, identity, "authorized"
