# `/system/summary` — Unified subsystem health endpoint

A single auth-exempt JSON endpoint that aggregates a snapshot of every
subsystem the AI Control daemon has loaded. One call, everything shown.

## Why it exists

Existing endpoints (`/health`, `/system/info`, `/system/overview`) each
give a partial view. Monitoring tools, the QEMU smoke-test harness, the
future `/system/coherence` aggregator, and human operators all want the
same thing: a single-pane-of-glass snapshot showing *which subsystems
are up, which are degraded, and how much state each holds*. This
endpoint is that snapshot.

Design goals:

- **Auth-exempt** — works with `curl` directly, no token required.
- **Always HTTP 200** — even when every subsystem is missing.
- **Never crashes** — a broken subsystem becomes `{"loaded": true,
  "error": "..."}` rather than 500-ing the whole endpoint.
- **Under 10ms** — no I/O, only cached attribute reads.

## Curl examples

```bash
# Full snapshot (no auth header needed).
curl -s http://localhost:8420/system/summary | jq .

# Is the daemon past startup?
curl -s http://localhost:8420/system/summary | jq -r .state

# Which subsystems failed to load?
curl -s http://localhost:8420/system/summary \
  | jq '.subsystems | to_entries | map(select(.value.loaded == false)) | .[].key'

# Useful for shell scripts:
ready=$(curl -sf http://localhost:8420/system/summary | jq -r .state)
[ "$ready" = "ready" ] || exit 1
```

## Response schema

```json
{
  "daemon": "ai-control",
  "version": "0.1.0",
  "uptime_s": 123,
  "session": "headless",
  "hostname": "archwindows",
  "subsystems": {
    "scanner":            {"loaded": true, "patterns": 39, "scans_total": 0, "hits_total": 0},
    "memory_observer":    {"loaded": true, "tracked_pids": 0, "enabled": true},
    "memory_diff":        {"loaded": true, "enabled": true, "tracked_pids": 0},
    "stub_discovery":     {"loaded": true},
    "binary_signatures":  {"loaded": true, "profiles": 28},
    "win_api_db":         {"loaded": true, "signatures": 295},
    "stub_generator":     {"loaded": true},
    "syscall_monitor":    {"loaded": true, "enabled": true, "tracked_pids": 0},
    "syscall_translator": {"loaded": true, "linux": 111, "nt": 31, "ioctls": 70},
    "behavioral_model":   {"loaded": true},
    "thermal":            {"loaded": true, "hw_class": "mid", "temp_c": null, "state": "normal"},
    "power":              {"loaded": true, "baseline": "auto", "boost_active": false},
    "contusion":          {"loaded": true, "apps_count": 0},
    "firewall":           {"loaded": true, "cgroup_enforcement": true}
  },
  "counters": {
    "auth_tokens_issued": 0,
    "auth_tokens_revoked": 0,
    "audit_entries_total": 0,
    "pe_processes_active": 0
  },
  "state": "ready"
}
```

### Top-level fields

| Field       | Type     | Meaning                                                   |
|-------------|----------|-----------------------------------------------------------|
| `daemon`    | string   | Always `"ai-control"`.                                    |
| `version`   | string   | Matches `app.version` in `api_server.create_app()`.       |
| `uptime_s`  | int      | Whole seconds since module load (monotonic clock).        |
| `session`   | enum     | `"wayland"`, `"x11"`, or `"headless"`.                    |
| `hostname`  | string   | `platform.node()` with `"unknown"` fallback.              |
| `subsystems`| object   | Per-subsystem blocks. See table below.                    |
| `counters`  | object   | Daemon-wide monotonic counters.                           |
| `state`     | enum     | `"starting"` during early init, `"ready"` post-startup.   |

### Subsystem blocks

Every subsystem key *always appears*. If not loaded, the block is
`{"loaded": false}` (optionally with `"error"`). If loaded, the block
contains `"loaded": true` plus subsystem-specific counters.

| Subsystem          | Additional fields                                                |
|--------------------|------------------------------------------------------------------|
| `scanner`          | `patterns`, `scans_total`, `hits_total`                          |
| `memory_observer`  | `tracked_pids`, `enabled`                                        |
| `memory_diff`      | `enabled`, `tracked_pids`                                        |
| `stub_discovery`   | —                                                                |
| `binary_signatures`| `profiles`                                                       |
| `win_api_db`       | `signatures`                                                     |
| `stub_generator`   | —                                                                |
| `syscall_monitor`  | `enabled`, `tracked_pids`                                        |
| `syscall_translator`| `linux`, `nt`, `ioctls`                                         |
| `behavioral_model` | —                                                                |
| `thermal`          | `hw_class`, `temp_c` (float or null), `state`                    |
| `power`            | `baseline`, `boost_active`                                       |
| `contusion`        | `apps_count`                                                     |
| `firewall`         | `cgroup_enforcement`                                             |

### Counters

All counters are integers. They grow monotonically across the lifetime
of the daemon process; they reset on daemon restart.

| Counter                  | Source                                                   |
|--------------------------|----------------------------------------------------------|
| `auth_tokens_issued`     | `auth._tokens_issued_total` (0 if unavailable).          |
| `auth_tokens_revoked`    | `len(auth._revoked_tokens)`.                             |
| `audit_entries_total`    | `len(AuditLogger._recent)`.                              |
| `pe_processes_active`    | `len(MemoryObserver._processes)`.                        |

## Stability contract

- **Field names are stable across minor versions.** New subsystems add
  new keys; existing keys never disappear.
- **Every subsystem key is always present** — callers can do
  `body.subsystems.scanner.loaded` without `.get()` guards.
- **HTTP status is always 200.** Errors surface as `"error"` fields in
  the relevant block, never as non-2xx responses.
- **Adding new fields inside a subsystem block is a minor-version
  change.** Removing fields is a breaking change and will only happen
  in a major-version bump with a release note.

## Integration with authentication

The route is in the *auth-exempt* list alongside `/health`, `/docs`, and
`/openapi.json`. Operators who need to restrict access should front the
daemon with a reverse proxy; the daemon itself assumes the loopback
binding in `config.toml` is sufficient for the default deployment.

## Reference implementation

- Module: `ai-control/daemon/system_summary.py`
- Factory: `make_summary_router(app_state: Mapping) -> APIRouter`
- Tests: `ai-control/daemon/tests/test_system_summary.py`
