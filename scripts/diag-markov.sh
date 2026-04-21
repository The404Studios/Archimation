#!/bin/bash
# diag-markov.sh -- operator-facing diagnostic for the Markov-chain telemetry
# layer (see docs/markov-chains.md). Probes a LIVE ai-cortex / ai-control
# daemon on localhost; degrades gracefully when the daemon is not reachable
# instead of crashing.
#
# Flags:
#   --mock        Pretend the daemon answered with a synthetic snapshot
#                 (lets you see the report shape without booting a daemon)
#   --host HOST   Override 127.0.0.1
#   --port PORT   Override 8420
#   --token TOK   Bearer token to send (defaults to $AI_CONTROL_TOKEN env)
#   --max-subj N  Cap subject loop (default 10)
#
# Exit code: 0 if zero ERRORs, 1 otherwise.
#
# Cite: Roberts/Eli/Leelee, Zenodo 18710335.

set -uo pipefail

HOST="127.0.0.1"
PORT="8420"
TOKEN="${AI_CONTROL_TOKEN:-}"
MAX_SUBJ=10
MOCK=0

while [ $# -gt 0 ]; do
    case "$1" in
        --mock)     MOCK=1; shift ;;
        --host)     HOST="$2"; shift 2 ;;
        --port)     PORT="$2"; shift 2 ;;
        --token)    TOKEN="$2"; shift 2 ;;
        --max-subj) MAX_SUBJ="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,17p' "$0"; exit 0 ;;
        *)
            echo "[ERROR] unknown flag: $1" >&2; exit 2 ;;
    esac
done

INFO_N=0
WARN_N=0
ERR_N=0

log_info() { printf '[INFO] %s\n'  "$*"; INFO_N=$((INFO_N+1)); }
log_warn() { printf '[WARN] %s\n'  "$*"; WARN_N=$((WARN_N+1)); }
log_err()  { printf '[ERROR] %s\n' "$*"; ERR_N=$((ERR_N+1)); }

BASE="http://${HOST}:${PORT}"

# curl wrapper -- returns 0 even on transport error; we inspect $? in the
# caller so we can emit a structured WARN/ERROR.
fetch() {
    local path="$1"
    local out
    if [ -z "$TOKEN" ]; then
        out=$(curl -sS -m 5 -w '\n%{http_code}' "${BASE}${path}" 2>&1)
    else
        out=$(curl -sS -m 5 -H "Authorization: Bearer ${TOKEN}" \
              -w '\n%{http_code}' "${BASE}${path}" 2>&1)
    fi
    printf '%s' "$out"
}

# Tiny JSON inspectors -- prefer jq, fall back to python3.
have_jq() { command -v jq >/dev/null 2>&1; }
have_py() { command -v python3 >/dev/null 2>&1; }

json_get() {
    local key="$1"
    local body="$2"
    if have_jq; then
        printf '%s' "$body" | jq -r "${key} // empty" 2>/dev/null
    elif have_py; then
        KEY="${key#.}" printf '%s' "$body" | KEY="${key#.}" python3 -c '
import json, sys, os
key = os.environ.get("KEY", "")
try:
    d = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)
parts = [p for p in key.replace("[", ".").replace("]", "").split(".") if p and p != ""]
cur = d
for p in parts:
    if isinstance(cur, dict) and p in cur:
        cur = cur[p]
    elif isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
        cur = cur[int(p)]
    else:
        sys.exit(0)
print(cur if not isinstance(cur, (dict, list)) else json.dumps(cur))
' 2>/dev/null
    else
        printf ''
    fi
}

mock_payload_system() {
    cat <<'EOF'
{"uptime_s": 4127, "observation_count": 18342,
 "decision_chain": {"top": [["KILL_SUBJECT","QUARANTINE",412],
                            ["TRUST_RAISE","TRUST_RAISE",307],
                            ["NOOP","NOOP",1840]]},
 "subject_anomalies": [{"subject_id": 1234, "score": 4.7},
                       {"subject_id": 5678, "score": 1.1}],
 "subjects": [1234, 5678]}
EOF
}

mock_payload_decisions() {
    cat <<'EOF'
{"transitions": [["KILL_SUBJECT","QUARANTINE",412],
                 ["TRUST_RAISE","TRUST_RAISE",307],
                 ["NOOP","NOOP",1840]],
 "predict_next": {"NOOP": "NOOP", "KILL_SUBJECT": "QUARANTINE"}}
EOF
}

mock_payload_subject() {
    cat <<EOF
{"subject_id": $1, "hyperlation_markov": {"state": "NORMAL", "kl_recent": 0.12},
 "trust_markov": {"band_idx": 4, "expected_time_to_apoptosis": 42.7}}
EOF
}

# --- Section 1: liveness probe ---------------------------------------------
echo "=== Section 1: daemon liveness ==="
if [ "$MOCK" -eq 1 ]; then
    log_info "MOCK MODE -- not contacting any real daemon"
    SYS_BODY="$(mock_payload_system)"
    DECISIONS_BODY="$(mock_payload_decisions)"
else
    raw=$(fetch /health)
    code="${raw##*$'\n'}"
    body="${raw%$'\n'*}"
    if [ "$code" = "200" ]; then
        log_info "daemon up at ${HOST}:${PORT} (HTTP 200 on /health)"
    elif [ "$code" = "401" ] || [ "$code" = "403" ]; then
        log_warn "daemon up but /health required auth (HTTP ${code}) -- continuing"
    elif [ -z "$code" ] || [ "$code" = "000" ]; then
        log_err "daemon not reachable at ${BASE} (no HTTP response)"
        echo "=== TALLY: ${INFO_N} INFO, ${WARN_N} WARN, ${ERR_N} ERROR ==="
        exit 1
    else
        log_warn "daemon /health returned HTTP ${code} -- continuing best-effort"
    fi
fi

# --- Section 2: /cortex/markov/system --------------------------------------
echo "=== Section 2: system-wide telemetry (/cortex/markov/system) ==="
if [ "$MOCK" -eq 0 ]; then
    raw=$(fetch /cortex/markov/system)
    code="${raw##*$'\n'}"
    SYS_BODY="${raw%$'\n'*}"
    if [ "$code" != "200" ]; then
        log_warn "/cortex/markov/system returned HTTP ${code} -- endpoint may not be wired yet (Agent 9)"
        SYS_BODY=""
    else
        log_info "/cortex/markov/system OK (HTTP 200)"
    fi
fi
if [ -n "$SYS_BODY" ]; then
    obs=$(json_get '.observation_count' "$SYS_BODY")
    upt=$(json_get '.uptime_s' "$SYS_BODY")
    [ -n "$obs" ] && log_info "observation_count = ${obs}" || log_warn "observation_count missing in response"
    [ -n "$upt" ] && log_info "uptime_s = ${upt}"          || log_warn "uptime_s missing in response"

    if have_jq; then
        anom_n=$(printf '%s' "$SYS_BODY" | jq '.subject_anomalies | length' 2>/dev/null || echo 0)
        log_info "subject anomalies reported: ${anom_n}"
        printf '%s' "$SYS_BODY" | jq -r '.subject_anomalies // [] | .[] | "  subj=\(.subject_id) score=\(.score)"' 2>/dev/null \
          | while read -r line; do
              # extract score for threshold check
              s=$(printf '%s' "$line" | sed -nE 's/.*score=([0-9.]+).*/\1/p')
              if [ -n "$s" ]; then
                  awk -v s="$s" 'BEGIN{exit !(s+0 > 3.0)}' \
                      && log_warn "high-anomaly subject: ${line# }" \
                      || log_info "subject ok: ${line# }"
              fi
          done || true
    fi
fi

# --- Section 3: /cortex/markov/decisions -----------------------------------
echo "=== Section 3: decision chain (/cortex/markov/decisions) ==="
if [ "$MOCK" -eq 0 ]; then
    raw=$(fetch /cortex/markov/decisions)
    code="${raw##*$'\n'}"
    DECISIONS_BODY="${raw%$'\n'*}"
    if [ "$code" != "200" ]; then
        log_warn "/cortex/markov/decisions returned HTTP ${code} -- endpoint may not be wired yet"
        DECISIONS_BODY=""
    else
        log_info "/cortex/markov/decisions OK (HTTP 200)"
    fi
fi
if [ -n "$DECISIONS_BODY" ] && have_jq; then
    n_tr=$(printf '%s' "$DECISIONS_BODY" | jq '.transitions | length' 2>/dev/null || echo 0)
    log_info "distinct (prev,next) transitions: ${n_tr}"
    printf '%s' "$DECISIONS_BODY" | jq -r '.transitions[:10][] | "  \(.[0]) -> \(.[1])  n=\(.[2])"' 2>/dev/null \
      | while read -r line; do log_info "transition${line}"; done || true
    printf '%s' "$DECISIONS_BODY" | jq -r '.predict_next // {} | to_entries | .[] | "  given=\(.key) predict=\(.value)"' 2>/dev/null \
      | while read -r line; do log_info "predict_next${line}"; done || true
fi

# --- Section 4: per-subject loop -------------------------------------------
echo "=== Section 4: per-subject view (cap ${MAX_SUBJ}) ==="
if [ -n "$SYS_BODY" ] && have_jq; then
    subj_ids=$(printf '%s' "$SYS_BODY" | jq -r '.subjects // [] | .[]' 2>/dev/null \
               | head -n "$MAX_SUBJ")
    if [ -z "$subj_ids" ]; then
        log_info "no subject IDs in /cortex/markov/system response"
    else
        for sid in $subj_ids; do
            if [ "$MOCK" -eq 1 ]; then
                body="$(mock_payload_subject "$sid")"
                code=200
            else
                raw=$(fetch "/cortex/markov/subject/${sid}")
                code="${raw##*$'\n'}"
                body="${raw%$'\n'*}"
            fi
            if [ "$code" = "200" ]; then
                hstate=$(json_get '.hyperlation_markov.state' "$body")
                tband=$(json_get  '.trust_markov.band_idx' "$body")
                ttap=$(json_get   '.trust_markov.expected_time_to_apoptosis' "$body")
                log_info "subj=${sid} hyper=${hstate:-?} trust_band=${tband:-?} ttap=${ttap:-?}s"
            elif [ "$code" = "404" ]; then
                log_info "subj=${sid} -- 404 (no live record)"
            else
                log_warn "subj=${sid} -- HTTP ${code}"
            fi
        done
    fi
else
    log_info "skipping subject loop (no system payload or jq unavailable)"
fi

# --- Section 5: APE chi-square reminder ------------------------------------
echo "=== Section 5: APE Markov validator (kernel) ==="
if [ "$MOCK" -eq 1 ]; then
    log_info "MOCK: trust_ape_markov chi_sq=234 (within +/-64 of df=255) -- PASS"
elif command -v journalctl >/dev/null 2>&1; then
    line=$(journalctl -k -b 0 --no-pager 2>/dev/null | grep -m1 trust_ape_markov || true)
    if [ -n "$line" ]; then
        log_info "kernel: ${line#*trust_ape_markov}"
    else
        log_warn "no trust_ape_markov line in current boot dmesg (module may be off)"
    fi
else
    log_info "journalctl unavailable -- skipping kernel chi-square check"
fi

# --- Final tally -----------------------------------------------------------
echo "=== TALLY: ${INFO_N} INFO, ${WARN_N} WARN, ${ERR_N} ERROR ==="
[ "$ERR_N" -eq 0 ] && exit 0 || exit 1
