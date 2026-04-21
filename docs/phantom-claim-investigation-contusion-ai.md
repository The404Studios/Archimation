# Phantom-Claim Investigation — `/contusion/ai` Endpoint (S51 claim)

**Status:** S74 Agent U investigation. Extends the S68 phantom-claim
pattern documentation (four prior phantoms) with a fifth candidate.
**Date:** 2026-04-20.
**Git HEAD:** `071b6aa+` (post-checkpoint `5013ad9`).
**Verdict:** **NEVER-LANDED on the server; client-side references
exist as dangling callers.**

---

## §1. Claim source

**Source memory file:**
`~/.claude/projects/C--Users-wilde-Downloads-arch-linux-with-full-ai-control/memory/session51_qemu_pass_ai_cli.md:46-51, 112`.

**Exact S51 claim wording** (verbatim from the memory file):

```
NEW endpoint `POST /contusion/ai`:
- Body: `{instruction, auto_confirm=false, context?}`
- `auto_confirm=true AND confidence>=0.85 AND latch_clear AND not lockdown` → executes immediately
- Otherwise returns proposal for `/contusion/confirm` flow
- Audited via `_audit_contusion("ai", detail, ok)`
```

And as an S52 handoff at `session51_qemu_pass_ai_cli.md:112`:

```
Auth.py: add `"/contusion/ai": 200` to ENDPOINT_TRUST (Agent 1 noted —
currently inherits the `/contusion` prefix at trust 100)
```

So S51 memory claims both **the endpoint itself was added to
api_server.py** AND **an auth.py trust entry was a known follow-on**.

---

## §2. Current state — the 15 /contusion/* routes that DO exist

Grep `@app\.(post|get|put|delete)\(.*/contusion` against
`ai-control/daemon/api_server.py` at HEAD — 15 routes:

| # | Method | Path | api_server.py line | Purpose |
|---|--------|------|--------------------|---------|
| 1 | POST | `/contusion/run` | 2514 | Typed handler dispatch |
| 2 | POST | `/contusion/pipeline` | 2526 | Multi-step plan |
| 3 | POST | `/contusion/macro/record` | 2544 | Start macro recording |
| 4 | POST | `/contusion/macro/stop` | 2552 | Stop macro recording |
| 5 | POST | `/contusion/macro/play` | 2560 | Replay macro |
| 6 | GET  | `/contusion/macro/list` | 2572 | List macros |
| 7 | GET  | `/contusion/apps` | 2579 | App library enumeration |
| 8 | POST | `/contusion/context` | 2599 | Natural-language routing |
| 9 | POST | `/contusion/execute` | 2624 | Alias for `/contusion/context` |
| 10 | POST | `/contusion/launch` | 2630 | Launch from library |
| 11 | POST | `/contusion/confirm` | 2681 | Dangerous-action confirmation |
| 12 | POST | `/contusion/dictionary/search` | 2697 | Dict search |
| 13 | GET | `/contusion/dictionary/stats` | 2704 | Dict stats |
| 14 | GET | `/contusion/dictionary/app/{name}` | 2710 | Per-app dict |
| 15 | GET | `/contusion/processes` | 2719 | Process listing |

Plus `/contusion/workflows`, `/contusion/workflows/{name}`,
`/contusion/workflows/{name}/run`, `/contusion/window/automate`,
`/contusion/clipboard` (GET+POST), `/contusion/screen/read`,
`/contusion/window/wait` — the count is 22 route decorators if workflows and
window endpoints are counted. The S74-Agent-U brief quoted "15" per an earlier
audit; the audit's scope likely excluded the workflow sub-tree. The number
does not materially affect the phantom-claim finding.

**Critically: `/contusion/ai` is not in this list.** `grep "@app\..*/contusion/ai"`
across `ai-control/daemon/api_server.py` returns **zero** matches at HEAD.

### §2.1 Semantic-similarity check — is it hidden behind another name?

Could `/contusion/ai` be renamed to something else that implements the
S51 contract?

Checked routes:

- **`/contusion/context` (line 2599)** — takes a natural-language body,
  returns routing decision, handles `auto_confirm`. **Closest match** but
  body shape differs (S51 claim: `{instruction, auto_confirm=false,
  context?}`; current `/contusion/context` takes `ContusionContextRequest`
  which per grep at `contusion_dictionary.py:2764` has a different body
  contract). Also no `latch_clear`/`lockdown` branching in
  `/contusion/context`.
- **`/contusion/execute` (line 2624)** — explicitly documented at line 2626
  as *"Alias for /contusion/context. The `ai automate` shell helper..."*.
  Not the S51 `/contusion/ai` contract.
- **`/contusion/run` (line 2514)** — typed handler dispatch. Different body.

**None of the 22 current routes implement the S51 `/contusion/ai` contract
with body `{instruction, auto_confirm, context?}` and the auto-execute
gating logic (`confidence>=0.85 AND latch_clear AND not lockdown`).**

---

## §3. Git archaeology — did `/contusion/ai` ever land?

### §3.1 String search in tree

Grep `"/contusion/ai"` in the full working tree:

| File | Line | Nature |
|------|------|--------|
| `ai-control/cli/ai` | 5 | docstring: *"Talks to the daemon's /contusion/ai endpoint"* |
| `ai-control/cli/ai` | 192 | docstring: *"Normalise the /contusion/ai response"* |
| `ai-control/cli/ai` | 200 | docstring: *"the /contusion/ai endpoint. We pluck results[0]"* |
| `ai-control/cli/ai` | 491 | **call site:** `code, resp = client._post("/contusion/ai", ...)` |
| `ai-control/cli/README.md` | 6 | doc: *"by the daemon's `/contusion/ai`, `/contusion/confirm`, and"* |

**5 references, all CLIENT-SIDE.** The server side has zero references to
the endpoint.

### §3.2 Git log search

Commands run:

```
git log --all -S '/contusion/ai' --oneline
```

Single hit: `5013ad9 chore: checkpoint S38-S73 accumulated work (pre-S74 base)`.

```
git log --all --oneline -S '/contusion/ai' -- ai-control/daemon/api_server.py
```

**No hits.** The string never appeared in any commit that touched the server.

```
git log --all -S 'def contusion_ai' 2>&1
git log --all -S 'ContusionAIRequest' 2>&1
```

**No hits.** No function or request-model named for a `/contusion/ai`
endpoint ever landed.

### §3.3 Checkpoint `5013ad9` — what actually landed

The single commit referencing `/contusion/ai` is the S38-S73 squash
checkpoint at `5013ad9` — created 2026-04-20 as part of the S74 rebase-
clean prep. Its commit message lists all sessions squashed:

> *"Squashes ~35 sessions of working-tree work accumulated since commit
> e2f4ed7 (S37) into a single checkpoint so the upcoming S74 10-agent
> dispatch lands on a clean base and its delta is isolable.
>
> Significant prior-session output landed here:
> - S38-S52: desktop + NL + PE-loader + contusion iteration [...]*"

S51 is inside this range. However, `git show 5013ad9 -- ai-control/daemon/api_server.py
| grep "contusion/ai"` returns **zero lines** — the server file was squashed
without the `/contusion/ai` endpoint ever being present.

In other words: **the CLI client script `ai-control/cli/ai` was added in
that checkpoint, the server endpoint that the client calls was never added
in any commit, including the squash itself.**

### §3.4 Branches and stashes

```
git branch -a              # → only `master`
git log --all --source     # → only master + refs/stash
```

No lingering feature branch. No stash with the endpoint either — the single
stash `4e2dd0d WIP on master: e2f4ed7` predates S51.

### §3.5 Summary table

| Question | Answer |
|----------|--------|
| Does `/contusion/ai` exist at HEAD in `api_server.py`? | **NO** |
| Does any `git log -S` hit show it ever existed on the server? | **NO** |
| Does the CLI client (`ai-control/cli/ai`) reference it? | **YES** (5 refs including a live call site) |
| Does `auth.py` reference it in the ENDPOINT_TRUST dict? | **NO** (verified by grep — auth.py has 20+ `/contusion/*` entries at lines 333-375, none for `/contusion/ai`) |
| Is it semantically the same as another existing endpoint? | **NO** — `/contusion/context` is closest but body shape and auto-execute gating differ |
| Is there a feature branch or stash with the work? | **NO** |

---

## §4. Verdict

**NEVER-LANDED.**

The S51 memory file records a claim that the endpoint was added to
`ai-control/daemon/api_server.py`. This claim is false: no commit in any
branch has ever contained the endpoint. The client-side references exist
in `ai-control/cli/ai` as a live, broken caller — `client._post("/contusion/ai",
...)` at line 491 will return HTTP 404 against the current server.

The S52-handoff note `"Auth.py: add '/contusion/ai': 200"` was also never
acted upon — `auth.py` at HEAD has no entry for the path.

### §4.1 Evidence that the client side was written

The CLI helper `ai-control/cli/ai` appears in the squash commit as a new
601-LOC file (`git show 5013ad9 --stat -- ai-control/cli/ai` →
`ai-control/cli/ai | 601 +++`). Its docstring and 5 occurrence-sites are
consistent with the S51 memory's description of CLI behaviour — so **S51's
CLI work did land**. It is specifically the server-side endpoint that did
not. This matches the **Session 68 phantom-claim pattern exactly** — claim
landed in memory, half the implementation shipped, the other half silently
dropped, and subsequent sessions retained the claim in memory as if both
halves shipped.

### §4.2 Operational consequence

Any user invoking the CLI today with `ai task <something>` will:

1. Read `~/.ai/config.toml` for daemon URL/token.
2. POST to `/contusion/ai` per `ai:491`.
3. Receive HTTP 404 from FastAPI's default "not found" handler.
4. CLI will crash or produce unhelpful error (depends on line
   `ai:491` error handling — untested by this audit).

**This is a user-visible bug.** S75 code work owed.

---

## §5. Recommendation

### §5.1 Add to the S68 phantom-claim pattern documentation

S68's four phantom claims documented (per
`~/.claude/projects/.../memory/session68_audit_10agent_v2wire_verify.md`):

1. Kbuild ↔ PKGBUILD manifest drift for trust-dkms.
2. Missing `verify_trust_dkms_manifest()` in `scripts/build-packages.sh`.
3. Missing `/cortex/markov/*` endpoints.
4. `comctl32 register_*_class` never called.

This `/contusion/ai` finding is a **fifth same-pattern claim** (claim
landed in memory; implementation half-shipped; subsequent sessions
retained the claim). The pattern is stable: **memory claims should be
cross-checked against `git log -S` and grep against the source file
named as the implementation host, not just against the claim narrative.**

### §5.2 Actions owed (S75)

- **Memory repair (Agent M territory, not this agent):** S51 memory entry
  needs "SINCE DISCOVERED NEVER-LANDED" annotation.

- **Code repair (S75 feature work):** **either**
  - **(a) implement the endpoint** per S51's spec — body
    `{instruction, auto_confirm=false, context?}`; gated by
    `confidence>=0.85 AND latch_clear AND not lockdown`; audit via
    `_audit_contusion("ai", detail, ok)`; trust value 200 in `auth.py`;
    estimated ~120 LOC in `ai-control/daemon/api_server.py`;
  - **or (b) remove the dangling client references** —
    `ai-control/cli/ai:491` call site and its 4 docstring refs; retarget
    the CLI to `/contusion/context` if behaviourally equivalent; estimated
    ~30 LOC of client-side edits plus a documentation note in the CLI
    README.

  **Recommendation: (a)** — the CLI is shipped, documented, and
  user-facing; ripping out the call site is a regression. Implementing
  the endpoint is ~120 LOC and completes what S51 attempted.

- **Tests owed (S75):** `tests/integration/test_ai_cli_endpoint.py` or
  equivalent — should cover the auto-execute gating (HTTP 200 success +
  HTTP 202 "awaiting confirm") and the lockdown refusal path. No such
  test exists at HEAD per grep.

### §5.3 Reason this finding matters beyond the specific endpoint

The `/contusion/ai` phantom is the **fifth** of the same pattern. At a
rate of one phantom per ~17 sessions (S51 was 17 before S68), the
pattern suggests that the memory-vs-code-drift check belongs at the
per-session verification gate, not as an ad-hoc audit. Specifically:

- A tool like the S68-added `verify_trust_dkms_manifest()` — but for
  memory claims — could automatically grep any memory claim of the
  form *"NEW endpoint `X`"* against the source file named as the host,
  and fail-loud if the claim does not verify. Estimated ~80 LOC Python
  + 20 LOC CI hook.
- Alternatively, a per-session "agent-M audit" (the role already
  instanced for memory updates) could verify all endpoint/function
  claims from the just-ended session against live code before the
  memory file is committed.

**Flag only — not in this agent's scope. Recommended for S75 Agent M
discussion.**

---

## §6. Cross-references

- `~/.claude/projects/C--Users-wilde-Downloads-arch-linux-with-full-ai-control/memory/session51_qemu_pass_ai_cli.md`
  — original S51 claim (lines 46-51, 112).
- `~/.claude/projects/.../memory/session68_audit_10agent_v2wire_verify.md`
  — four prior phantom claims establishing the pattern.
- `ai-control/daemon/api_server.py:2477-2836` — the 22 live
  `/contusion/*` routes at HEAD.
- `ai-control/cli/ai:491` — the live dangling call site that motivates
  the fix.
- `ai-control/cli/README.md:6-7` — documentation that also names the
  missing endpoint.
- `ai-control/daemon/auth.py:333-375` — `ENDPOINT_TRUST` dict without
  a `/contusion/ai` entry.
- `docs/yx-quadrant-novelty.md`, `docs/meiosis-rename-decision.md` —
  companion S74 Agent U decision docs.

---

*S74 Agent U, 2026-04-20. Read-only investigation; no code edits
in this session. Flagged for S75 feature work.*
