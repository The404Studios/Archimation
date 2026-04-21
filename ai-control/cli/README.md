# `ai` -- natural-language CLI for the AI Control daemon

`ai` is a thin, stdlib-only Python frontend that turns plain English into
actions executed by the AI Control daemon (`ai-control.service`, port
8420).  It never runs system commands itself -- every effect is mediated
by the daemon's `/contusion/ai`, `/contusion/confirm`, and
`/contusion/execute` endpoints.

## Synopsis

```
ai <task in natural language ...>
ai task <task in natural language ...>      # explicit subcommand alias
ai --help
```

## Configuration

Per-user config lives at `~/.ai/config.toml`:

```toml
daemon_url = "http://127.0.0.1:8420"
auth_token = ""              # leave empty for localhost-bootstrap
auto_confirm_threshold = 0.85
verbosity = "normal"         # "quiet" | "normal" | "verbose"
editor = ""                  # empty = use $EDITOR or vi
```

A skeleton is shipped at `/etc/skel/.ai/config.toml`, so new users get it
on first login.

## Flags

| Flag | Effect |
|---|---|
| `-y`, `--yes` | Auto-confirm if the LLM's confidence >= `auto_confirm_threshold`. |
| `--dry-run` | Show the plan, don't execute. |
| `--no-color` | Strip ANSI from output (also honors `NO_COLOR`). |
| `-v`, `--verbose` | Show the full LLM rationale + the daemon audit envelope. |
| `--token TOKEN` | Override the auth token from the config file. |

At the confirm prompt you can answer `y` (run), `N` (decline), or `edit`
(open the proposed action JSON in `$EDITOR` so you can tweak the args
before dispatch).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Action executed successfully. |
| 1 | The user declined at the confirm prompt. |
| 2 | LLM confidence too low; the daemon needs clarification. |
| 3 | The daemon accepted but the action itself failed. |
| 4 | The daemon was unreachable or rejected our auth. |

## Examples

```bash
# Install a package
ai install firefox

# Launch a Steam game in big picture
ai launch steam in big picture mode

# Multi-step composite request
ai close all chrome windows and lock the screen

# Provision Claude Code with a key from a file the daemon can read
ai install claude code and set it up with the api key from /etc/ai-control/claude-key

# Open-ended diagnostic
ai check why my system feels slow
```

## Troubleshooting

If `ai` reports `cannot reach AI daemon`, run `systemctl status
ai-control` and confirm the unit is `active (running)`.  The `ai-control`
service binds 127.0.0.1:8420 by default; if you've moved it, update
`daemon_url` in your config.
