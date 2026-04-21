# ARCHWINDOWS Permission Model

Status: living document, Session 69 (Agent R) baseline.  
Scope: how non-root users reach the AI daemon, the event bus, and `/dev/trust` without escalating to root.

---

## 1. Why is the daemon root?

`ai-control.service` runs as `User=root` and `Group=root`. That is deliberate, not an oversight:

1. **Kernel module I/O.** `/dev/trust` write-side ioctls (quarantine, revoke, authority-proof mint) require `CAP_SYS_ADMIN`. The kernel module inside `trust.ko` double-checks capability bits on the caller; group membership on the device node alone does not unlock writes.
2. **Namespace and cgroup operations.** The daemon moves PE processes between `pe-compat.slice` and `game.slice`, constructs per-app scope cgroups under cgroup v2, and occasionally mounts overlayfs for PE `C:\` drive emulation. All require `CAP_SYS_ADMIN`.
3. **nftables control.** The firewall subsystem adds/removes rules via `nft`, which needs `CAP_NET_ADMIN` in the host netns.
4. **Input synthesis.** `python-evdev` opens `/dev/input/event*` for reading real input and writing uinput events. `uinput` is root-only on a stock kernel (can be loosened via udev, but we don't).
5. **PTY and window enumeration.** `CAP_SYS_PTRACE` lets the daemon read `/proc/<pid>/environ` and `/proc/<pid>/ns/*` for any user's PE process, which is how `window.list` enumerates across sessions.

We have NOT dropped the daemon to a dedicated uid for the reasons above. What we have done (Session 69, Agent R) is:

- Keep the daemon root, BUT
- Give it `SupplementaryGroups=trust pe-compat` via a systemd drop-in, so
- Every socket / pipe / file the daemon creates at `0660` with a group owner **accessible to non-root members of those groups** gets the right gid.

`profile/airootfs/etc/systemd/system/ai-control.service.d/group.conf:26`

---

## 2. What does membership in `trust` grant?

`/dev/trust` is mode `0660`, group `trust`. Kernel-side policy inside `trust.ko` is layered on top of that FS permission.

### Read-side (group membership alone is enough)

| ioctl | Purpose |
|---|---|
| `TRUST_IOC_QUERY_BAND` | Read caller's current trust band (0–255). Used by diagnostics, set_smoke, and cortex probes. |
| `TRUST_IOC_QUERY_SUBJECT` | Read metadata on a subject_id (chromosomal segments A0..A22, last reputation delta). |
| `TRUST_IOC_STATS` | Read aggregate counters (mint/revoke/consume totals, current pool HWM, APE proof count). |
| `TRUST_IOC_LIST_SUBJECTS` | Enumerate active subjects (cap: 256 subjects per syscall page). |
| `TRUST_IOC_CHISQ_SNAPSHOT` | Markov-chain histogram snapshot (Session 58 `trust_ape_markov`). |

### Write-side (group membership is NECESSARY but NOT SUFFICIENT)

All of these still require `CAP_SYS_ADMIN` in the caller's user namespace. The kernel module refuses with `-EPERM` when a non-privileged caller invokes them, even with the file open.

| ioctl | Purpose | Required capability |
|---|---|---|
| `TRUST_IOC_QUARANTINE` | Force a PID into the quarantine slice. | `CAP_SYS_ADMIN` |
| `TRUST_IOC_MINT_PROOF` | Generate an APE proof blob for a subject. | `CAP_SYS_ADMIN` |
| `TRUST_IOC_REVOKE_SUBJECT` | Mark a subject revoked; side-effects reputation. | `CAP_SYS_ADMIN` |
| `TRUST_IOC_RELOAD_POLICY` | Reload trust policy tables from userspace. | `CAP_SYS_ADMIN` |

This means a non-root user in the `trust` group can observe the trust system but cannot modify it. That is the entire point of the group.

Rule enforcing this split: `profile/airootfs/etc/udev/rules.d/70-trust.rules:14`

---

## 3. What does membership in `pe-compat` grant?

`/run/pe-compat/events.sock` is a `SOCK_DGRAM` AF_UNIX socket owned `root:pe-compat` mode `0660`. The AI daemon creates it at startup (`ai-control/cortex/event_bus.py:583`) and chgrp's it to `pe-compat` (same file, Session 69 addition).

Membership grants:

- **Subscribe:** `recvmsg()` on the socket reads every event published by the PE loader, the SCM, the object broker, and the AI cortex. Events follow the `pe_event_header_t` wire format (`services/scm/scm_event.h:5`).
- **Publish:** `sendto()` with a well-formed event header is accepted. The cortex will route the event through its handler chain. This is how `scm-daemon`, `pe-objectd`, and in-process tools like `pe-status` talk to the cortex.

Ancillary paths also gated by this group on a clean install:

- `/var/lib/pe-compat/registry/` (mode `0770 pe-compat`) — registry hive files.
- `/run/pe-compat/scm.sock` (mode `0660 pe-compat`) — SCM control socket.
- `/run/pe-compat/objectd.sock` (mode `0660 pe-compat`) — named-object broker.

If you are writing a tool that talks to any of the above, add its running user to `pe-compat`.

---

## 4. Creating a new non-root user

### Live ISO

On the live ISO the default user is `arch` (passwordless autologin, `sudo` NOPASSWD). `customize_airootfs.sh` adds `arch` to `wheel`, `trust`, `pe-compat`, `audio`, `video`, `input`, `network`, `storage`, `users`, `autologin` at build time (`profile/airootfs/root/customize_airootfs.sh:27`). No post-login action needed.

### Installed to disk

Agent O's `ai-install-to-disk` CLI handles user creation. If you're doing it manually after a base install:

```bash
# 1. Create groups (idempotent -- sysusers.d also does this, but run this
#    if you haven't rebooted yet after installing trust-system):
sudo groupadd -r trust
sudo groupadd -r pe-compat

# 2. Create the user.  Adapt <username> and <shell>:
sudo useradd -m -G wheel,trust,pe-compat,audio,video,input -s /bin/bash <username>
sudo passwd <username>

# 3. (Optional) Grant sudo:
sudo sh -c "echo '<username> ALL=(ALL) ALL' > /etc/sudoers.d/50-<username>"
sudo chmod 440 /etc/sudoers.d/50-<username>

# 4. Verify group membership:
id <username>
# Expected: ...,trust,pe-compat,...

# 5. Log out and back in so the new supplementary groups stick.
```

The `ai-setup-users.service` oneshot runs on every boot and adds the first UID-≥1000 regular user to those groups idempotently, so even if you forget step 2's `-G` list, the next boot will fix it up. Script: `profile/airootfs/root/setup-users.sh:64`.

### Sanity check

```bash
# Should all succeed for a user in trust + pe-compat:
test -r /dev/trust                     && echo "trust: OK"      || echo "trust: FAIL (group trust missing?)"
test -S /run/pe-compat/events.sock     && echo "events: OK"     || echo "events: FAIL (daemon not up?)"
curl -sSf http://127.0.0.1:8420/health && echo                  || echo "daemon: FAIL"
```

`ai-health` runs the full check across all three.

---

## 5. What we explicitly chose NOT to secure

Session 68's audit and the top-level README both say so; this section is the honest checklist.

- **Hostile root.** A user who already has root on the box can do whatever they want. We make no attempt to defend against the local superuser.
- **SUID bits.** No ARCHWINDOWS binary is SUID. Privilege escalation to root goes through `sudo` and nothing else. If a hostile actor gets SUID somewhere unrelated (stock `passwd`, `ping`, etc.) we inherit the stock Arch attack surface, unchanged.
- **The Python daemon's attack surface.** The daemon is ~30k LOC of Python with FastAPI, evdev, subprocess, nftables, and LLM integration. It exposes 100+ endpoints on localhost:8420 without CSRF tokens, without rate limiting beyond the cortex's circuit breaker, and with token auth that is mint-by-asking. If a user can run arbitrary code as the `arch` user they can post to `/keyboard/type` and own the session — which is fine because they're already that user.
- **The event bus is lossy.** `/run/pe-compat/events.sock` is a datagram socket with a bounded kernel buffer. Under sustained load, events drop on the floor. A hostile subscriber in the `pe-compat` group can flood the daemon with bogus events to mask real ones.
- **Trust kernel module as a whole.** The module is GPL-3 but unsigned, DKMS-built, and does not go through Secure Boot's chain. A hostile root can `rmmod trust; insmod evil.ko` and the system won't notice.

If your threat model includes any of the above, ARCHWINDOWS is not the right distro for you today.

---

## 6. Future hardening (aspirational)

In rough priority order, what we would do with a second engineering pass:

1. **Drop the daemon to a dedicated uid `ai-control`** with `AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_SYS_ADMIN` and `CapabilityBoundingSet=` locked. Would require a systemd rework of every subsystem (udev_mount, cgroup control, nftables) but is the clean way to reduce blast radius.
2. **SELinux policy** for `/dev/trust` and the event bus, so the kernel enforces who-can-talk-to-what regardless of FS permissions. Gentoo hardened taught us a lot here.
3. **Signed kernel module.** `trust.ko` compiled against a project-owned MOK, loaded only under Secure Boot. Prevents `rmmod; insmod evil.ko`.
4. **Full audit log.** Every ioctl on `/dev/trust` goes through `audit_log_user_message()` with subject_id + PID + band-delta. Log shipped to `/var/log/audit/trust.log` rotated daily.
5. **Token auth for the daemon.** `/token/mint` should require a one-time out-of-band secret (QR code at boot, `/boot/daemon-secret`) and expire tokens faster than 24h. Current 24h mint window is too lax for shared hosts.
6. **PID-namespace isolation for PE processes.** Each PE process should run in its own pid/net namespaces so the trust system's quarantine primitive can be enforced by the kernel, not by cgroup moves. Wine does this via `unshare`.
7. **Mandatory 2-person review** on any change to `trust.ko`. We currently single-maintainer-land kernel changes. Not scaling.

None of the above is on the Session 69 roadmap. We document them here so the next maintainer doesn't have to re-derive the list.

---

## Quick reference

| Who / What | Mode | Owner | Group | Set by |
|---|---|---|---|---|
| `/dev/trust` | `0660` | root | trust | `70-trust.rules` (udev) |
| `/run/pe-compat/events.sock` | `0660` | root | pe-compat | `event_bus.py` chgrp |
| `/run/pe-compat/scm.sock` | `0660` | root | pe-compat | `scm_daemon.c` |
| `/run/pe-compat/objectd.sock` | `0660` | root | pe-compat | `pe-objectd` |
| `/var/lib/pe-compat/registry/` | `0770` | root | pe-compat | airootfs tree |
| `ai-control.service` | — | User=root | Group=root | systemd unit |
| `ai-control.service.d/group.conf` | — | — | SupplementaryGroups=trust pe-compat | drop-in |

File citations:
- `packages/trust-system/PKGBUILD:48` (udev rule install)
- `profile/airootfs/etc/udev/rules.d/70-trust.rules:14`
- `profile/airootfs/etc/systemd/system/ai-control.service.d/group.conf:26`
- `profile/airootfs/root/setup-users.sh:64` (runtime reconciler)
- `profile/airootfs/root/customize_airootfs.sh:27` (build-time `arch` user)
- `ai-control/cortex/event_bus.py:587` (chgrp at bind time)
