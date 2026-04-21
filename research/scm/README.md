svchost grouping -- research-only. NOT built into SCM.

`scm_svchost.c` implements Windows SERVICE_WIN32_SHARE_PROCESS semantics:
services tagged with the same `service_group` are co-hosted in one peloader
process via an AF_UNIX LP-JSON wire protocol. The implementation is solid
(spawn, ack, reap, crash-propagation), but wiring it into the live SCM
requires:

  1. Adding `char service_group[64]` to `service_entry_t` in `services/scm/scm.h`.
  2. Adding `int pending_restart; long restart_deadline_ns;` fields to the
     same struct (referenced at scm_svchost.c:499-500).
  3. Extending `services/scm/scm_database.c` on-disk format for those fields
     (with memset(0) backward-compat for existing service entries).
  4. Routing `scm_api.c::scm_start_service()` through `scm_svchost_load_service()`
     when `svc->service_group[0]` is set, and routing stop/crash accordingly.
  5. Hooking `scm_svchost_handle_host_exit()` from `scm_daemon.c`'s SIGCHLD
     reaper.

That's a multi-file schema change beyond surgical scope -- parked here until
someone owns the hosting feature end-to-end. The design doc is the header
comment in scm_svchost.c itself (wire format, concurrency contract, spawn
semantics). See memory/session75_8agent_s75_punchlist.md (Agent H dead-code
finding) and memory/session76 for parking rationale.
