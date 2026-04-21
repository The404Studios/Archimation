# AI Arch Linux: Perfect Architecture Design

**Date:** 2026-03-26
**Target:** Development platform for a general-purpose OS
**Core principle:** Native Windows PE execution on Linux with biologically-inspired trust, orchestrated by an autonomous AI cortex

---

## 1. Layer Model

Five layers. Commands flow down, events flow up. No layer calls upward.

```
Layer 0 ─ KERNEL
  trust.ko (authority root) + binfmt_pe.ko + Linux kernel

Layer 1 ─ OBJECT BROKER (pe-objectd)
  Named objects, registry, device namespace, session manager

Layer 2 ─ PE RUNTIME (per-process, monolithic, native speed)
  PE loader + 39 DLL stubs + SEH + trust gate + WDM host + subsystem backends

Layer 3 ─ SERVICE FABRIC (scm-daemon, enhanced)
  Windows + Linux service lifecycle, driver hosting, dependency graph

Layer 4 ─ AI CORTEX (the brain)
  Event bus + decision engine + orchestrator + autonomy controller
```

---

## 2. Layer 0 — Kernel

### 2.1 Trust Module (trust.ko)

The authority root. All trust decisions ultimately trace back here.

**Components:**
- TLB cache: 1024 sets x 4 ways = 4096 entries for O(1) capability checks
- RISC fast-path: single-cycle trust operations (check, score, record, threshold, decay, translate)
- FBC complex-path: multi-step policy evaluation, escalation, propagation, audit
- APE (Authority Proof Engine): self-consuming proof chain (proof destroyed on read, regenerated for next action)
- Chromosomal model: 23 segment pairs per subject (runtime A-segments + static B-segments)
- Token economy: metabolic cost per action, regeneration over time, starvation suspends capabilities
- Lifecycle: mitotic division (process spawn), meiotic combination (cooperative authority), immune response (anomaly detection), apoptosis (controlled death)
- TRC (Trust Regulation Core): state machine (NORMAL → ELEVATED → LOCKDOWN → PERMISSIVE) that dynamically adjusts resistance to authority changes
- Command buffer: batch submission of trust operations via TRUST_IOC_CMD_SUBMIT ioctl (GPU command buffer model, not a VM)

**ISA encoding (32-bit instruction word):**
```
[31:28] Family (4 bits): AUTH=0, TRUST=1, GATE=2, RES=3, LIFE=4, META=5
[27:24] Opcode (4 bits): per-family operation (8 per family = 48 total)
[23:20] Flags (4 bits): CHAIN=1, AUDIT=2, FENCE=4, CONDITIONAL=8
[19:16] Operand count (4 bits)
[15:0]  Immediate (16-bit)
```

**Operands (64-bit each):**
```
[63:60] Type: SUBJECT=0, CAP=1, SCORE=2, TOKEN=3, ACTION=4, DOMAIN=5, PROOF=6, THRESHOLD=7
[59:0]  Value
```

**Interface:** `/dev/trust` character device, ioctl-based.

### 2.2 binfmt_pe.ko

Registers with Linux binfmt_misc. Detects MZ+PE signature, redirects execution to `/usr/bin/peloader`. Flags: `OCF` (open-binary, credentials, fix-binary).

### 2.3 pe_compat.ko (optional)

Kernel-side helpers for PE memory management, process tracking, and syscall interception. Not required for basic operation.

---

## 3. Layer 1 — Object Broker (pe-objectd)

Single lightweight C daemon providing cross-process shared state that Windows applications expect.

### 3.1 Named Object Namespace

Windows applications create named synchronization objects (mutexes, events, semaphores, file mappings, waitable timers, jobs) that are visible across processes. The object broker manages these.

**Implementation strategy:**
- Unnamed objects: stay in-process (zero overhead, current implementation)
- Named objects: brokered via Unix domain socket + shared memory

**Fast-path for synchronization:**
- Broker allocates a shared memory page per named sync object
- Both processes mmap the same page
- WaitForSingleObject uses Linux futex on the shared page
- Zero broker involvement on the contention path (~100ns, kernel futex only)
- Broker involved only for create/open/close operations (~2μs socket round-trip)

**IPC protocol:** Unix domain socket at `/run/pe-compat/objects.sock`. Request/response with 32-byte header + variable payload. Datagram mode for fire-and-forget notifications, stream mode for request/response.

### 3.2 Registry Hive

Persistent, cross-process registry built on the existing `registry/registry.c` file-backed implementation.

**Hive mapping:**
```
HKEY_LOCAL_MACHINE  → /var/lib/pe-compat/registry/HKLM/
HKEY_CURRENT_USER   → ~/.pe-compat/registry/HKCU/
HKEY_CLASSES_ROOT   → merged view (HKLM\Software\Classes + HKCU\Software\Classes)
HKEY_USERS          → /var/lib/pe-compat/registry/HKU/
```

**Features:**
- Change notifications (RegNotifyChangeKeyValue) via inotify on backing files
- Atomic multi-key writes (rename-based commit)
- Default values seeded from `registry_defaults.c` on first boot
- Trust-gated: HKLM writes require elevated trust score

### 3.3 Device Namespace

Maps Windows device paths to Linux devices and PE driver instances.

**Namespace layout:**
```
\Device\*           → driver-created devices (via windrv_host)
\DosDevices\C:      → / (root filesystem)
\DosDevices\D:      → /mnt/cdrom (or configurable)
\DosDevices\Z:      → /home/<user>
\Device\Null        → /dev/null
\Device\KsecDD      → /dev/urandom (crypto RNG)
\??\PIPE\*          → /tmp/pe-compat/pipes/* (named pipes)
```

**Symlink resolution:** Up to 8 hops, cycle detection.

### 3.4 Session Manager

- Window stations: one per login session
- Desktops: one per window station (default: WinSta0\Default)
- Clipboard: cross-process, per-desktop, backed by X11/Wayland clipboard
- Atom table: GlobalAddAtom/GlobalGetAtomName for DDE and window class registration

### 3.5 Trust Enforcement

Every broker operation checks the caller's trust subject:
- Object creation: requires trust score >= threshold for object type
- Registry HKLM write: requires CAP_REGISTRY_WRITE + elevated trust
- Device access: requires CAP_DEVICE_IO
- Audit events emitted to cortex event bus for all operations

---

## 4. Layer 2 — PE Runtime

Per-process, monolithic, native speed. This is where Windows executables actually run.

### 4.1 Loader Core

**Boot sequence for a PE binary:**
1. `binfmt_pe` triggers `/usr/bin/peloader <exe>`
2. Peloader contacts cortex via `/run/pe-compat/cortex-cmd.sock`: PE_LOAD_REQUEST
3. Cortex responds: APPROVED with `{token_budget, capabilities, priority}` — or DENIED
4. If denied: peloader exits with error. If approved: continue.
5. Preloader reserves address space (8 slots)
6. PE parser reads headers (DOS, COFF, Optional, Section table)
7. Mapper maps sections with correct protections (mmap)
8. Relocator applies base relocations if image moved
9. Import resolver patches IAT (dlsym for .so stubs, PE export walking for PE DLLs, forwarder chain following)
10. Trust gate initializes with cortex-assigned budget and caps
11. PEB/TEB/GS register setup
12. Exception system initializes (SEH/VEH, RUNTIME_FUNCTION tables registered)
13. TLS initialized, callbacks invoked
14. Entry point called via abi_call_win64_2 (exe) or abi_call_win64_3 (DLL)
15. On exit: stub report printed, trust history updated, cortex notified

**Import resolution order:**
1. CRT ms_abi wrappers (memset, strlen, etc.)
2. dlsym on .so stub DLLs
3. C++ mangled name lookup
4. PE export directory walking (binary search, O(log n))
5. Forwarder chain following (max 8 hops)
6. RTLD_DEFAULT fallback
7. Diagnostic stub (logs function name, returns 0)

### 4.2 DLL Stub Layer

39+ shared libraries implementing Windows APIs via POSIX translation. All exported functions use `__attribute__((ms_abi))` for zero-overhead ABI bridge.

**Core DLLs:** kernel32 (24 files), ntdll (7), msvcrt (5), advapi32 (4), user32 (6), gdi32 (4)

**Extended DLLs:** ole32 (3), shell32, ws2_32, d3d (7), dsound (2), combase, bcrypt, crypt32, winhttp, setupapi, comctl32, comdlg32, ntoskrnl (6), hal, ndis, msi (2), shlwapi, version, iphlpapi, psapi, dbghelp, userenv, secur32, dwmapi, steamclient, imm32, shcore, winpix, wer, dstorage, oleaut32

**Key implementations (not stubs):**
- File I/O: CreateFile/ReadFile/WriteFile → POSIX open/read/write with path translation
- Memory: VirtualAlloc/HeapAlloc → mmap/malloc
- Threading: CreateThread → pthread_create with TEB/GS setup
- Synchronization: Events/Mutexes/CriticalSections/SRW → pthreads (intra-process) or object broker (named)
- IOCP: CreateIoCompletionPort → thread queue with pthread condition
- Fibers: CreateFiber/SwitchToFiber → ucontext
- Named Pipes: CreateNamedPipe → Unix domain sockets
- File Notifications: FindFirstChangeNotification → inotify
- Registry: RegOpenKeyEx/RegQueryValueEx → object broker
- Exceptions: VEH/SEH → signal handlers + RUNTIME_FUNCTION unwind tables
- Process/thread info: NtQuerySystemInformation → convincing fake Windows 10 environment

### 4.3 Subsystem Backends

Pluggable backend interfaces for system-specific functionality. Selected at runtime.

**Graphics (pe_gfx_backend_t):**
- `gfx_x11.c` — X11 window creation, DC management, event processing (942 lines, working)
- `gfx_wayland.c` — Wayland compositor protocol (580 lines, partial)
- `gfx_headless.c` — null backend for servers/CI (to be created)

**Audio (pe_audio_backend_t):**
- `audio_pipewire.c` — PipeWire for modern Linux (to be created)
- `audio_alsa.c` — direct ALSA fallback (to be created)

**Network (pe_net_backend_t):**
- `net_posix.c` — direct POSIX socket translation (current, in ws2_32)

**Storage (pe_storage_backend_t):**
- `stor_vfs.c` — path translation + case-folding (current, in dll_common.c)

### 4.4 Trust Gate

Mandatory per-API-call trust enforcement. Thread-local cache avoids ioctl overhead.

**22 gate categories:** FILE_READ, FILE_WRITE, NET_CONNECT, NET_LISTEN, PROCESS_CREATE, PROCESS_INJECT, THREAD_CREATE, MEMORY_EXEC, REGISTRY_READ, REGISTRY_WRITE, DRIVER_LOAD, SERVICE_START, DLL_LOAD, DEVICE_IOCTL, PRIVILEGE_ADJUST, CRYPTO_OP, SYSTEM_INFO, DEBUG_OP, CLIPBOARD, SCREEN_CAPTURE, KEYBOARD_HOOK, ANTI_TAMPER

**Cache invalidation:** Thread-local cache refreshed every 500ms or 64 calls. Active invalidation via shared memory flag set by trust.ko when subject state changes.

**Performance:** ~5ns for cached allow (single branch). ~2μs for cache miss (ioctl round-trip). Zero overhead when all checks pass.

### 4.5 Exception Handling

Full x64 SEH implementation.

- Module registry: cache-line-aligned (32 bytes/entry), lock-free reads via atomics
- Function lookup: O(log n) binary search on RUNTIME_FUNCTION tables
- Unwind: full UNWIND_CODE processing (11 opcodes)
- Dispatch: two-phase (search for handler, then unwind with __finally calls)
- Signal translation: SIGSEGV → ACCESS_VIOLATION, SIGFPE → FLOAT_DIVIDE_BY_ZERO, etc.
- Thread-local scratch buffers: zero malloc in exception dispatch path

### 4.6 WDM Driver Host

Userspace Windows Driver Model host for .sys files.

- DRIVER_OBJECT, DEVICE_OBJECT, IRP structures matching Windows DDK
- IRP dispatch through driver's MajorFunction table
- Device stacking (IoAttachDevice)
- IOCTL translation (Windows CTL_CODE → Linux ioctl where possible)
- Pool memory with tag tracking and leak detection
- Synchronization: KeInitializeEvent → pthread_cond, KeAcquireSpinLock → pthread_spin
- Device registration flows through Object Broker (Layer 1)
- SCM integration for SERVICE_KERNEL_DRIVER lifecycle

### 4.7 Event Emission

Non-blocking event emission to cortex via lock-free ring buffer.

**Ring buffer:** 4096 entries x 64 bytes = 256KB per PE process. Background thread drains to `/run/pe-compat/events.sock`. If cortex isn't listening, events silently drop. PE process never blocks.

**Events emitted:**
- PE_EVENT_LOAD, PE_EVENT_DLL_LOAD, PE_EVENT_UNIMPLEMENTED_API
- PE_EVENT_EXCEPTION, PE_EVENT_EXIT
- PE_EVENT_TRUST_DENY, PE_EVENT_TRUST_ESCALATE
- PE_EVENT_DRIVER_LOAD, PE_EVENT_DEVICE_CREATE

---

## 5. Layer 3 — Service Fabric

Enhanced SCM daemon managing Windows and Linux services under cortex orchestration.

### 5.1 Unified Service Model

**Windows service types:**
- SERVICE_WIN32_OWN_PROCESS → fork + peloader (separate PE process)
- SERVICE_WIN32_SHARE_PROCESS → svchost-like container (multiple services in one PE process)
- SERVICE_KERNEL_DRIVER → windrv_host in the hosting PE process
- SERVICE_FILE_SYSTEM_DRIVER → FUSE bridge

**Linux service bridge:**
- Wraps systemd units as Windows-queryable services
- `sc query "NetworkManager"` → `systemctl status NetworkManager`
- Bidirectional: Windows service → systemd unit created automatically
- Cross-type dependencies: Windows service can depend on Linux service

### 5.2 Service Health Monitor

- Heartbeat monitoring (configurable interval per service)
- Crash detection + restart with exponential backoff
- Resource usage tracking (CPU, memory, handle count)
- Emits SVC_EVENT_* to cortex event bus
- Cortex can override restart policy at runtime

### 5.3 Dependency Graph

- Topological sort for startup order
- Circular dependency detection (breaks cycle, logs warning)
- Parallel start for independent services
- Cortex can reorder based on priority and resource availability

### 5.4 Service Database

Persistent at `/var/lib/pe-compat/services/`. Survives reboots. JSON per service:
```json
{
  "name": "FooService",
  "display_name": "Foo Application Service",
  "type": "SERVICE_WIN32_OWN_PROCESS",
  "start_type": "SERVICE_AUTO_START",
  "binary_path": "/home/user/FooApp/service.exe",
  "dependencies": ["AppService2"],
  "restart_policy": "on_failure",
  "max_restarts": 3,
  "trust_history": { "last_score": 72, "incidents": 0 }
}
```

---

## 6. Layer 4 — AI Cortex

The central nervous system. Event-driven autonomous orchestrator.

### 6.1 Three Core Loops

**SENSE (Event Bus):**
Subscribes to all system events via `/run/pe-compat/events.sock` (datagram). Sources:
- trust.ko: score changes, token starvation, immune alerts, quarantine, apoptosis
- PE runtime: load, DLL load, unimplemented API, exception, exit, trust deny
- Object broker: object create, contention, registry write
- SCM: service start, crash, dependency failure
- Linux kernel: process exec (via fanotify), file open, network connect, OOM

**DECIDE (Decision Engine):**
Three-tier decision making:
1. **Policy rules** (fastest): static rules checked first. "Always allow games to access GPU." "Never allow unsigned drivers."
2. **Heuristics** (fast): behavioral patterns. "Process spawning >20 children in 5s = suspicious." "Network connection to known malware C2 = block."
3. **LLM reasoning** (slow, optional): for ambiguous cases. "This process is doing something unusual but not clearly malicious — what should I do?" Uses local GGUF model via llama-cpp-python. Only invoked when policy and heuristics are insufficient.

**ACT (Orchestrator):**
Executes decisions by commanding lower layers:
- trust.ko: modify subject scores, burn tokens, quarantine, release
- PE runtime: approve/deny loads, set budgets, kill processes
- Object broker: lock objects, modify registry, create devices
- SCM: start/stop/restart services, reorder dependencies
- systemd: manage Linux services
- Desktop: send notifications, launch apps, manage windows

### 6.2 Autonomy Controller

Autonomy level is per-domain and derived from the cortex's own trust score:

**Levels:**
```
Level 0 — OBSERVE:   Log everything, take no action
Level 1 — ADVISE:    Suggest actions, human approves via desktop notification or CLI
Level 2 — ACT+REPORT: Execute action, notify human after the fact
Level 3 — AUTONOMOUS: Full control, log only (human can review logs)
Level 4 — SOVEREIGN:  Can modify own trust parameters and policy rules
```

**Per-domain configuration (default):**
```
process_management:   2  (act + report)
network_access:       1  (advise)
trust_modification:   0  (observe only)
hardware_control:     1  (advise)
pe_execution:         2  (act + report)
service_management:   2  (act + report)
security_response:    2  (act + report)
system_configuration: 1  (advise)
```

**Score-based autonomy ceiling:**
```
Cortex trust score >= 90: maximum Level 4
Cortex trust score >= 70: maximum Level 3
Cortex trust score >= 50: maximum Level 2
Cortex trust score >= 30: maximum Level 1
Cortex trust score <  30: forced Level 0
```

Per-domain levels cannot exceed the ceiling. A cortex with score 65 can be Level 2 for pe_execution but not Level 3, regardless of configuration.

**Score dynamics:**
- +1: correct decision (human confirms or no incident after 24h)
- -5: false positive (human overrides a quarantine/deny)
- -10: missed threat (incident occurs after cortex allowed an action)
- -20: human explicitly lowers autonomy
- Fresh install starts at score 50 (Level 2 ceiling)

### 6.3 Cortex as Trust Subject

The cortex is itself governed by the Root of Authority:

```
Subject ID:     0 (reserved for AI cortex)
Domain:         TRUST_DOMAIN_AI
Auth Level:     TRUST_AUTH_SYSTEM
Token Budget:   10000 (high, essential service)
Regen Rate:     100/tick (fast, must not starve)

Chromosomes:
  A-segments (runtime):
    [0] uptime_hours
    [1] total_decisions
    [2] correct_decisions
    [3] false_positive_rate
    [4] mean_response_time_ms
    [5] human_override_count
    [6] events_processed
    [7] active_pe_processes
    [8..22] rolling behavioral hash

  B-segments (static):
    [0] binary_version_hash
    [1] config_hash
    [2] policy_hash
    [3] model_hash (LLM weights)
    [4] event_schema_version
    [5..22] reserved
```

### 6.4 Human Interface

When autonomy requires human input (Level 0 or 1, or Level 2+ for escalations):

**Desktop notification:** Toast popup with action buttons (Allow/Deny/Details)
**CLI interface:** `ai-cortex --pending` shows pending decisions
**Web dashboard:** Optional, served on localhost:8420 (replaces current passive REST API)
**REST API:** Retained for programmatic access, but now serves cortex state, not raw system commands

### 6.5 Proactive Behaviors

The cortex doesn't just react — it proactively manages the system:

- **Startup optimization:** Learns which services the user needs, pre-starts them
- **Resource balancing:** Shifts CPU/memory priority between PE processes based on foreground/background
- **Trust history:** Remembers which executables behaved well, fast-tracks their approval
- **Stub coverage tracking:** Tracks which unimplemented APIs are hit most often, prioritizes stub development
- **Security patrol:** Periodically scans for anomalous trust patterns across all subjects
- **Update management:** Checks for OS/driver updates, applies when autonomy permits
- **Game optimization:** Detects game launch, adjusts GPU governor, enables MangoHud, suppresses notifications

---

## 7. Event Bus Protocol

Universal event format used by all layers.

### 7.1 Event Frame

```
Fixed header (64 bytes):
  magic:        uint32  0x45564E54 ("EVNT")
  version:      uint16  1
  source_layer: uint8   (0=kernel, 1=broker, 2=pe_runtime, 3=scm, 4=cortex)
  event_type:   uint8   (per-source enum)
  timestamp_ns: uint64  (CLOCK_BOOTTIME nanoseconds)
  pid:          uint32  (source process ID)
  tid:          uint32  (source thread ID)
  subject_id:   uint32  (trust subject)
  sequence:     uint64  (monotonic per-source)
  payload_len:  uint16
  flags:        uint16  (URGENT=1, AUDIT=2, REPLY_REQUESTED=4)
  reserved:     uint8[12]

Variable payload:
  [payload_len bytes, event-specific]
```

### 7.2 Transport

```
/run/pe-compat/events.sock      Cortex event listener (datagram)
/run/pe-compat/objects.sock     Object broker (stream)
/run/pe-compat/scm.sock         Service fabric (stream)
/run/pe-compat/cortex-cmd.sock  Cortex command channel (stream)
```

PE processes use `libpe-event.so` (linked into peloader) to emit events. The library:
- Opens socket lazily on first event
- Writes datagrams (no connection, no blocking)
- Drops events if socket buffer is full (PE process never stalls)
- Batches events if rate exceeds 10,000/sec

### 7.3 Event Types

**Trust events (source=0):**
TRUST_SCORE_CHANGE, TRUST_TOKEN_STARVE, TRUST_IMMUNE_ALERT, TRUST_QUARANTINE, TRUST_APOPTOSIS, TRUST_ESCALATION_REQUEST, TRUST_TRC_STATE_CHANGE

**Object broker events (source=1):**
OBJ_CREATE, OBJ_DESTROY, OBJ_CONTENTION, REGISTRY_WRITE, REGISTRY_DELETE, DEVICE_ARRIVE, DEVICE_REMOVE, SESSION_CREATE

**PE runtime events (source=2):**
PE_LOAD, PE_DLL_LOAD, PE_UNIMPLEMENTED_API, PE_EXCEPTION, PE_EXIT, PE_TRUST_DENY, PE_TRUST_ESCALATE, PE_DRIVER_LOAD, PE_DEVICE_CREATE

**Service fabric events (source=3):**
SVC_INSTALL, SVC_START, SVC_STOP, SVC_CRASH, SVC_RESTART, SVC_DEPENDENCY_FAIL, SVC_HEALTH_CHECK

**Cortex events (source=4):**
CORTEX_DECISION, CORTEX_AUTONOMY_CHANGE, CORTEX_HUMAN_OVERRIDE, CORTEX_POLICY_UPDATE, CORTEX_HEALTH

---

## 8. Boot Sequence

```
1. BIOS/UEFI → GRUB (3s timeout)
2. Linux kernel loads
3. initramfs: plymouth splash (archimation theme)
4. trust.ko loads → /dev/trust created
5. systemd reaches multi-user.target
6. pe-objectd.service starts (Layer 1)
   → creates /run/pe-compat/objects.sock
   → loads registry hives from disk
   → populates device namespace defaults
7. scm-daemon.service starts (Layer 3)
   → creates /run/pe-compat/scm.sock
   → loads service database from /var/lib/pe-compat/services/
   → starts SERVICE_AUTO_START services
8. ai-cortex.service starts (Layer 4)
   → creates /run/pe-compat/events.sock + cortex-cmd.sock
   → registers as trust subject 0 (TRUST_DOMAIN_AI)
   → loads policy rules, autonomy config
   → begins listening for events
   → starts proactive behaviors (security patrol, resource monitor)
9. lightdm starts → XFCE session for user
10. Desktop shortcuts, MIME handlers, PE binfmt all ready
11. User double-clicks game.exe → full pipeline activates
```

---

## 9. File System Layout

```
/usr/bin/peloader                    PE loader binary
/usr/lib/pe-compat/dlls/             DLL stub .so files (39+)
/usr/lib/pe-compat/dxvk/             DXVK D3D→Vulkan translation
/usr/lib/pe-compat/vkd3d-proton/     VKD3D D3D12→Vulkan translation

/usr/bin/pe-objectd                  Object broker daemon
/usr/bin/scm-daemon                  Service Control Manager
/usr/bin/ai-cortex                   AI Cortex daemon
/usr/bin/sc                          Service control CLI

/var/lib/pe-compat/services/         Persistent service database
/var/lib/pe-compat/trust-history/    Per-executable trust history

/run/pe-compat/events.sock           Cortex event listener
/run/pe-compat/objects.sock          Object broker
/run/pe-compat/scm.sock              Service fabric
/run/pe-compat/cortex-cmd.sock       Cortex commands
/run/pe-compat/pipes/                Named pipe backing

~/.pe-compat/registry/HKCU/          User registry hive
~/.pe-compat/drives/c/               C: drive root
~/.pe-compat/drives/z/               Z: drive (home alias)
~/.pe-compat/trust/                  User trust preferences

/var/lib/pe-compat/registry/HKLM/    Machine registry hive
/var/lib/pe-compat/registry/HKU/     All users registry

/etc/pe-compat/cortex.toml           Cortex configuration
/etc/pe-compat/autonomy.toml         Per-domain autonomy levels
/etc/pe-compat/policy.toml           Security policy rules
/etc/pe-compat/backends.toml         Subsystem backend selection
```

---

## 10. Performance Budget

Target: <1% overhead vs running the same binary on Windows.

| Operation | Windows native | Our implementation | Overhead |
|-----------|---------------|-------------------|----------|
| Application code (math, logic) | CPU native | CPU native | 0% |
| API call (CreateFile, etc.) | ~200ns (syscall) | ~250ns (function + POSIX syscall) | ~50ns |
| Trust gate check (cached) | N/A | ~5ns (single branch) | 5ns |
| Trust gate check (miss) | N/A | ~2μs (ioctl) | 2μs (rare) |
| Named object create | ~1μs (kernel) | ~3μs (broker socket) | 2μs |
| Named object wait | ~100ns (futex) | ~100ns (futex on shared page) | 0% |
| D3D11 draw call | ~500ns | ~550ns (DXVK Vulkan translation) | ~10% |
| Event emission | N/A | ~50ns (lock-free ring write) | 50ns |

The critical insight: trust gate checks and event emission are on every API call, but at 5ns and 50ns respectively they're negligible compared to the API call itself (~250ns). The hot path is API translation, which is a direct function call — same address space, no IPC.

---

## 11. What Changes From Current Implementation

### New components to build:
1. **pe-objectd** (Layer 1): ~3,000 lines C. Named objects + registry hosting + device namespace + session manager.
2. **AI Cortex rewrite** (Layer 4): ~5,000 lines Python. Event bus + decision engine + orchestrator + autonomy controller. Replaces current passive ai-control daemon.
3. **libpe-event** (shared library): ~500 lines C. Lock-free ring buffer + event emission for PE processes.
4. **Subsystem backend interfaces**: ~200 lines C per interface. Formalize existing code into pluggable backends.

### Components to modify:
1. **kernel32_sync.c**: Named objects delegate to object broker instead of intra-process hash table.
2. **advapi32_registry.c**: Registry operations delegate to object broker.
3. **main.c**: PE load request/approval handshake with cortex before loading.
4. **scm_daemon.c**: Service health monitor + cortex event emission + Linux service bridge.
5. **trust_gate.c**: Active cache invalidation via shared memory flag.

### Components unchanged:
- trust.ko (kernel module) — already complete
- PE parser, mapper, relocator — working
- DLL stubs (39 .so files) — working, extend incrementally
- SEH/VEH exception handling — working
- WDM driver host — working
- Graphics/audio backends — working, formalize interfaces

---

## 12. Implementation Order

Phase 1 — Foundation:
  1. Event bus protocol (libpe-event + event frame format)
  2. Object broker (pe-objectd) with named objects
  3. Registry hosting migration to broker

Phase 2 — Cortex:
  4. AI Cortex event loop (SENSE)
  5. Decision engine with policy rules (DECIDE)
  6. Orchestrator commands (ACT)
  7. Autonomy controller

Phase 3 — Integration:
  8. PE loader → cortex handshake (approval before load)
  9. Named object delegation (kernel32_sync.c → broker)
  10. Service fabric enhancements (health monitor, Linux bridge)

Phase 4 — Polish:
  11. Trust history persistence
  12. Subsystem backend formalization
  13. Human interface (desktop notifications, CLI, web dashboard)
  14. Performance profiling and optimization
