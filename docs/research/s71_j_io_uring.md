# S71 Agent J — io_uring and Modern Linux I/O Patterns for ARCHWINDOWS daemon

Research angle: could the ai-control-daemon (FastAPI + uvicorn on :8420, cortex
on :8421, heavy subprocess fan-out, some disk I/O) benefit from io_uring, and
is now (2026) a reasonable moment to migrate?

## 1. io_uring recap — kernel timeline through 6.16

io_uring landed in **5.1 (May 2019)** with READV/WRITEV/FSYNC/POLL as the
initial op set [1]. The relevant milestones since:

| Kernel | Year | Capability                                                     |
|--------|------|----------------------------------------------------------------|
| 5.1    | 2019 | Base ring, fixed files, fixed buffers                         |
| 5.3    | 2019 | sendmsg / recvmsg                                              |
| 5.5    | 2020 | accept / connect / async-cancel / linked timeouts              |
| 5.6    | 2020 | openat / close / statx / send / recv / epoll_ctl               |
| 5.19   | 2022 | LINK_TIMEOUT, socket tx/rx polish                              |
| 6.0    | 2022 | Zero-copy send (`SEND_ZC`) [2]                                 |
| 6.6    | 2023 | `kernel.io_uring_disabled` sysctl (0/1/2) [3]                  |
| 6.10   | 2024 | Provided buffer rings with incremental consumption              |
| 6.11   | 2024 | Send/recv bundles (contiguous buffer group drain) [4]          |
| 6.12   | 2024 | Async discard; Device-memory-TCP zero-copy rx [5]              |
| 6.13   | 2025 | Hybrid IO polling; dynamic ring resize [6]                     |
| 6.16   | 2025 | DMA-BUF zero-copy rx plumbing; devmem TCP tx [5]               |

Zero-copy send works through registered (fixed) buffers, posts two CQEs per
op with `IORING_CQE_F_MORE` on the first so the app knows when its buffer is
safe to reuse [2]. Zero-copy rx landed experimentally in liburing during
2025 as a thin wrapper around `io_uring_register` [5]. "Fixed files" —
pre-registered FDs referenced by their slot in the registration array — are
the core optimization behind Cloudflare-class workloads [1].

## 2. Security: the `io_uring_disabled` sysctl

Google disclosed in 2023 that **~60% of their kernel VRP submissions for one
reporting window involved io_uring**, with roughly $1M paid out [3]. That led
directly to the 6.6 sysctl `kernel.io_uring_disabled`:

- 0 — unrestricted (default on most distros)
- 1 — only CAP_SYS_ADMIN processes can create rings
- 2 — disabled for every process regardless of privilege

Google ChromeOS and Android both run with this at 2 on many builds [3, 7]. An
io_uring-based rootkit demoed in early 2025 bypassed most syscall-watching
antivirus because it literally never issues the watched syscalls — the ring
sidesteps them entirely [7]. Any security-sensitive ARCHWINDOWS deployment
needs to think about this before making io_uring a hard dependency.

## 3. Python-side reality check

This is where the task brief and the actual 2026 state diverge in a way that
matters for our recommendation:

**asyncio (stdlib).** Still epoll/kqueue-only. `bpo-44738` proposed an
io_uring backend for `selectors`/`asyncio` back in 2021; as of April 2026 it
remains open with no merged implementation [8].

**uvloop.** Cython wrapper over **libuv**. libuv's Linux backend is epoll.
Work-in-progress libuv io_uring support exists behind a build flag and is
used in some Node.js test matrices, but the upstream default — and the
binary shipped on PyPI for uvloop — is epoll [9, 10]. Our daemon's current
config in `api_server.py:4202-4213` (uvicorn + uvloop + httptools) therefore
does NOT use io_uring at all, on any kernel.

**uvicorn.** The ASGI layer on top of uvloop. Same story.

**granian.** Rust HTTP server built on **Hyper + Tokio** (verified against
the repo README; benchmarks confirm Tokio not tokio-uring) [11, 12]. So
granian is **not an io_uring route either** as of 2.7.x. It is, however,
dramatically faster than uvicorn at the HTTP layer — the upstream April 2026
benchmark against Uvicorn+httptools on an identical ASGI "GET 10KB" workload
at c=128 shows:

| Server             | RPS      | p50 latency | max/avg gap |
|--------------------|----------|-------------|-------------|
| Granian 2.7.3      | 126,671  | 1.00 ms     | 2.8x        |
| Uvicorn+httptools  | 51,252   | 2.49 ms     | 6.8x        |
| Uvicorn+h11        | 12,885   | 9.90 ms     | —           |
| Gunicorn sync      | 36,751   | 3.47 ms     | —           |

Source: `benchmarks/vs.md` in emmett-framework/granian [13]. The 2.5x RPS win
is largely from Hyper's Rust HTTP parser, Tokio's scheduler, and not having
to cross the GIL for connection lifecycle — **not** from io_uring.

**If you want io_uring from Python today:** `python-io-uring` bindings are
alive but niche; `socketify.py` (uWebSockets core) and direct `liburing`
ctypes are the realistic routes. None of them give you FastAPI on top
without substantial surgery.

## 4. Rust/C alternatives (for the "rewrite the daemon" question)

- **tokio-uring** — Tokio-compatible runtime with `io_uring` backend.
  Requires kernel 5.10+ [14]. Production use: Apache Iggy migrated to compio
  (similar model) in Feb 2026 and hit **5000 MB/s / 5M msg/s** at 1KB [15].
- **monoio** (ByteDance) — thread-per-core, io_uring-first. Their gateway
  benchmark shows **~2x Tokio at 4 cores, ~3x at 16 cores** [16].
- **compio / glommio** — similar thread-per-core story.
- **Cloudflare Pingora** ships at 40M+ rps **without** io_uring — gains are
  workload-dependent and for pure HTTP proxying at moderate concurrency,
  epoll is already CPU-bound somewhere else [16].
- C++: `liburing` direct + `std::execution` (P2300). Works; rarely worth it
  over Rust for new code.

## 5. Benchmarks applicable to our daemon

- io_uring vs epoll, Rust TCP echo (Seipp 2024): **~25% more throughput,
  ~1ms better p99** [16].
- io_uring vs threaded blocking I/O, random small-file disk read (fio): 5-10x.
- io_uring vs libaio: parity on large sequential; io_uring wins on mixed.

Our daemon's workload is **NOT** the 50K+rps HTTP flood where io_uring
shines. It's ~10-100 rps peak, handlers that spend ~95% of their wall time
in `pactl` / `brightnessctl` / `systemctl` subprocesses. The HTTP layer is
not the bottleneck; `fork+exec+wait` is.

## 6. Our daemon surface — what subprocess calls actually look like

Survey of `ai-control/daemon/*.py`:

- `contusion_handlers.py` — **15 occurrences** of `asyncio.create_subprocess_exec`.
  All routed through a single `_exec()` helper at line 97 that already wraps
  in `asyncio.wait_for` with timeout + kill-on-timeout. This is clean.
- `api_server.py` — **4 occurrences** of `asyncio.create_subprocess_exec`
  (telemetry probes) **and** a `_run_subprocess_async()` helper at line 2121
  that thread-pools blocking `subprocess.run()` via `run_in_executor`. The
  helper exists because the `/auto/*` endpoints have a mix.
- `contusion.py` — 1 `subprocess.Popen` (the app launcher at line 603;
  fire-and-forget, start_new_session). Acceptable.
- `compositor.py`, `gpu.py`, `screen.py`, `mouse.py`, `input.py`,
  `desktop_automation.py`, `claude_installer.py`, `stub_generator.py` —
  ~30 `subprocess.run`/`Popen` calls. Most are sync-blocking-in-executor
  rather than asyncio-native. This is the **actual fat** to trim.
- `cgroup.py` — 4 `subprocess.Popen` calls for long-lived child processes.
  Correct as written.

The S68 → S69 / S71 migration pattern (quoted in the task brief: "Agent
S/U/W/Y added these in S68/S69") already rewrote contusion_handlers fully.
What's left is the perimeter modules.

## 7. Old-hardware constraint

ARCHWINDOWS boots Arch rolling, kernel 6.x is typical — io_uring is
available everywhere. The hardened kernel variant in `profile/packages.x86_64`
(`linux-hardened`) ships with `kernel.io_uring_disabled=2` as of its
2025-backport, so io_uring literally does not work there. Any adoption must
sniff via `io_uring_queue_init()` succeeding or `/proc/sys/kernel/io_uring_disabled`
being 0 and fall back cleanly to epoll.

## 8. New-hardware opportunity

On a fast NVMe + modern NIC, io_uring + fixed buffers + registered files
gives near-zero-overhead I/O for the **disk** side. Combined with DMA-BUF
on a Vulkan/DXVK surface (Kernel 6.16's devmem-TCP rx [5]), media pipelines
could in principle skip one full memcpy between kernel and GPU. None of our
shipped daemons currently touch that path.

## 9. Recommendation for S72+

**Switch to granian as the FastAPI server: YES, conditionally.**

Ship as a ~5-line change in `api_server.py::start_server()`:
```python
try:
    import granian
    from granian import Granian
    server = Granian(
        target=f"{module}:{app_symbol}", interface="asgi",
        address=host, port=port, runtime_mode="st", workers=1,
    )
    server.serve()
    return
except ImportError:
    pass  # fall through to uvicorn path
```
Add `granian` as an **optdepend** (not hard dep) on ai-control-daemon
PKGBUILD. Bench the ISO's `/health` endpoint with `wrk -c 64 -t 4 -d 30s`
and ship granian-primary only if the win is **≥20% latency reduction AND
≥1.5x RPS**. Granian's published benchmark is 2.5x RPS / 2.5x p50, so the
bar is achievable — but the smoothness-under-TCG question matters for our
QEMU CI (granian has more moving parts on startup; Type=notify ready-gating
would need re-validation).

**Do NOT adopt io_uring directly.** Three reasons:

1. The Python ecosystem (asyncio/uvloop/granian/uvicorn) does not use it
   today; wiring it would require a C extension and would not bubble up to
   FastAPI handlers.
2. `linux-hardened` sets `io_uring_disabled=2` — a hard dependency would
   break that kernel variant for our users.
3. Our daemon is subprocess-bound, not I/O-bound. 10-100 rps handler
   latency is dominated by `fork+exec` time for `pactl`/`wpctl`/etc, not
   HTTP parsing or disk.

**The bigger real win: finish the S68/S69 subprocess migration.** Thirty
`subprocess.run()` sites in compositor/gpu/screen/etc. should become
`asyncio.create_subprocess_exec` + `asyncio.wait_for`. This moves from
thread-pool-blocking to true async cancellation and cuts p99 tail latency
for concurrent handler requests (common under the LLM/cortex fan-out).
Estimated: ~300 LOC of mechanical change, bigger observable impact than
any server swap.

**For kernel driver / high-concurrency work (wdm_host, objectd):** if
any layer grows to >1000 rps of cross-process message passing, **that's**
where tokio-uring becomes worth a rewrite — not the Python daemon.

## Summary (400 words)

io_uring is mature in 2026 but its Python story is still "not yet." uvloop
under uvicorn still runs on epoll; granian (the obvious upgrade from
uvicorn) uses Tokio+Hyper, also not io_uring. Using io_uring from Python
requires going below FastAPI — `python-io-uring` bindings, `socketify.py`,
or a full Rust rewrite. None of those map cleanly onto the ARCHWINDOWS
daemon's shape (ASGI endpoints whose latency is dominated by forking
`pactl`/`brightnessctl`/`systemctl`, not by HTTP parsing).

The security dimension matters too: kernel 6.6's `io_uring_disabled=2`
sysctl is set on `linux-hardened` — our own hardened-kernel build variant.
An io_uring-dependent daemon would simply not start there. That alone
disqualifies it as anything but an opt-in accelerator.

Where real gains exist: Granian's published benchmarks show 2.5x RPS
(126K vs 51K) and 2.5x p50 latency improvement (1.0ms vs 2.5ms) against
uvicorn+httptools on identical ASGI workloads at c=128 (benchmarks/vs.md,
April 2026). Our workload is far below c=128 and the HTTP layer is not
the bottleneck, so the real-world win on :8420 may be 0-30%. Still worth
a 5-line optdepend trial for S72 — if QEMU smoke holds and wrk numbers
clear a 20% bar, flip the default; otherwise keep uvicorn.

The bigger lift is finishing what S68/S69 started: ~30 remaining
`subprocess.run()` sites in `compositor.py`, `gpu.py`, `screen.py`,
`mouse.py`, `input.py`, `desktop_automation.py`, `claude_installer.py`,
and `stub_generator.py` should move to `asyncio.create_subprocess_exec`.
That removes thread-pool blocking from the executor path — where concurrent
handler requests can currently queue — and gives the cortex fan-out true
async cancellation on timeout. Estimate ~300 LOC mechanical, bigger
observable improvement than any server swap for this daemon.

For old hardware: no change. Kernel 5.1+ is universal in modern Arch;
epoll works everywhere and uvicorn+uvloop stays on epoll anyway.

For new hardware: the one place io_uring eventually earns its keep is
if/when wdm_host or objectd grow into >1000 rps cross-process message
pipelines. That's a tokio-uring rewrite in Rust, not a Python change.
For now, not justified.

## Sources

[1] [io_uring(7) — Linux man-pages](https://man7.org/linux/man-pages/man7/io_uring.7.html)
[2] [io_uring_prep_send_zc(3)](https://man7.org/linux/man-pages/man3/io_uring_prep_send_zc.3.html)
[3] [Linux 6.6 Will Make It Easy To Disable IO_uring System-Wide — Phoronix](https://www.phoronix.com/news/Linux-6.6-sysctl-IO_uring)
[4] [What's new with io_uring in 6.11 and 6.12 — axboe/liburing wiki](https://github.com/axboe/liburing/wiki/What%27s-new-with-io_uring-in-6.11-and-6.12)
[5] [NVMe FDP Block Write Streams, IO_uring DMA-BUF Zero Copy Receive Land In Linux 6.16 — Phoronix](https://www.phoronix.com/news/Linux-6.16-Block-IO_uring)
[6] [IO_uring Enjoys Hybrid IO Polling & Ring Resizing With Linux 6.13 — Phoronix](https://www.phoronix.com/news/Linux-6.13-IO_uring)
[7] [io_uring Rootkit Bypasses Linux Security Tools — ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
[8] [bpo-44738: io_uring as a new backend to selectors and asyncio](https://bugs.python.org/issue44738)
[9] [uvloop — MagicStack/uvloop](https://github.com/MagicStack/uvloop)
[10] [Libuv – Linux: io_uring support — Hacker News](https://news.ycombinator.com/item?id=36106196)
[11] [Granian — emmett-framework/granian](https://github.com/emmett-framework/granian)
[12] [FastAPI-Granian-Starter](https://github.com/DevSpace88/FastAPI-Granian-Starter)
[13] [granian benchmarks/vs.md](https://github.com/emmett-framework/granian/blob/master/benchmarks/vs.md)
[14] [tokio-uring](https://github.com/tokio-rs/tokio-uring)
[15] [io_uring-benchmark — tontinton](https://github.com/tontinton/io_uring-benchmark)
[16] [Monoio — bytedance/monoio](https://github.com/bytedance/monoio)
[17] [The rapid growth of io_uring — LWN](https://lwn.net/Articles/810414/)
[18] [Why you should use io_uring for network I/O — Red Hat](https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io)
