# libtrust-wine-shim

`libtrust_wine_shim.so` is a tiny `LD_PRELOAD` shim injected into Wine whenever
the pe-loader detects a 32-bit PE32 binary and hands off to `/usr/bin/wine`
(Session 74, Agent 1).  The pe-loader `execve()`s Wine with
`LD_PRELOAD=/usr/lib/libtrust_wine_shim.so` and `TRUST_SHIM_PID=<caller-pid>`;
the shim intercepts `open(2)`, `openat(2)`, and `execve(2)` via
`dlsym(RTLD_NEXT, ...)`, consults `/dev/trust` via `TRUST_IOC_CHECK_CAP` on
first use, and denies the call with `errno = EACCES` when the trust kernel
refuses the capability.  This preserves trust-gated execution for the 30%+ of
the Windows corpus that is still 32-bit (Steam's bootstrapper, older games,
most pre-2015 installers) without rebuilding a second 32-bit PE loader.  The
shim is fail-open if `/dev/trust` is unavailable (lets Wine run unmodified on
hosts without trust.ko), and honours `AICONTROL_WINE_SHIM_DISABLE=1` for
debugging.
