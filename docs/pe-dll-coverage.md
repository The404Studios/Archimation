# PE DLL Coverage Map

This document lists every DLL stub shipped in `pe-loader/dlls/` with its
coverage level, source file count, approximate lines-of-code, and short notes
on what does and does not work. The coverage labels are:

- **Full** -- the stub implements the real Win32 behaviour for the surface
  area that non-pathological binaries touch. Edge cases (obscure flags, rare
  enumerations) may still route through `ERROR_NOT_SUPPORTED` or similar, but
  the stub is not a placeholder.
- **Partial** -- the common-path behaviour is implemented; less-common entry
  points return valid error codes (`E_NOTIMPL`, `ERROR_CALL_NOT_IMPLEMENTED`,
  `FALSE` with `GetLastError()` set) so callers can fall back cleanly.
- **Stub-only** -- the DLL exists to satisfy load-time imports. Functions
  return a plausible success value (0, `S_OK`, `TRUE`) without performing
  the underlying action. Binaries that depend on observable side effects will
  misbehave.

All DLLs are built to `pe-loader/dlls/libpe_<name>.so` and installed to
`/usr/lib/pe-compat/`. The import resolver in `pe-loader/loader/pe_import.c`
maps Windows DLL names (including `api-ms-win-core-*` API sets) onto these
`.so` files.

**Total DLLs audited: 40** (39 production DLLs + the `common/` and `extra/`
helpers; `extra_stubs.c` is a catch-all used for exports that do not justify
their own DLL directory yet).

## Coverage Table

| DLL            | Source files | LOC   | Level    | Notes                                                                               |
| -------------- | ------------ | ----- | -------- | ----------------------------------------------------------------------------------- |
| kernel32       | 26           | 17011 | Full     | Largest DLL. File/process/thread/memory/sync/IOCP/fibers/time/toolhelp/threadpool   |
| user32         | 6            | 6179  | Partial  | Window/message/menu/dialog/input/display. GDI-lite only; no RAW input               |
| ntdll          | 7            | 4755  | Partial  | File/memory/process/thread/sync/exception/main. Rtl aliases, many Nt* still stub    |
| d3d            | 8            | 4575  | Partial  | d3d9/10/11/12 + dxgi + dxvk_bridge + dinput + d3dcompiler + d3dx. DXVK/VKD3D-backed |
| msvcrt         | 5            | 4178  | Full     | stdio/string/math/heap/except. Also backs ucrtbase via forwarders                   |
| gdi32          | 4            | 3817  | Partial  | bitmap/dc/font/text. No printing, no metafiles, limited path rendering              |
| advapi32       | 5            | 3451  | Partial  | credman/crypto/registry/security/service. CAPI cert store minimal                   |
| winhttp        | 1            | 2196  | Partial  | libcurl-backed GET/POST. No WinHTTP sessions with proxy auto-config                 |
| dsound         | 2            | 2078  | Partial  | DirectSound + XAudio2 output via PipeWire. No capture (returns `E_NOTIMPL`)         |
| shlwapi        | 1            | 1525  | Full     | Path/string helpers. Session 37 fixed signed/unsigned wraps                         |
| ntoskrnl       | 6            | 1416  | Partial  | io/mm/ps/registry/rtl/sync. Only what shimmed anti-cheat drivers actually call      |
| msi            | 2            | 1329  | Stub-only| vcredist handler + MSI installer stubs. Refuses unknown MSI tables                  |
| common         | 3            | 1242  | n/a      | Shared helpers: casefold, wchar_util, dll_common                                    |
| ws2_32         | 1            | 1095  | Partial  | Berkeley socket mapping, WSAEventSelect. No RIO, no overlapped AcceptEx             |
| shell32        | 1            | 882   | Partial  | ShellExecute, SHGetFolderPath, DragQueryFile. No IShellFolder                       |
| ole32          | 3            | 806   | Partial  | com/classregistry/shell. In-proc only. `CoCreateInstanceEx` returns `E_NOTIMPL`     |
| oleaut32       | 1            | 791   | Partial  | VARIANT, BSTR, SafeArray. No typelib marshalling                                    |
| dstorage       | 1            | 754   | Partial  | DirectStorage via io_uring. Reflink copy path, short-read fix (Session 29)          |
| secur32        | 1            | 469   | Stub-only| SSPI surface. NTLM/Kerberos return `SEC_E_UNSUPPORTED_FUNCTION`                     |
| bcrypt         | 1            | 453   | Partial  | AES/SHA/RSA via openssl. No DPAPI, no elliptic curves beyond P-256                  |
| combase        | 1            | 412   | Stub-only| WinRT activation. `RoActivateInstance` returns `E_NOTIMPL`                          |
| mscoree        | 1            | 409   | Stub-only| CLR host refuses `_CorExeMain`. .NET is explicitly not supported                    |
| crypt32        | 1            | 396   | Partial  | X.509 cert parsing, no CRL, no PFX import                                           |
| extra          | 1            | 362   | Stub-only| Catch-all: exports that have not been moved to a dedicated DLL yet                  |
| iphlpapi       | 1            | 354   | Partial  | `GetAdaptersAddresses`, `GetIfTable` from /proc/net. No IPv6 scope zones            |
| winmm          | 1            | 336   | Partial  | timeGetTime, timeSetEvent. No MIDI, no waveOut (dsound handles audio)               |
| setupapi       | 1            | 314   | Stub-only| `SetupDiGetClassDevs` returns empty device list. DRM drivers bypass this            |
| userenv        | 1            | 310   | Partial  | `GetUserProfileDirectory` maps to `$HOME`. No roaming profiles                      |
| psapi          | 1            | 272   | Partial  | `EnumProcesses`, `GetModuleInformation`. Uses /proc; 34 fake procs via anti-cheat   |
| comctl32       | 1            | 268   | Stub-only| Common-controls init is a no-op. `InitCommonControls` returns TRUE, nothing drawn   |
| dbghelp        | 1            | 265   | Stub-only| `SymFromAddr`, `StackWalk64` return failure. Crash dumps unsupported                |
| dwmapi         | 1            | 239   | Stub-only| `DwmExtendFrameIntoClientArea` etc. succeed silently. No actual compositing        |
| ndis           | 1            | 238   | Stub-only| Kernel-mode NDIS surface for shimmed drivers. Passes type-of-registration checks    |
| steamclient    | 1            | 234   | Stub-only| `SteamAPI_Init` returns TRUE. No real Steam integration; games see Steam as "up"   |
| comdlg32       | 1            | 221   | Partial  | GetOpenFileName routes to GTK/Qt dialog via xdg-open shim. Limited filter support   |
| hal            | 1            | 177   | Stub-only| HAL exports for kernel-mode shims (KeGetCurrentIrql, etc.)                          |
| version        | 1            | 151   | Partial  | VerQueryValue on PE resource block. Reads the target's own version table            |
| winpix         | 1            | 119   | Stub-only| PIX debug-marker exports. `PIXBeginEvent` is a no-op                                |
| wer            | 1            | 104   | Stub-only| Windows Error Reporting. `WerRegisterFile` returns `S_OK`, does nothing             |
| imm32          | 1            | 93    | Stub-only| IME surface. Always reports "no IME". Roman-alphabet input works via user32        |
| shcore         | 1            | 85    | Stub-only| DPI awareness: `SetProcessDpiAwareness` returns `S_OK`, process is always PerMon   |

## Per-DLL Notes

### Fully implemented

- **kernel32** (`pe-loader/dlls/kernel32/`) -- 26 files split by subsystem:
  async IO, console, debug, environment, error codes, fibers, file I/O, find-file,
  IOCP, job objects, locale, memory (VirtualAlloc/Protect), module loader,
  notifications, path, pipes, process, resource, SRW locks, strings (MultiByteToWideChar
  and family), sync primitives, threads, threadpool, time, toolhelp32. This is the
  load-bearing DLL: most binaries fail or succeed based on how complete this is.

- **msvcrt** (`pe-loader/dlls/msvcrt/`) -- 5 files covering stdio, strings, math,
  heap, and exception handling. Forwarders in `pe_import.c` also route ucrtbase
  and the `api-ms-win-crt-*` API sets here. Approximately 120 additional `ms_abi`
  wrappers live in `pe_find_crt_wrapper()` inside the loader to bridge glibc
  functions (which use the System V ABI) into Windows calling convention.

- **shlwapi** (`pe-loader/dlls/shlwapi/shlwapi_path.c`) -- Path helpers are
  heavily used by installers and game launchers. Session 37 fixed five signed-to-unsigned
  size wraps; Session 28 added 23 new exports.

### Partially implemented

- **user32** -- Window creation, message pump, menus, dialogs, keyboard/mouse
  input, display enumeration. Raw HID input (`GetRawInputData`) is not implemented;
  use XInput for controllers. Session 25 fixed a UAF in `DestroyWindow` timer cleanup.

- **ntdll** -- The Rtl alias layer is complete (most `Rtl*` forward to equivalent
  kernel32/libc functions). Native Nt/Zw syscalls that shimmed drivers rely on are
  implemented; user-mode Nt* calls (`NtCreateFile`, `NtQueryInformationProcess`)
  cover the common query classes only.

- **d3d** -- 8 files for the DirectX family:
  - `d3d9_device.c` -- D3D9 device + vtable, routes to DXVK
  - `d3d_stubs.c` -- D3D10/11 COM surface
  - `d3dcompiler_stubs.c` -- HLSL compiler stubs (DXVK brings its own shader compile)
  - `d3dx_stubs.c` -- Legacy D3DX helpers; most return `E_NOTIMPL`
  - `dinput_stubs.c` -- DirectInput 8; returns `DIERR_UNSUPPORTED` for force feedback
  - `dxgi_factory.c` / `dxgi_format_cache.c` -- Factory, adapter enum, format probe
  - `dxvk_bridge.c` -- Load-time bridge into DXVK's `dxvk_native`
  Session 32 added Vulkan-feature-level probes so weak GPUs get honest `E_NOTIMPL`
  instead of a crash deep in DXVK.

- **advapi32** -- Registry (backed by in-memory hive + 80+ prepopulated keys),
  service control (forwards to the SCM daemon), credential manager (stub, returns
  empty), crypto (legacy CAPI, forwards to bcrypt where possible), security
  descriptors (always returns a permissive SID).

- **gdi32** -- Device contexts, bitmaps, fonts, text rendering. Session 27 added
  the GDI stock font table. Printing (`CreateDC("WINSPOOL", ...)`) is not
  implemented and returns NULL.

- **ws2_32** -- Winsock 2 mapped onto Berkeley sockets. Session 37 fixed a
  thread-unsafe `gethostbyname` by switching to `gethostbyname_r` + TLS. No
  Registered I/O, no `AcceptEx`-style overlapped completion; synchronous +
  `WSAEventSelect` paths work.

- **winhttp / wininet** -- Backed by libcurl. Basic auth, TLS, redirects work.
  Proxy auto-config (PAC), NTLM, and Kerberos do not.

- **bcrypt** -- Symmetric AES (CBC, GCM), SHA-1/256/384/512, HMAC, RSA (up to
  4096), P-256 ECDSA -- all via OpenSSL. No DPAPI (`BCryptProtect*`), no hardware
  TPM keys.

- **ole32 / oleaut32 / combase** -- COM is partial: `CoInitialize`,
  `CoCreateInstance` for registered in-proc classes, `IUnknown`, `IDispatch`,
  `IStream` in memory, VARIANT and BSTR helpers. There is no DCOM, no
  out-of-process server support, no WinRT activation beyond returning `E_NOTIMPL`.

### Stub-only

These DLLs exist to satisfy import-resolution but implement no meaningful
behaviour. They return plausible success values so that binaries load and run;
any binary that relies on the actual effect of these APIs will misbehave
silently. Known stub-only DLLs: `combase`, `comctl32`, `dbghelp`, `dwmapi`,
`extra`, `hal`, `imm32`, `mscoree`, `msi`, `ndis`, `secur32`, `setupapi`,
`shcore`, `steamclient`, `wer`, `winpix`.

The largest practical impact is:

- **mscoree** stub-only means no .NET Framework or .NET Core binaries. Use a
  Linux-native .NET runtime or Wine.
- **msi** stub-only means MSI installers do not actually install (except the
  vcredist fast-path). Use `wine msiexec` for MSI packages.
- **comctl32** stub-only means controls created by the common-controls library
  (e.g. TreeView, ListView) may not render. Plain user32 windows still work.
- **dbghelp** stub-only means crash dumps and symbol resolution are unavailable.
  The loader's own crash path emits Linux-style backtraces instead.

## Verification

To confirm which DLL stubs are present and what symbols they export on a given
system, run:

```
peloader -D <your.exe>
```

This performs import resolution and prints per-DLL coverage without running
the binary. See `docs/pe-compat.md` for how to read the output.

## Source-file entry points

If you need to jump directly to implementation code:

- kernel32: `pe-loader/dlls/kernel32/kernel32_*.c` (26 files)
- user32:   `pe-loader/dlls/user32/user32_{window,message,menu,dialog,input,display}.c`
- ntdll:    `pe-loader/dlls/ntdll/ntdll_{main,file,memory,process,thread,sync,exception}.c`
- d3d:      `pe-loader/dlls/d3d/{d3d9_device,d3d_stubs,d3dcompiler_stubs,d3dx_stubs,dinput_stubs,dxgi_factory,dxgi_format_cache,dxvk_bridge}.c`
- msvcrt:   `pe-loader/dlls/msvcrt/msvcrt_{stdio,string,math,heap,except}.c`
- advapi32: `pe-loader/dlls/advapi32/advapi32_{credman,crypto,registry,security,service}.c`
- ntoskrnl: `pe-loader/dlls/ntoskrnl/ntoskrnl_{io,mm,ps,registry,rtl,sync}.c`

The import-name-to-`.so` mapping lives in `pe-loader/loader/pe_import.c`
(`g_dll_mappings` and related tables) -- ~190 entries covering raw DLL names,
API-set contracts (`api-ms-win-core-*`), and forwarders.
