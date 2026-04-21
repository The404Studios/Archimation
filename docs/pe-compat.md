# PE Loader Compatibility Reference

## Overview

The `peloader` binary in this distribution runs **PE32+ x86_64** Windows executables
natively on Linux without Wine or a Windows kernel. The loader parses the PE image,
maps sections, applies base relocations and thread-local storage callbacks, resolves
imports against the `.so` DLL stubs shipped in `/usr/lib/pe-compat/`, walks exception
directories for SEH, and calls the image entry point under the Windows x86_64
(`ms_abi`) calling convention. There is no emulation layer: the Windows code runs as
native instructions in the same process.

The loader is **not a Wine replacement**. It is a complement: Wine targets broad Win32
source compatibility across decades of APIs, while `peloader` targets a narrower,
more opinionated surface -- modern x86_64 user-mode binaries, DirectX games via DXVK
and VKD3D, and a handful of anti-cheat shims. **32-bit PE (PE32) binaries are
explicitly unsupported** and exit with code 4 and a `wine "<exe>"` suggestion; see
`pe-loader/loader/main.c:533`. Managed .NET assemblies, UWP/WinRT apps, kernel-mode
drivers other than the shimmed anti-cheat variants, and anything requiring a real
Windows session are out of scope.

## Runtime Requirements

The PE loader and its DLL stubs assume the following stack on the host:

| Component                                   | Purpose                                             |
| ------------------------------------------- | --------------------------------------------------- |
| glibc 2.38+ (x86_64)                        | pthreads, dlopen, `ms_abi` attribute support        |
| Linux kernel with `binfmt_misc`             | Direct `./foo.exe` invocation via MZ magic          |
| Vulkan 1.3 driver (NVIDIA / Mesa / lavapipe)| Required for D3D9/10/11/12 translation              |
| DXVK (D3D9/10/11)                           | Installed under `/usr/lib/pe-compat/dxvk/`          |
| VKD3D-Proton (D3D12)                        | Installed under `/usr/lib/pe-compat/vkd3d/`         |
| PipeWire or PulseAudio                      | Backs DirectSound/XAudio2 via `dsound_audio.c`      |
| X11 or XWayland                             | Backs `user32`/`gdi32` windowing                    |
| openssl, zstd, libcurl                      | Used by bcrypt, winhttp, crypt32 stubs              |

GPU driver VRAM and feature level gate what actually works: D3D9/11 typically load on
any Vulkan 1.3 GPU; D3D12 requires Vulkan 1.3 + `VK_KHR_timeline_semaphore` and VRAM
sufficient for the game. On old hardware (e.g. GT218-class) the D3D stubs report
`E_NOTIMPL` for unsupported feature levels rather than silently falling back.

## Supported Features

| Feature                                                   | Status   | Notes                                                                              |
| --------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------- |
| Win32 console (CRT `printf`, `ExitProcess`)               | Full     | 5-file msvcrt, ~120 ms_abi CRT wrappers                                            |
| Win32 GUI (`MessageBoxA`, `CreateWindowExA`)              | Partial  | user32 core done, GDI drawing limited                                              |
| Direct3D 9                                                | Partial  | DXVK-backed, `d3d9_device.c`                                                       |
| Direct3D 10 / 11                                          | Partial  | DXVK-backed, `d3d_stubs.c` + `dxvk_bridge.c`                                       |
| Direct3D 12                                               | Partial  | VKD3D-Proton backed; feature-level probes return `E_NOTIMPL` on weak GPUs          |
| DXGI                                                      | Partial  | swap chain + format cache + factory; no fullscreen exclusive                       |
| COM (in-proc)                                             | Partial  | 20+ interfaces, class registry, `CoCreateInstance`. No DCOM / out-of-proc          |
| WinRT / Windows Runtime                                   | Stub     | `combase_winrt.c` returns `E_NOTIMPL` for most activation paths                    |
| .NET / managed code                                       | None     | `mscoree_host.c` is a stub that refuses `_CorExeMain`                              |
| UWP / AppContainer                                        | None     | No sandbox, no app-container capabilities                                          |
| 32-bit PE (PE32)                                          | None     | Exit code 4, suggests `wine`. See `pe_parser.c:244`, `main.c:533`                  |
| Anti-cheat (EAC, BattlEye, Vanguard, GameGuard, Blackshield) | Shimmed  | 34 fake procs, 22 kernel modules, SMBIOS spoof. See `services/anticheat/`           |
| Structured Exception Handling (SEH, `__try`/`__except`)   | Full     | `pe_exception.c` + `.pdata`/`.xdata` walker                                        |
| C++ Exceptions (MSVC `__CxxFrameHandler3`)                | Partial  | Common unwind paths only                                                           |
| Vectored Exception Handlers                               | Full     | `ntdll_exception.c`                                                                |
| Thread-Local Storage (`__declspec(thread)`, TLS slots)    | Full     | `pe_tls.c`, TLS callbacks run                                                      |
| Delay-load imports                                        | Full     | V1 and V2 descriptors, `pe_import.c:2848`                                          |
| Forwarded exports                                         | Full     | Cross-DLL forwarders resolve recursively                                           |
| Registry                                                  | Partial  | In-memory hive, 80+ prepopulated keys. No persistence to `HKLM\System`             |
| Services / SCM                                            | Partial  | `services/scm/` backs `StartService`, `CreateServiceA`                             |
| Named objects (mutex, event, semaphore, file-mapping)     | Full     | Cross-process via `pe-objectd` broker                                              |
| Job Objects                                               | Partial  | Handle resolution + basic limits, no UI restrictions                               |
| Fibers                                                    | Full     | `kernel32_fiber.c` (ucontext-based)                                                |
| IOCP (I/O Completion Ports)                               | Partial  | `kernel32_iocp.c`; io_uring-backed on capable kernels                              |
| Winsock 2                                                 | Partial  | TCP/UDP blocking + WSAEventSelect. No RIO, no AcceptEx async overlapped            |
| WinHTTP / WinINet                                         | Partial  | libcurl-backed, no auth negotiation                                                |
| Cryptography (CNG / BCrypt)                               | Partial  | AES/SHA via openssl. No CAPI smartcard, no PFX import                              |
| DirectSound / XAudio2                                     | Partial  | PipeWire output, no capture                                                        |
| Print / GDI printing                                      | None     | `CreatePrintDC` returns NULL                                                       |

## Known Working Binaries

Session 41's wizard populates this list from the CI harness in
`tests/pe-binaries/`. At the time of writing the shipped coverage includes:

- Console hello-world (MSVC 2022, `/MT` and `/MD`)
- MinGW-w64 C/C++ test suite (console + minimal GUI)
- Simple Win32 window demos (`CreateWindowExA` + message pump)
- DXVK sample D3D11 triangle
- VKD3D d3d12 "HelloTriangle"

Agent 3's run populates `docs/pe-compat-results.md` with real-world AAA titles and
tools. If that file is absent, only the items above are CI-verified.

## Known Broken Binaries

These either fail to load or crash partway through startup:

- **Any 32-bit PE**: bailed out at parse time. Use Wine.
- **.NET Framework / .NET Core apps**: `mscoree.dll` refuses to host the CLR.
  Use Wine with `dotnet-core`, or a Linux-native .NET runtime.
- **UWP / MSIX apps**: no AppContainer, no package manifest handling.
- **Installer MSI packages (`msiexec.exe`)**: `msi_installer.c` only handles a
  vcredist-style subset. Use `wine msiexec`.
- **Apps that call `LoadLibrary("wintrust.dll")` for Authenticode**: wintrust is
  not shipped; signatures cannot be verified. Shipped binaries bypass this via
  the anti-cheat shim path where applicable.
- **Anything that uses Direct3D fullscreen-exclusive fences** (rare modern games):
  DXGI swap chain returns windowed only.
- **`GetRawInputData` for game controllers**: XInput works, raw HID does not.
- **Print / GDI-to-printer flows**: `CreateDC("DISPLAY", ...)` works,
  `CreateDC("WINSPOOL", ...)` returns NULL.

## Troubleshooting

### `peloader -D <exe>` diagnostic output

Running with `-D` / `--diag` parses the image, resolves imports against the
shipped DLL stubs, and prints a coverage summary instead of executing the binary.
Sample output, explained:

```
[peloader] PE32+ image, subsystem=Windows GUI (2)
[peloader] Sections: 8
[peloader] Imports: 412 symbols across 14 DLLs
[peloader]   kernel32.dll   -> 189/189  resolved  (libpe_kernel32.so)
[peloader]   user32.dll     -> 47/47    resolved  (libpe_user32.so)
[peloader]   d3d11.dll      -> 12/13    resolved  (libpe_d3d.so)   [MISSING: D3D11On12CreateDevice]
[peloader]   api-ms-win-core-*  -> forwarded to libpe_kernel32.so
[peloader] Delay-load: 2 descriptors, 18 imports
[peloader] Anti-cheat: EAC detected, shim loaded (libpe_anticheat.so)
```

- **`MISSING:`** lines show individual exports the stub does not provide. The binary
  will still load (missing exports bind to a trap that fails on first call), but
  calls into that function will error out.
- **`resolved 0/N`** indicates the DLL stub itself was not found on the search
  path. Check `/usr/lib/pe-compat/` and `LD_LIBRARY_PATH`.

### Common errors

| Symptom                                          | Likely cause                                                       | Fix                                                                              |
| ------------------------------------------------ | ------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| Exit code 4, "unsupported bitness"               | 32-bit PE                                                          | Use `wine <exe>`                                                                 |
| Exit code 2, "Failed to read PE32+ optional hdr" | Corrupt or non-PE file                                             | Verify with `file <exe>`                                                         |
| `[peloader] import unresolved: <DLL>!<func>`     | Stub is missing that export                                        | Add the export (see "Extending"), or pick a different binary                     |
| Crash in `abi_call_win64_*`                      | Imported function was resolved to a sysv_abi host function         | Add an `ms_abi` wrapper in `pe_find_crt_wrapper()`                               |
| `std::bad_alloc` on startup                      | Huge image, AddressSanitizer build                                 | Use release build; ASan bloats PE mappings                                       |
| DX init returns `E_NOTIMPL`                      | Vulkan feature level below minimum                                 | Update GPU driver; check `vulkaninfo` for timeline semaphores                    |
| No audio                                         | PipeWire not running as user                                       | `systemctl --user start pipewire pipewire-pulse`                                 |
| Anti-cheat refuses to start                      | Shim not loaded (missing `libpe_anticheat.so`)                     | Reinstall `ai-desktop-config` package, check `/usr/lib/pe-compat/`               |

### Enabling verbose / trace output

- `peloader -v <exe>`: per-subsystem status lines (image parse, import resolve, DXVK init).
- `peloader -d <exe>`: adds debug logging from each DLL stub (very noisy; redirect to file).
- `peloader -t <exe>`: API-call trace; one line per Win32 function call. Useful for reproducing hangs.

Loader-side logs are emitted to stderr with `[peloader]`, `[pe-import]`, `[pe-relocator]` prefixes. DLL stubs use `[kernel32]`, `[user32]`, etc.

## Extending

To add a missing DLL export:

1. Identify the DLL and the missing symbol from the `-D` diagnostic output.
2. Find the DLL's source directory under `pe-loader/dlls/<name>/`. Each DLL has
   one or more `.c` files organised by subsystem (e.g. `kernel32_file.c`,
   `kernel32_process.c`).
3. Add the function with `__attribute__((ms_abi))` and whatever return-shape the
   MSDN reference documents. Wide-char (`W`) versions accept `const uint16_t *`,
   never `wchar_t *` (the Linux wchar_t is 32-bit and wrong for Windows).
4. Add an entry in the `pe-loader/dlls/<name>/Makefile` if you created a new
   source file, and rebuild: `make -C pe-loader`.
5. Register the export name in the appropriate `g_dll_mappings` table in
   `pe_import.c` so the import resolver finds it.
6. For CRT functions, if the symbol is a libc alias, add an `ms_abi` wrapper in
   `pe_find_crt_wrapper()` (see CLAUDE.md "PE Loader ABI" notes).
7. Run `make test` to verify no regressions.

See `docs/pe-dll-coverage.md` for a per-DLL map of what is already implemented
and which source files back each DLL.
