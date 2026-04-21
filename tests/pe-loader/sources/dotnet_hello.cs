// dotnet_hello.cs -- minimal .NET PE for Mono-bridge (mscoree A2) test.
//
// AI-Compile: mcs -platform:x64 -out:dotnet_hello.exe dotnet_hello.cs
//             (Mono compiler — falls back to dotnet/csc if available)
//
// Surface tested:
//   pe-loader/dlls/mscoree/* + Mono bridge from Session 65 Agent A2.
//   The PE has a CLR header and the loader must:
//     1. Detect .NET assembly via CLR data directory entry
//     2. Hand off to Mono runtime via mscoree CorBindToRuntime / _CorExeMain
//     3. JIT compile + execute Main()
//
// Harness expectation: outputs:DOTNET_HELLO_OK
//                  OR  outputs:DOTNET_HELLO_STUB  (mscoree returned a graceful stub)
//
// If mcs is absent on the build host this file is silently skipped by
// the Makefile (no .exe produced) and run_corpus.sh reports SKIP.
using System;

class DotnetHello {
    static int Main(string[] args) {
        Console.WriteLine("DOTNET_HELLO_OK");
        return 0;
    }
}
