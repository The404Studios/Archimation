/*
 * dbghelp_sym.c - Debug Help Library (dbghelp.dll / imagehlp.dll) stubs
 *
 * Provides SymInitialize, StackWalk64, MiniDumpWriteDump, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"
#include "compat/trust_gate.h"

/* ========== Symbol Handler ========== */

static uint32_t g_sym_options = 0;

WINAPI_EXPORT BOOL SymInitialize(void *hProcess, const char *UserSearchPath, BOOL fInvadeProcess)
{
    TRUST_CHECK_RET(TRUST_GATE_DEBUG_OP, "SymInitialize", FALSE);
    (void)hProcess; (void)UserSearchPath; (void)fInvadeProcess;
    return TRUE;
}

WINAPI_EXPORT BOOL SymInitializeW(void *hProcess, const void *UserSearchPath, BOOL fInvadeProcess)
{
    TRUST_CHECK_RET(TRUST_GATE_DEBUG_OP, "SymInitializeW", FALSE);
    (void)hProcess; (void)UserSearchPath; (void)fInvadeProcess;
    return TRUE;
}

WINAPI_EXPORT BOOL SymCleanup(void *hProcess)
{
    (void)hProcess;
    return TRUE;
}

WINAPI_EXPORT uint32_t SymSetOptions(uint32_t SymOptions)
{
    uint32_t old = g_sym_options;
    g_sym_options = SymOptions;
    return old;
}

WINAPI_EXPORT uint32_t SymGetOptions(void)
{
    return g_sym_options;
}

WINAPI_EXPORT BOOL SymSetSearchPath(void *hProcess, const char *SearchPath)
{
    (void)hProcess; (void)SearchPath;
    return TRUE;
}

WINAPI_EXPORT BOOL SymSetSearchPathW(void *hProcess, const void *SearchPath)
{
    (void)hProcess; (void)SearchPath;
    return TRUE;
}

/* ========== Stack Walking ========== */

WINAPI_EXPORT BOOL StackWalk64(uint32_t MachineType, void *hProcess, void *hThread,
                                void *StackFrame, void *ContextRecord,
                                void *ReadMemoryRoutine, void *FunctionTableAccessRoutine,
                                void *GetModuleBaseRoutine, void *TranslateAddress)
{
    TRUST_CHECK_RET(TRUST_GATE_DEBUG_OP, "StackWalk64", FALSE);
    (void)MachineType; (void)hProcess; (void)hThread;
    (void)StackFrame; (void)ContextRecord; (void)ReadMemoryRoutine;
    (void)FunctionTableAccessRoutine; (void)GetModuleBaseRoutine;
    (void)TranslateAddress;
    return FALSE; /* No more frames */
}

WINAPI_EXPORT BOOL StackWalk(uint32_t MachineType, void *hProcess, void *hThread,
                              void *StackFrame, void *ContextRecord,
                              void *ReadMemoryRoutine, void *FunctionTableAccessRoutine,
                              void *GetModuleBaseRoutine, void *TranslateAddress)
{
    return StackWalk64(MachineType, hProcess, hThread, StackFrame, ContextRecord,
                       ReadMemoryRoutine, FunctionTableAccessRoutine,
                       GetModuleBaseRoutine, TranslateAddress);
}

/* ========== Symbol Lookup ========== */

typedef struct {
    uint32_t SizeOfStruct;
    uint32_t TypeIndex;
    uint64_t Reserved[2];
    uint32_t Index;
    uint32_t Size;
    uint64_t ModBase;
    uint32_t Flags;
    uint64_t Value;
    uint64_t Address;
    uint32_t Register;
    uint32_t Scope;
    uint32_t Tag;
    uint32_t NameLen;
    uint32_t MaxNameLen;
    char Name[1];
} SYMBOL_INFO;

WINAPI_EXPORT BOOL SymFromAddr(void *hProcess, uint64_t Address,
                                uint64_t *Displacement, SYMBOL_INFO *Symbol)
{
    TRUST_CHECK_RET(TRUST_GATE_DEBUG_OP, "SymFromAddr", FALSE);
    (void)hProcess; (void)Address;
    if (Displacement) *Displacement = 0;
    if (Symbol) {
        Symbol->Address = Address;
        if (Symbol->MaxNameLen > 0)
            snprintf(Symbol->Name, Symbol->MaxNameLen, "<unknown>");
        Symbol->NameLen = 9;
    }
    return FALSE;
}

WINAPI_EXPORT BOOL SymFromAddrW(void *hProcess, uint64_t Address,
                                  uint64_t *Displacement, void *Symbol)
{
    (void)hProcess; (void)Address; (void)Displacement; (void)Symbol;
    return FALSE;
}

WINAPI_EXPORT BOOL SymGetSymFromAddr64(void *hProcess, uint64_t Address,
                                         uint64_t *Displacement, void *Symbol)
{
    (void)hProcess; (void)Address; (void)Displacement; (void)Symbol;
    return FALSE;
}

WINAPI_EXPORT BOOL SymFromName(void *hProcess, const char *Name, SYMBOL_INFO *Symbol)
{
    (void)hProcess; (void)Name; (void)Symbol;
    return FALSE;
}

/* ========== Module Loading ========== */

WINAPI_EXPORT uint64_t SymLoadModule64(void *hProcess, void *hFile,
                                         const char *ImageName, const char *ModuleName,
                                         uint64_t BaseOfDll, uint32_t SizeOfDll)
{
    (void)hProcess; (void)hFile; (void)ImageName; (void)ModuleName;
    (void)SizeOfDll;
    return BaseOfDll; /* Return the base address as "success" */
}

WINAPI_EXPORT uint64_t SymLoadModuleEx(void *hProcess, void *hFile,
                                         const char *ImageName, const char *ModuleName,
                                         uint64_t BaseOfDll, uint32_t DllSize,
                                         void *Data, uint32_t Flags)
{
    (void)Data; (void)Flags;
    return SymLoadModule64(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize);
}

WINAPI_EXPORT BOOL SymUnloadModule64(void *hProcess, uint64_t BaseOfDll)
{
    (void)hProcess; (void)BaseOfDll;
    return TRUE;
}

WINAPI_EXPORT BOOL SymEnumerateModules64(void *hProcess, void *EnumModulesCallback,
                                           void *UserContext)
{
    (void)hProcess; (void)EnumModulesCallback; (void)UserContext;
    return TRUE;
}

/* ========== Line Info ========== */

WINAPI_EXPORT BOOL SymGetLineFromAddr64(void *hProcess, uint64_t dwAddr,
                                          uint32_t *pdwDisplacement, void *Line)
{
    (void)hProcess; (void)dwAddr; (void)pdwDisplacement; (void)Line;
    return FALSE;
}

/* ========== MiniDump ========== */

WINAPI_EXPORT BOOL MiniDumpWriteDump(void *hProcess, uint32_t ProcessId,
                                       void *hFile, uint32_t DumpType,
                                       void *ExceptionParam,
                                       void *UserStreamParam,
                                       void *CallbackParam)
{
    TRUST_CHECK_RET(TRUST_GATE_DEBUG_OP, "MiniDumpWriteDump", FALSE);
    (void)hProcess; (void)ProcessId; (void)hFile; (void)DumpType;
    (void)ExceptionParam; (void)UserStreamParam; (void)CallbackParam;
    fprintf(stderr, "[dbghelp] MiniDumpWriteDump: stub (not creating dump)\n");
    return TRUE; /* Pretend success */
}

/* ========== Name Undecorating ========== */

WINAPI_EXPORT uint32_t UnDecorateSymbolName(const char *name, char *outputString,
                                              uint32_t maxStringLength, uint32_t flags)
{
    (void)flags;
    if (!name || !outputString || maxStringLength == 0) return 0;

    /* Simple passthrough - strip leading ? if present */
    const char *src = name;
    if (*src == '?') src++;

    strncpy(outputString, src, maxStringLength - 1);
    outputString[maxStringLength - 1] = '\0';
    return (uint32_t)strlen(outputString);
}

WINAPI_EXPORT uint32_t UnDecorateSymbolNameW(const void *name, void *outputString,
                                               uint32_t maxStringLength, uint32_t flags)
{
    (void)name; (void)outputString; (void)maxStringLength; (void)flags;
    return 0;
}

/* ========== Image Functions (imagehlp.dll) ========== */

WINAPI_EXPORT void *ImageNtHeader(void *Base)
{
    if (!Base) return NULL;
    uint8_t *p = (uint8_t *)Base;
    /* Check MZ signature */
    if (p[0] != 'M' || p[1] != 'Z') return NULL;
    /* e_lfanew at offset 0x3C */
    uint32_t pe_offset;
    memcpy(&pe_offset, p + 0x3C, 4);
    uint8_t *pe = p + pe_offset;
    /* Check PE\0\0 signature */
    if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0)
        return NULL;
    return pe;
}

WINAPI_EXPORT void *ImageRvaToVa(void *NtHeaders, void *Base, uint32_t Rva, void **LastRvaSection)
{
    (void)NtHeaders; (void)LastRvaSection;
    if (!Base) return NULL;
    return (uint8_t *)Base + Rva;
}

WINAPI_EXPORT BOOL SymRefreshModuleList(void *hProcess)
{
    (void)hProcess;
    return TRUE;
}

/* Function table access (needed by StackWalk64) */
WINAPI_EXPORT void *SymFunctionTableAccess64(void *hProcess, uint64_t AddrBase)
{
    (void)hProcess; (void)AddrBase;
    return NULL;
}

WINAPI_EXPORT uint64_t SymGetModuleBase64(void *hProcess, uint64_t dwAddr)
{
    (void)hProcess; (void)dwAddr;
    return 0;
}
