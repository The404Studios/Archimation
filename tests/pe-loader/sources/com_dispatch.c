/*
 * com_dispatch.c -- ICLRMetaHost dispatch test (A5 from Session 66).
 *
 * Surface tested:
 *   mscoree!CLRCreateInstance, ICLRMetaHost::GetRuntime,
 *   ICLRRuntimeInfo::IsLoadable, vtable dispatch through metahost.
 *
 * Rationale:
 *   Session 66 Agent A5 added ICLRMetaHost as the canonical entry point
 *   for hosting the CLR.  Real-world tools (windbg, msbuild, vstest)
 *   use exactly this sequence to discover an installed runtime.
 *
 *   We accept three outcomes:
 *     - CLRCreateInstance fails (mscoree.dll absent or returned a clean
 *       stub HRESULT) -> STUB
 *     - GetRuntime fails after CLRCreateInstance -> STUB
 *     - GetRuntime + IsLoadable both succeed -> OK
 *
 * Harness expectation: outputs-any:COM_DISPATCH_OK,COM_DISPATCH_STUB
 */

#include <windows.h>
#include <objbase.h>
#include <stdio.h>

/* Forward-declare metahost CLSID/IIDs so we don't need <metahost.h>
 * (rarely shipped in MinGW sysroots).  Values are canonical.
 */
static const CLSID CLSID_CLRMetaHost_local = {
    0x9280188D, 0x0E8E, 0x4867,
    { 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE }
};
static const IID IID_ICLRMetaHost_local = {
    0xD332DB9E, 0xB9B3, 0x4125,
    { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 }
};
static const IID IID_ICLRRuntimeInfo_local = {
    0xBD39D1D2, 0xBA2F, 0x486A,
    { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 }
};

typedef struct ICLRMetaHost ICLRMetaHost;
typedef struct ICLRRuntimeInfo ICLRRuntimeInfo;

typedef struct ICLRMetaHostVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRMetaHost*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRMetaHost*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRMetaHost*);
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(
        ICLRMetaHost*, LPCWSTR pwzVersion, REFIID riid, void **ppRuntime);
    /* … remaining methods unused … */
} ICLRMetaHostVtbl;
struct ICLRMetaHost { const ICLRMetaHostVtbl *lpVtbl; };

typedef struct ICLRRuntimeInfoVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeInfo*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeInfo*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeInfo*);
    HRESULT (STDMETHODCALLTYPE *GetVersionString)(
        ICLRRuntimeInfo*, LPWSTR pwzBuffer, DWORD *pcchBuffer);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeDirectory)(
        ICLRRuntimeInfo*, LPWSTR pwzBuffer, DWORD *pcchBuffer);
    HRESULT (STDMETHODCALLTYPE *IsLoaded)(
        ICLRRuntimeInfo*, HANDLE hProcess, BOOL *pbLoaded);
    HRESULT (STDMETHODCALLTYPE *LoadErrorString)(
        ICLRRuntimeInfo*, UINT iResourceID, LPWSTR pwzBuffer,
        DWORD *pcchBuffer, LONG iLocaleID);
    HRESULT (STDMETHODCALLTYPE *LoadLibraryW)(
        ICLRRuntimeInfo*, LPCWSTR pwzDllName, HMODULE *phndModule);
    HRESULT (STDMETHODCALLTYPE *GetProcAddress)(
        ICLRRuntimeInfo*, LPCSTR pszProcName, void **ppProc);
    HRESULT (STDMETHODCALLTYPE *GetInterface)(
        ICLRRuntimeInfo*, REFCLSID rclsid, REFIID riid, void **ppUnk);
    HRESULT (STDMETHODCALLTYPE *IsLoadable)(
        ICLRRuntimeInfo*, BOOL *pbLoadable);
    /* … remaining methods unused … */
} ICLRRuntimeInfoVtbl;
struct ICLRRuntimeInfo { const ICLRRuntimeInfoVtbl *lpVtbl; };

/* mscoree exports CLRCreateInstance with this signature. */
typedef HRESULT (WINAPI *PFN_CLRCreateInstance)(
    REFCLSID clsid, REFIID riid, LPVOID *ppInterface);

int main(void) {
    HMODULE m = LoadLibraryA("mscoree.dll");
    if (!m) {
        printf("COM_DISPATCH_STUB no-mscoree\n");
        return 0;
    }
    PFN_CLRCreateInstance pfn =
        (PFN_CLRCreateInstance)(void*)GetProcAddress(m, "CLRCreateInstance");
    if (!pfn) {
        printf("COM_DISPATCH_STUB no-CLRCreateInstance\n");
        return 0;
    }

    ICLRMetaHost *meta = NULL;
    HRESULT hr = pfn(&CLSID_CLRMetaHost_local, &IID_ICLRMetaHost_local,
                    (void**)&meta);
    if (FAILED(hr) || !meta) {
        printf("COM_DISPATCH_STUB clr=%08lx\n", (unsigned long)hr);
        return 0;
    }

    ICLRRuntimeInfo *runtime = NULL;
    hr = meta->lpVtbl->GetRuntime(meta, L"v4.0.30319",
                                  &IID_ICLRRuntimeInfo_local,
                                  (void**)&runtime);
    if (SUCCEEDED(hr) && runtime) {
        BOOL loadable = FALSE;
        runtime->lpVtbl->IsLoadable(runtime, &loadable);
        printf("COM_DISPATCH_OK loadable=%d\n", loadable ? 1 : 0);
        runtime->lpVtbl->Release(runtime);
    } else {
        printf("COM_DISPATCH_STUB getruntime=%08lx\n", (unsigned long)hr);
    }
    meta->lpVtbl->Release(meta);
    return 0;
}
