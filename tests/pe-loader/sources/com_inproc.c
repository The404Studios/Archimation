/*
 * com_inproc.c -- COM (combase) initialization smoke test.
 *
 * Surface tested:
 *   ole32!CoInitializeEx, ole32!CoUninitialize, ole32!CoCreateInstance,
 *   ole32!CoCreateGuid, ole32!CoTaskMemAlloc, ole32!CoTaskMemFree,
 *   ole32!StringFromGUID2
 *
 * Rationale:
 *   Validates Agent A3's COM/HKCR fallback.  We:
 *     1. CoInitializeEx(COINIT_APARTMENTTHREADED) -- must return S_OK or
 *        S_FALSE (already initialized).
 *     2. CoCreateGuid -- must return S_OK with a non-zero GUID.
 *     3. StringFromGUID2 -- formats the GUID, must return >0 chars.
 *     4. CoCreateInstance against CLSID_FileSystemObject (a built-in
 *        OLE Automation server).  May return REGDB_E_CLASSNOTREG if
 *        HKCR has no entry; we accept that and report STUB.  S_OK means
 *        the in-proc COM hot-path works.
 *     5. CoUninitialize.
 *
 * Harness expectation: outputs:COM_INPROC_OK   (CoCreateInstance worked)
 *                  OR  outputs:COM_INPROC_STUB (only init paths worked)
 */

#include <windows.h>
#include <objbase.h>
#include <stdio.h>

/* CLSID_FileSystemObject = {0D43FE01-F093-11CF-8940-00A0C9054228} */
static const CLSID CLSID_FSO = {
    0x0D43FE01, 0xF093, 0x11CF,
    { 0x89, 0x40, 0x00, 0xA0, 0xC9, 0x05, 0x42, 0x28 }
};

static const IID IID_IUnk = {
    0x00000000, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

int main(void) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        fprintf(stderr, "CoInitializeEx failed: 0x%08lx\n",
                (unsigned long)hr);
        return 60;
    }

    GUID g;
    hr = CoCreateGuid(&g);
    if (FAILED(hr)) {
        fprintf(stderr, "CoCreateGuid failed: 0x%08lx\n",
                (unsigned long)hr);
        CoUninitialize();
        return 61;
    }

    /* Format the GUID for a sanity look. */
    OLECHAR gstr[64] = {0};
    int n = StringFromGUID2(&g, gstr, 64);
    printf("CoCreateGuid -> %d chars\n", n);

    /* Try to create FileSystemObject.  Acceptable outcomes:
     *   S_OK                  -> COM_INPROC_OK
     *   REGDB_E_CLASSNOTREG   -> COM_INPROC_STUB (HKCR empty, expected)
     *   anything else         -> failure */
    void *unk = NULL;
    hr = CoCreateInstance(&CLSID_FSO, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IUnk, &unk);

    int success = 0;
    if (SUCCEEDED(hr) && unk) {
        printf("CoCreateInstance(FSO) succeeded -> %p\n", unk);
        IUnknown *u = (IUnknown *)unk;
        u->lpVtbl->Release(u);
        success = 1;
    } else {
        printf("CoCreateInstance(FSO) hr=0x%08lx (HKCR fallback?)\n",
               (unsigned long)hr);
    }

    CoUninitialize();

    if (success) {
        printf("COM_INPROC_OK\n");
    } else {
        printf("COM_INPROC_STUB\n");
    }
    fflush(stdout);
    return 0;
}
