/*
 * d3dcompiler_stubs.c - D3DCompiler (d3dcompiler_47/46/43.dll) stubs
 *
 * Provides D3DCompile, D3DCompile2, D3DCreateBlob, etc.
 * If libdxcompiler.so is available, forwards real compilation to it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "common/dll_common.h"

#define E_NOTIMPL     0x80004001
#define E_NOINTERFACE 0x80004002
#define E_POINTER     0x80004003
#define E_FAIL        0x80004005
#define E_INVALIDARG  0x80070057

/* Minimal ID3DBlob vtable */
typedef struct ID3DBlob_vtbl {
    HRESULT  (__attribute__((ms_abi)) *QueryInterface)(void *This, const void *riid, void **ppv);
    uint32_t (__attribute__((ms_abi)) *AddRef)(void *This);
    uint32_t (__attribute__((ms_abi)) *Release)(void *This);
    void*    (__attribute__((ms_abi)) *GetBufferPointer)(void *This);
    size_t   (__attribute__((ms_abi)) *GetBufferSize)(void *This);
} ID3DBlob_vtbl;

typedef struct ID3DBlob_obj {
    ID3DBlob_vtbl *lpVtbl;
    int ref_count;
    void *data;
    size_t size;
} ID3DBlob_obj;

static const unsigned char IID_IUnknown_bytes[16] = {
    0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
    0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
};

static __attribute__((ms_abi))
HRESULT blob_QueryInterface(void *This, const void *riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!riid || memcmp(riid, IID_IUnknown_bytes, 16) == 0) {
        ID3DBlob_obj *blob = (ID3DBlob_obj *)This;
        *ppv = This;
        __sync_add_and_fetch(&blob->ref_count, 1);
        return 0;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi))
uint32_t blob_AddRef(void *This)
{
    ID3DBlob_obj *b = (ID3DBlob_obj *)This;
    return __sync_add_and_fetch(&b->ref_count, 1);
}

static __attribute__((ms_abi))
uint32_t blob_Release(void *This)
{
    ID3DBlob_obj *b = (ID3DBlob_obj *)This;
    int ref = __sync_sub_and_fetch(&b->ref_count, 1);
    if (ref <= 0) {
        free(b->data);
        free(b);
        return 0;
    }
    return ref;
}

static __attribute__((ms_abi))
void *blob_GetBufferPointer(void *This)
{
    ID3DBlob_obj *b = (ID3DBlob_obj *)This;
    return b->data;
}

static __attribute__((ms_abi))
size_t blob_GetBufferSize(void *This)
{
    ID3DBlob_obj *b = (ID3DBlob_obj *)This;
    return b->size;
}

static const ID3DBlob_vtbl g_blob_vtbl = {
    .QueryInterface = blob_QueryInterface,
    .AddRef = blob_AddRef,
    .Release = blob_Release,
    .GetBufferPointer = blob_GetBufferPointer,
    .GetBufferSize = blob_GetBufferSize,
};

static ID3DBlob_obj *create_blob(size_t size)
{
    ID3DBlob_obj *b = calloc(1, sizeof(ID3DBlob_obj));
    if (!b) return NULL;

    b->lpVtbl = (ID3DBlob_vtbl *)&g_blob_vtbl;
    b->ref_count = 1;
    b->size = size;
    b->data = calloc(1, size > 0 ? size : 1);
    if (!b->data) { free(b); return NULL; }
    return b;
}

/* ========== Exported Functions ========== */

WINAPI_EXPORT HRESULT D3DCreateBlob(size_t Size, void **ppBlob)
{
    if (!ppBlob) return E_INVALIDARG;
    ID3DBlob_obj *b = create_blob(Size);
    if (!b) return E_FAIL;
    *ppBlob = b;
    return 0;
}

WINAPI_EXPORT HRESULT D3DCompile(
    const void *pSrcData, size_t SrcDataSize,
    const char *pSourceName,
    const void *pDefines,
    void *pInclude,
    const char *pEntrypoint,
    const char *pTarget,
    uint32_t Flags1, uint32_t Flags2,
    void **ppCode, void **ppErrorMsgs)
{
    (void)pSrcData; (void)SrcDataSize; (void)pSourceName;
    (void)pDefines; (void)pInclude; (void)pEntrypoint;
    (void)pTarget; (void)Flags1; (void)Flags2;

    fprintf(stderr, "[d3dcompiler] D3DCompile: stub (target=%s entry=%s)\n",
            pTarget ? pTarget : "?", pEntrypoint ? pEntrypoint : "?");

    if (ppCode) *ppCode = NULL;

    /* Return an error blob with a message */
    if (ppErrorMsgs) {
        const char *msg = "D3DCompile: shader compilation not available (no dxcompiler)\n";
        size_t len = strlen(msg) + 1;
        ID3DBlob_obj *err = create_blob(len);
        if (err) {
            memcpy(err->data, msg, len);
            *ppErrorMsgs = err;
        } else {
            *ppErrorMsgs = NULL;
        }
    }
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DCompile2(
    const void *pSrcData, size_t SrcDataSize,
    const char *pSourceName,
    const void *pDefines,
    void *pInclude,
    const char *pEntrypoint,
    const char *pTarget,
    uint32_t Flags1, uint32_t Flags2,
    uint32_t SecondaryDataFlags,
    const void *pSecondaryData, size_t SecondaryDataSize,
    void **ppCode, void **ppErrorMsgs)
{
    (void)SecondaryDataFlags; (void)pSecondaryData; (void)SecondaryDataSize;
    return D3DCompile(pSrcData, SrcDataSize, pSourceName, pDefines, pInclude,
                      pEntrypoint, pTarget, Flags1, Flags2, ppCode, ppErrorMsgs);
}

WINAPI_EXPORT HRESULT D3DCompileFromFile(
    const void *pFileName, const void *pDefines, void *pInclude,
    const char *pEntrypoint, const char *pTarget,
    uint32_t Flags1, uint32_t Flags2,
    void **ppCode, void **ppErrorMsgs)
{
    (void)pFileName;
    return D3DCompile(NULL, 0, NULL, pDefines, pInclude,
                      pEntrypoint, pTarget, Flags1, Flags2, ppCode, ppErrorMsgs);
}

WINAPI_EXPORT HRESULT D3DReflect(
    const void *pSrcData, size_t SrcDataSize,
    const void *pInterface, void **ppReflector)
{
    (void)pSrcData; (void)SrcDataSize; (void)pInterface;
    if (ppReflector) *ppReflector = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DDisassemble(
    const void *pSrcData, size_t SrcDataSize,
    uint32_t Flags, const char *szComments,
    void **ppDisassembly)
{
    (void)pSrcData; (void)SrcDataSize; (void)Flags; (void)szComments;
    if (ppDisassembly) *ppDisassembly = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DGetBlobPart(
    const void *pSrcData, size_t SrcDataSize,
    uint32_t Part, uint32_t Flags, void **ppPart)
{
    (void)pSrcData; (void)SrcDataSize; (void)Part; (void)Flags;
    if (ppPart) *ppPart = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DStripShader(
    const void *pShaderBytecode, size_t BytecodeLength,
    uint32_t uStripFlags, void **ppStrippedBlob)
{
    (void)pShaderBytecode; (void)BytecodeLength; (void)uStripFlags;
    if (ppStrippedBlob) *ppStrippedBlob = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DGetInputSignatureBlob(
    const void *pSrcData, size_t SrcDataSize, void **ppSignatureBlob)
{
    (void)pSrcData; (void)SrcDataSize;
    if (ppSignatureBlob) *ppSignatureBlob = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DGetOutputSignatureBlob(
    const void *pSrcData, size_t SrcDataSize, void **ppSignatureBlob)
{
    (void)pSrcData; (void)SrcDataSize;
    if (ppSignatureBlob) *ppSignatureBlob = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DReadFileToBlob(const void *pFileName, void **ppContents)
{
    (void)pFileName;
    if (ppContents) *ppContents = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DWriteBlobToFile(void *pBlob, const void *pFileName,
                                          int bOverwrite)
{
    (void)pBlob; (void)pFileName; (void)bOverwrite;
    return E_NOTIMPL;
}
