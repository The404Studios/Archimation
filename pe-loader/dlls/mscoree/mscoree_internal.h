/*
 * mscoree_internal.h - Private interface between mscoree translation units.
 *
 * Shared between mscoree_host.c (legacy entry points + Mono dlopen helper)
 * and mscoree_metahost.c (ICLRMetaHost / ICLRRuntimeInfo / ICLRRuntimeHost
 * vtables).  Not exported to PE callers.
 */

#ifndef MSCOREE_INTERNAL_H
#define MSCOREE_INTERNAL_H

#include "common/dll_common.h"

/* HRESULT codes shared between TUs */
#ifndef S_OK
#  define S_OK            ((HRESULT)0x00000000)
#endif
#ifndef S_FALSE
#  define S_FALSE         ((HRESULT)0x00000001)
#endif
#ifndef E_FAIL
#  define E_FAIL          ((HRESULT)0x80004005)
#endif
#ifndef E_INVALIDARG
#  define E_INVALIDARG    ((HRESULT)0x80070057)
#endif
#ifndef E_NOTIMPL
#  define E_NOTIMPL       ((HRESULT)0x80004001)
#endif
#ifndef E_NOINTERFACE
#  define E_NOINTERFACE   ((HRESULT)0x80004002)
#endif
#ifndef E_POINTER
#  define E_POINTER       ((HRESULT)0x80004003)
#endif
#ifndef CLASS_E_CLASSNOTAVAILABLE
#  define CLASS_E_CLASSNOTAVAILABLE ((HRESULT)0x80040111)
#endif

/* CLR-specific HRESULTs */
#ifndef CLR_E_SHIM_RUNTIMELOAD
#  define CLR_E_SHIM_RUNTIMELOAD ((HRESULT)0x80131700)
#endif
#ifndef HOST_E_INVALIDOPERATION
#  define HOST_E_INVALIDOPERATION ((HRESULT)0x80131022)
#endif
#ifndef HOST_E_CLRNOTAVAILABLE
#  define HOST_E_CLRNOTAVAILABLE ((HRESULT)0x80131013)
#endif

/* --------------------------------------------------------------------------
 * Mono runtime - shared dlopen handle and resolved symbols.
 * Owned by mscoree_host.c; consumed by mscoree_metahost.c.
 * -------------------------------------------------------------------------- */

/* Loads libmono*.so on first call, returns 0 on success, -1 on failure.
 * Idempotent and thread-safe (internal mutex). */
int mscoree_try_load_mono(void);

/* True only after a successful mscoree_try_load_mono() AND after the
 * required symbols (mono_jit_init, mono_jit_exec) resolved. */
int mscoree_mono_available(void);

/* Mono signature typedefs (kept SysV - libmono is plain C, not ms_abi). */
typedef void *(*mscoree_mono_jit_init_fn)(const char *domain_name);
typedef int   (*mscoree_mono_jit_exec_fn)(void *domain, void *assembly,
                                          int argc, char *argv[]);
typedef void *(*mscoree_mono_domain_assembly_open_fn)(void *domain,
                                                      const char *name);
typedef void  (*mscoree_mono_jit_cleanup_fn)(void *domain);

/* Extra symbols pulled in for ExecuteInDefaultAppDomain. */
typedef void *(*mscoree_mono_assembly_get_image_fn)(void *assembly);
typedef void *(*mscoree_mono_class_from_name_fn)(void *image,
                                                 const char *name_space,
                                                 const char *name);
typedef void *(*mscoree_mono_class_get_method_from_name_fn)(void *klass,
                                                            const char *name,
                                                            int param_count);
typedef void *(*mscoree_mono_string_new_fn)(void *domain, const char *text);
typedef void *(*mscoree_mono_runtime_invoke_fn)(void *method, void *obj,
                                                void **params,
                                                void **exc /* out, MonoObject** */);
typedef void *(*mscoree_mono_object_unbox_fn)(void *obj);
typedef void *(*mscoree_mono_get_root_domain_fn)(void);
typedef void *(*mscoree_mono_domain_get_fn)(void);
typedef int   (*mscoree_mono_runtime_exec_main_fn)(void *method, void *args /*MonoArray**/, void **exc);
typedef void *(*mscoree_mono_assembly_get_main_fn)(void *assembly);
typedef void *(*mscoree_mono_array_new_fn)(void *domain, void *eclass, uintptr_t n);
typedef void *(*mscoree_mono_get_string_class_fn)(void);

/* Resolved Mono entry points. NULL until mscoree_try_load_mono() succeeds. */
extern mscoree_mono_jit_init_fn                       pfn_mono_jit_init;
extern mscoree_mono_jit_exec_fn                       pfn_mono_jit_exec;
extern mscoree_mono_domain_assembly_open_fn           pfn_mono_domain_assembly_open;
extern mscoree_mono_jit_cleanup_fn                    pfn_mono_jit_cleanup;
extern mscoree_mono_assembly_get_image_fn             pfn_mono_assembly_get_image;
extern mscoree_mono_class_from_name_fn                pfn_mono_class_from_name;
extern mscoree_mono_class_get_method_from_name_fn     pfn_mono_class_get_method_from_name;
extern mscoree_mono_string_new_fn                     pfn_mono_string_new;
extern mscoree_mono_runtime_invoke_fn                 pfn_mono_runtime_invoke;
extern mscoree_mono_object_unbox_fn                   pfn_mono_object_unbox;
extern mscoree_mono_get_root_domain_fn                pfn_mono_get_root_domain;
extern mscoree_mono_domain_get_fn                     pfn_mono_domain_get;
extern mscoree_mono_runtime_exec_main_fn              pfn_mono_runtime_exec_main;
extern mscoree_mono_assembly_get_main_fn              pfn_mono_assembly_get_main;
extern mscoree_mono_array_new_fn                      pfn_mono_array_new;
extern mscoree_mono_get_string_class_fn               pfn_mono_get_string_class;

/* --------------------------------------------------------------------------
 * Singleton accessor for the metahost vtable.  Returns S_OK + populates
 * *ppInterface, or an HRESULT failure code.
 * -------------------------------------------------------------------------- */
HRESULT mscoree_get_metahost_singleton(const GUID *riid, void **ppInterface);

/* --------------------------------------------------------------------------
 * Shared GUIDs (definitions live in mscoree_metahost.c).
 * -------------------------------------------------------------------------- */
extern const GUID MSCOREE_CLSID_CLRMetaHost;
extern const GUID MSCOREE_IID_ICLRMetaHost;
extern const GUID MSCOREE_IID_ICLRRuntimeInfo;
extern const GUID MSCOREE_CLSID_CLRRuntimeHost;
extern const GUID MSCOREE_IID_ICLRRuntimeHost;
extern const GUID MSCOREE_IID_IUnknown;

/* GUID equality helper (memcmp-based, Linux-side). */
static inline int mscoree_guid_eq(const GUID *a, const GUID *b)
{
    if (!a || !b) return 0;
    return a->Data1 == b->Data1 &&
           a->Data2 == b->Data2 &&
           a->Data3 == b->Data3 &&
           a->Data4[0] == b->Data4[0] &&
           a->Data4[1] == b->Data4[1] &&
           a->Data4[2] == b->Data4[2] &&
           a->Data4[3] == b->Data4[3] &&
           a->Data4[4] == b->Data4[4] &&
           a->Data4[5] == b->Data4[5] &&
           a->Data4[6] == b->Data4[6] &&
           a->Data4[7] == b->Data4[7];
}

#endif /* MSCOREE_INTERNAL_H */
