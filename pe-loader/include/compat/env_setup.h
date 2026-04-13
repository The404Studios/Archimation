#ifndef ENV_SETUP_H
#define ENV_SETUP_H

#include "win32/windef.h"

int   env_setup_init(void *image_base, const char *image_path, const char *command_line);
int   env_setup_thread(void);
void *env_get_teb(void);
void *env_get_peb(void);
void  env_set_last_error(DWORD error);
DWORD env_get_last_error(void);
void  env_cleanup(void);

/* TLS slot management — wires TEB.ThreadLocalStoragePointer */
void  env_tls_set_slot(DWORD index, void *data);
void *env_tls_get_slot(DWORD index);

/* PEB LDR module registration */
int   env_register_module(void *base, ULONG size, void *entry_point,
                          const char *full_path, const char *name, int is_dll);
void *env_find_module_by_base(void *base);
void *env_find_module_by_name(const char *name);

/* Wire PEB->ProcessHeap to real heap handle */
void  env_wire_process_heap(void *heap_handle);

/* Exception handling initialization */
void  ntdll_exception_init(void);

#endif /* ENV_SETUP_H */
