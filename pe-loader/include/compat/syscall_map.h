#ifndef SYSCALL_MAP_H
#define SYSCALL_MAP_H

#include <stdint.h>

/*
 * NT Syscall Number Mapping (Windows 10 21H2, 64-bit)
 *
 * Windows syscall numbers change between OS versions.
 * This table targets Win10 21H2 as the default.
 * Source: https://j00ru.vexillium.org/syscalls/nt/64/
 */

/* Syscall context passed to handlers */
typedef struct {
    uint64_t rax;   /* Syscall number */
    uint64_t rcx;   /* Arg 1 (Win64 ABI) */
    uint64_t rdx;   /* Arg 2 */
    uint64_t r8;    /* Arg 3 */
    uint64_t r9;    /* Arg 4 */
    uint64_t r10;   /* Used by syscall instruction (original RCX) */
    uint64_t rsp;   /* Stack pointer (args 5+ on stack) */
} pe_syscall_context_t;

/* Syscall handler function type */
typedef int (*nt_syscall_handler_t)(pe_syscall_context_t *ctx);

/* Syscall table entry */
typedef struct {
    uint32_t            nt_number;
    const char         *nt_name;
    nt_syscall_handler_t handler;
} nt_syscall_entry_t;

/* NT syscall numbers (Windows 10 21H2) */
#define NT_CLOSE                        0x000F
#define NT_CREATE_FILE                  0x0055
#define NT_READ_FILE                    0x0006
#define NT_WRITE_FILE                   0x0008
#define NT_ALLOCATE_VIRTUAL_MEMORY      0x0018
#define NT_FREE_VIRTUAL_MEMORY          0x001E
#define NT_PROTECT_VIRTUAL_MEMORY       0x0050
#define NT_QUERY_VIRTUAL_MEMORY         0x0023
#define NT_CREATE_THREAD_EX             0x004B
#define NT_TERMINATE_THREAD             0x0053
#define NT_TERMINATE_PROCESS            0x002C
#define NT_WAIT_FOR_SINGLE_OBJECT       0x0004
#define NT_WAIT_FOR_MULTIPLE_OBJECTS    0x000B
#define NT_SET_EVENT                    0x000E
#define NT_CREATE_EVENT                 0x0048
#define NT_OPEN_KEY                     0x0012
#define NT_QUERY_VALUE_KEY              0x0016
#define NT_SET_VALUE_KEY                0x0017
#define NT_QUERY_INFO_PROCESS           0x0019
#define NT_QUERY_INFO_THREAD            0x0025
#define NT_QUERY_SYSTEM_INFO            0x0036
#define NT_DELAY_EXECUTION              0x0034
#define NT_CREATE_SECTION               0x004A
#define NT_MAP_VIEW_OF_SECTION          0x0028
#define NT_UNMAP_VIEW_OF_SECTION        0x002A
#define NT_OPEN_PROCESS                 0x0026
#define NT_OPEN_THREAD                  0x0132
#define NT_QUERY_OBJECT                 0x0010
#define NT_DUPLICATE_OBJECT             0x003C
#define NT_CREATE_MUTEX                 0x0165
#define NT_RELEASE_MUTEX                0x001D

/* Get the syscall table */
const nt_syscall_entry_t *nt_get_syscall_table(void);

/* Look up a syscall handler by number */
nt_syscall_handler_t nt_find_handler(uint32_t syscall_number);

/* Get the number of entries in the syscall table */
int nt_get_syscall_count(void);

#endif /* SYSCALL_MAP_H */
