#ifndef PE_COMPAT_IOCTL_H
#define PE_COMPAT_IOCTL_H

/*
 * ioctl interface between the userspace PE loader and
 * the pe_compat kernel module via /dev/pe_compat
 *
 * This header is shared between kernel and userspace.
 */

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#define PE_COMPAT_MAGIC 'P'

/* Register a PE process with the kernel module */
struct pe_process_info {
    int32_t  pid;
    uint64_t image_base;
    uint64_t image_size;
    uint32_t subsystem;         /* PE_SUBSYSTEM_WINDOWS_GUI or _CUI */
    uint32_t nt_version;        /* Target Windows version for syscall table */
};

/* Query module status */
struct pe_compat_status {
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t registered_processes;
    uint32_t intercepted_syscalls;
    uint32_t flags;
};

/* Syscall interception mode */
struct pe_syscall_mode {
    int32_t  pid;
    uint32_t mode;              /* 0=userspace only, 1=kernel fast-path */
    uint32_t nt_version;        /* Windows version for syscall numbers */
};

/* Virtual memory allocation request (VirtualAlloc equivalent) */
struct pe_valloc_request {
    uint64_t address;       /* Requested address (0 = any), output: actual address */
    uint64_t size;          /* Requested size in bytes */
    uint32_t alloc_type;    /* MEM_COMMIT=0x1000, MEM_RESERVE=0x2000, etc. */
    uint32_t protect;       /* PAGE_READWRITE=0x04, PAGE_EXECUTE_READ=0x20, etc. */
};

/* Virtual memory free request (VirtualFree equivalent) */
struct pe_vfree_request {
    uint64_t address;       /* Address to free */
    uint64_t size;          /* Size to free (0 for MEM_RELEASE) */
    uint32_t free_type;     /* MEM_DECOMMIT=0x4000, MEM_RELEASE=0x8000 */
    uint32_t _reserved;
};

#define PE_COMPAT_REGISTER_PROCESS   _IOW(PE_COMPAT_MAGIC, 1, struct pe_process_info)
#define PE_COMPAT_UNREGISTER_PROCESS _IOW(PE_COMPAT_MAGIC, 2, int32_t)
#define PE_COMPAT_SET_SYSCALL_MODE   _IOW(PE_COMPAT_MAGIC, 3, struct pe_syscall_mode)
#define PE_COMPAT_QUERY_STATUS       _IOR(PE_COMPAT_MAGIC, 4, struct pe_compat_status)
#define PE_COMPAT_VALLOC             _IOWR(PE_COMPAT_MAGIC, 5, struct pe_valloc_request)
#define PE_COMPAT_VFREE              _IOW(PE_COMPAT_MAGIC, 6, struct pe_vfree_request)

/* Windows memory allocation type flags */
#define PE_MEM_COMMIT               0x00001000
#define PE_MEM_RESERVE              0x00002000
#define PE_MEM_DECOMMIT             0x00004000
#define PE_MEM_RELEASE              0x00008000
#define PE_MEM_RESET                0x00080000

/* Windows memory protection flags */
#define PE_PAGE_NOACCESS            0x01
#define PE_PAGE_READONLY            0x02
#define PE_PAGE_READWRITE           0x04
#define PE_PAGE_WRITECOPY           0x08
#define PE_PAGE_EXECUTE             0x10
#define PE_PAGE_EXECUTE_READ        0x20
#define PE_PAGE_EXECUTE_READWRITE   0x40
#define PE_PAGE_EXECUTE_WRITECOPY   0x80
#define PE_PAGE_GUARD               0x100

/* Module version */
#define PE_COMPAT_VERSION_MAJOR 0
#define PE_COMPAT_VERSION_MINOR 1

/* ========================================================================
 * Trust Memory Scanner (TMS) ioctl definitions
 *
 * These ioctls are sent by the PE loader to /dev/trust (magic 'T') to
 * register PE processes and their memory sections with the Trust Memory
 * Scanner kernel subsystem.  The TMS tracks memory regions per trust
 * subject and emits events when protection changes violate expected
 * patterns (e.g. .text becoming writable).
 * ======================================================================== */

#define TRUST_IOC_MAGIC_T 'T'

/* Register a PE process with the Trust Memory Scanner */
struct tms_register_req {
    uint32_t subject_id;        /* Trust subject ID for this PE process */
    int32_t  pid;               /* Linux PID of the PE process */
    int32_t  result;            /* Output: 0=ok, <0=error */
    uint32_t _reserved;
};

/* Register a PE section (e.g. .text, .data, .rdata) with the TMS */
struct tms_section_req {
    uint32_t subject_id;        /* Trust subject ID */
    uint64_t va_start;          /* Virtual address of section start */
    uint64_t size;              /* Section size in bytes */
    uint32_t tag;               /* Section type (TMS_TAG_*) */
    char     label[32];         /* Human-readable label, e.g. "ntdll.dll .text" */
    int32_t  result;            /* Output: 0=ok, <0=error */
    uint32_t _padding;
};

/* Query memory map for a trust subject */
struct tms_query_req {
    uint32_t subject_id;        /* Trust subject ID to query */
    uint32_t max_regions;       /* Maximum region entries caller can receive */
    uint32_t returned;          /* Output: number of entries returned */
    uint32_t total;             /* Output: total regions tracked for subject */
    uint64_t buf;               /* Userspace pointer to region info array */
};

/* TMS region tags (mirrors enum tms_region_tag in trust_memory.h) */
#define TMS_TAG_UNKNOWN     0
#define TMS_TAG_PE_HEADER   1
#define TMS_TAG_TEXT        2
#define TMS_TAG_RDATA       3
#define TMS_TAG_DATA        4
#define TMS_TAG_BSS         5
#define TMS_TAG_RSRC        6
#define TMS_TAG_RELOC       7
#define TMS_TAG_IAT         8
#define TMS_TAG_TLS         9
#define TMS_TAG_HEAP        10
#define TMS_TAG_STACK       11
#define TMS_TAG_DLL         12
#define TMS_TAG_SHARED      13
#define TMS_TAG_DEVICE      14

#define TRUST_IOC_TMS_REGISTER  _IOW(TRUST_IOC_MAGIC_T, 0x30, struct tms_register_req)
#define TRUST_IOC_TMS_SECTION   _IOW(TRUST_IOC_MAGIC_T, 0x31, struct tms_section_req)
#define TRUST_IOC_TMS_QUERY     _IOWR(TRUST_IOC_MAGIC_T, 0x32, struct tms_query_req)

#endif /* PE_COMPAT_IOCTL_H */
