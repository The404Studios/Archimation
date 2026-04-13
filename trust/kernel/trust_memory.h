/*
 * trust_memory.h - Trust Memory Scanner (TMS) declarations
 *
 * Per-subject memory region tracking for trust-tracked PE processes.
 * Hooks mmap/mprotect/munmap via kprobes, maintains an rbtree-based
 * memory map per subject, emits netlink events for interesting operations,
 * and supports configurable byte-pattern matching for detecting IAT hooks,
 * shellcode, debug flags, etc.
 *
 * Part of the Root of Authority kernel module.
 */

#ifndef TRUST_MEMORY_H
#define TRUST_MEMORY_H

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

/* --- Limits --- */
#define TMS_MAX_REGIONS_PER_SUBJECT 4096
#define TMS_MAX_SUBJECTS            1024
#define TMS_MAX_PATTERNS            256
#define TMS_PATTERN_MAX_LEN         64
#define TMS_NETLINK_GROUP           1
#define TMS_NETLINK_PROTO           30   /* Netlink protocol number */

/* --- Event types (reported via netlink) --- */
#define TMS_EVENT_MAP       0x01    /* New memory mapping created */
#define TMS_EVENT_UNMAP     0x02    /* Memory mapping destroyed */
#define TMS_EVENT_PROTECT   0x03    /* Protection flags changed */
#define TMS_EVENT_PATTERN   0x04    /* Byte pattern matched */
#define TMS_EVENT_SECTION   0x05    /* PE section registered */
#define TMS_EVENT_EXEC_HEAP 0x06    /* Executable pages in heap region */
#define TMS_EVENT_W_TEXT    0x07    /* Write access on .text section */

/* --- Memory region tag --- */
enum tms_region_tag {
    TMS_TAG_UNKNOWN = 0,
    TMS_TAG_PE_HEADER,      /* MZ/PE headers */
    TMS_TAG_TEXT,            /* .text executable code */
    TMS_TAG_RDATA,           /* .rdata read-only data */
    TMS_TAG_DATA,            /* .data read-write data */
    TMS_TAG_BSS,             /* .bss uninitialized data */
    TMS_TAG_RSRC,            /* .rsrc resources */
    TMS_TAG_RELOC,           /* .reloc relocations */
    TMS_TAG_IAT,             /* Import Address Table */
    TMS_TAG_TLS,             /* Thread-Local Storage */
    TMS_TAG_HEAP,            /* Process heap */
    TMS_TAG_STACK,           /* Thread stack */
    TMS_TAG_DLL,             /* Loaded DLL */
    TMS_TAG_SHARED,          /* Shared memory / IPC */
    TMS_TAG_DEVICE,          /* Device-mapped memory */
    TMS_TAG_VDSO,            /* vDSO/vsyscall */
    TMS_TAG_COUNT
};

/* --- Tracked memory region (rbtree node keyed by va_start) --- */
struct tms_region {
    struct rb_node      node;
    u64                 va_start;
    u64                 va_end;        /* Exclusive: [va_start, va_end) */
    u32                 prot;          /* PROT_READ | PROT_WRITE | PROT_EXEC */
    enum tms_region_tag tag;
    char                label[32];     /* Human-readable: "ntdll.dll .text" */
    u64                 load_time_ns;  /* When this region was mapped */
    u32                 pattern_hits;  /* Number of pattern matches found */
};

/* --- Byte pattern for scanning --- */
struct tms_pattern {
    u8                  bytes[TMS_PATTERN_MAX_LEN];
    u8                  mask[TMS_PATTERN_MAX_LEN];  /* 0xFF=must match, 0x00=wildcard */
    u16                 len;
    u16                 id;            /* Pattern ID reported in events */
    char                name[32];      /* "IAT_HOOK", "SHELLCODE_NOP_SLED", etc. */
    enum tms_region_tag scan_in;       /* Only scan regions with this tag (0=all) */
};

/* --- Per-subject memory map --- */
struct tms_subject_map {
    struct rb_root      regions;
    u32                 region_count;
    spinlock_t          lock;
    u32                 subject_id;
    pid_t               pid;
    bool                active;        /* Is this slot in use? */
};

/* --- Netlink event message (sent to userspace) --- */
struct tms_event_msg {
    u32                 seq;           /* Monotonic event sequence number */
    u32                 type;          /* TMS_EVENT_* */
    u32                 subject_id;
    pid_t               pid;
    u64                 va;
    u64                 size;
    u32                 prot;
    u32                 pattern_id;    /* Only for TMS_EVENT_PATTERN */
    enum tms_region_tag tag;
    char                label[32];
};

/* --- ioctl structures for querying the memory map --- */

/* Single region info returned to userspace */
typedef struct {
    u64                 va_start;
    u64                 va_end;
    u32                 prot;
    u32                 tag;           /* enum tms_region_tag */
    char                label[32];
    u64                 load_time_ns;
    u32                 pattern_hits;
    u32                 _padding;
} tms_ioc_region_info_t;

/* Query memory map for a subject */
typedef struct {
    u32                 subject_id;
    u32                 max_regions;   /* Max entries caller can receive */
    u32                 returned;      /* Output: actual entries returned */
    u32                 total;         /* Output: total regions for subject */
    u64                 buf;           /* Userspace pointer to tms_ioc_region_info_t[] */
} tms_ioc_query_map_t;

/* Register a PE section with the TMS */
typedef struct {
    u32                 subject_id;
    u64                 va_start;
    u64                 size;
    u32                 tag;           /* enum tms_region_tag */
    char                label[32];
    int32_t             result;        /* Output: 0=ok, <0=error */
    u32                 _padding;
} tms_ioc_register_section_t;

/* Add a scan pattern */
typedef struct {
    u8                  bytes[TMS_PATTERN_MAX_LEN];
    u8                  mask[TMS_PATTERN_MAX_LEN];
    u16                 len;
    u16                 id;
    char                name[32];
    u32                 scan_in;       /* enum tms_region_tag (0=all) */
    int32_t             result;        /* Output: 0=ok, <0=error */
} tms_ioc_add_pattern_t;

/* Trigger a scan on a specific region */
typedef struct {
    u32                 subject_id;
    u64                 va_start;
    u64                 va_end;
    u32                 hits;          /* Output: number of pattern matches */
    int32_t             result;        /* Output: 0=ok, <0=error */
} tms_ioc_scan_region_t;

/* --- ioctl numbers (continue from trust_ioctl.h numbering) --- */
#define TRUST_IOC_TMS_QUERY_MAP         _IOWR('T', 110, tms_ioc_query_map_t)
#define TRUST_IOC_TMS_REGISTER_SECTION  _IOWR('T', 111, tms_ioc_register_section_t)
#define TRUST_IOC_TMS_ADD_PATTERN       _IOWR('T', 112, tms_ioc_add_pattern_t)
#define TRUST_IOC_TMS_SCAN_REGION       _IOWR('T', 113, tms_ioc_scan_region_t)

/* --- API functions (called from trust_core.c and kprobe handlers) --- */

int  tms_init(void);
void tms_cleanup(void);

int  tms_register_subject(u32 subject_id, pid_t pid);
void tms_unregister_subject(u32 subject_id);

int  tms_register_section(u32 subject_id, u64 va_start, u64 size,
                           enum tms_region_tag tag, const char *label);

void tms_on_mmap(pid_t pid, u64 addr, u64 len, u32 prot);
void tms_on_munmap(pid_t pid, u64 addr, u64 len);
void tms_on_mprotect(pid_t pid, u64 addr, u64 len, u32 prot);

int  tms_scan_region(u32 subject_id, u64 va_start, u64 va_end);

int  tms_add_pattern(const u8 *bytes, const u8 *mask, u16 len,
                      const char *name, u16 id, enum tms_region_tag tag);

/* ioctl handler (dispatched from trust_core.c) */
long tms_ioctl(unsigned int cmd, unsigned long arg);

#endif /* TRUST_MEMORY_H */
