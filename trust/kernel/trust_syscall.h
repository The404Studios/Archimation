/*
 * trust_syscall.h - Syscall interception and translation for trust-tracked PE processes
 *
 * Extends the Root of Authority kernel module to trace syscalls made by
 * PE processes. Uses kprobes on key syscall entry points and kretprobes
 * to capture return values. Events are emitted via netlink to the
 * userspace AI daemon for Windows API translation.
 *
 * Part of the Root of Authority kernel module (trust.ko).
 */

#ifndef TRUST_SYSCALL_H
#define TRUST_SYSCALL_H

#include <linux/types.h>
#include <linux/spinlock.h>

/* --- Limits --- */
#define TSC_MAX_SUBJECTS        1024    /* Max tracked PIDs */
#define TSC_RING_SIZE           4096    /* Per-PID event ring buffer entries */
#define TSC_NETLINK_PROTO       31      /* Netlink protocol number */
#define TSC_NETLINK_GROUP       1       /* Netlink multicast group */

/* --- Syscall categories we track --- */
#define TSC_CAT_FILE            0x01    /* open, read, write, close, stat, ioctl */
#define TSC_CAT_MEMORY          0x02    /* mmap, munmap, mprotect, brk */
#define TSC_CAT_PROCESS         0x04    /* fork, clone, execve, exit, wait */
#define TSC_CAT_NETWORK         0x08    /* socket, connect, bind, listen, send, recv */
#define TSC_CAT_SIGNAL          0x10    /* kill, sigaction, sigprocmask */
#define TSC_CAT_IPC             0x20    /* pipe, shmget, semget, msgget */
#define TSC_CAT_ALL             0x3F    /* All categories */

/* --- x86_64 syscall numbers (for reference and mapping) --- */
#define TSC_NR_READ             0
#define TSC_NR_WRITE            1
#define TSC_NR_CLOSE            3
#define TSC_NR_MMAP             9
#define TSC_NR_IOCTL            16
#define TSC_NR_SOCKET           41
#define TSC_NR_CONNECT          42
#define TSC_NR_BIND             49
#define TSC_NR_SENDTO           44
#define TSC_NR_RECVFROM         45
#define TSC_NR_CLONE            56
#define TSC_NR_OPENAT           257

/* --- Syscall event (recorded per-call) --- */
struct tsc_event {
    u32     subject_id;         /* Trust subject that made this call */
    pid_t   pid;                /* Linux PID */
    u16     syscall_nr;         /* Syscall number */
    u8      category;           /* TSC_CAT_* */
    u8      _pad;
    u64     arg0;               /* First argument */
    u64     arg1;               /* Second argument */
    u64     arg2;               /* Third argument */
    s64     return_value;       /* Return value (from kretprobe) */
    u64     timestamp_ns;       /* ktime_get_ns() at entry */
};

/* --- Per-PID tracking slot --- */
struct tsc_pid_slot {
    pid_t   pid;
    u32     subject_id;
    bool    active;
    u8      category_mask;      /* Which categories to trace */
    u8      _pad[2];

    /* Ring buffer of recent events */
    struct tsc_event ring[TSC_RING_SIZE];
    u32     ring_head;          /* Next write position */
    u32     ring_count;         /* Total events recorded (wraps) */
    spinlock_t lock;

    /* Per-syscall counters */
    u64     stats[512];         /* Indexed by syscall number */
};

/* --- Netlink event message (sent to userspace) --- */
struct tsc_event_msg {
    u32     seq;                /* Monotonic sequence number */
    u32     subject_id;
    pid_t   pid;
    u16     syscall_nr;
    u8      category;
    u8      _pad;
    u64     arg0;
    u64     arg1;
    u64     arg2;
    s64     return_value;
    u64     timestamp_ns;
};

/* --- ioctl structures --- */

/* Start/stop tracing for a PID */
typedef struct {
    u32     subject_id;
    pid_t   pid;
    u8      category_mask;      /* TSC_CAT_* bitmask */
    u8      _pad[3];
    int32_t result;             /* Output: 0=ok, <0=error */
} tsc_ioc_trace_t;

/* Get syscall stats for a PID */
typedef struct {
    pid_t   pid;
    u32     max_entries;        /* Max syscall stat entries caller wants */
    u32     returned;           /* Output: actual entries returned */
    u32     _padding;
    u64     buf;                /* Userspace pointer to u64[512] */
} tsc_ioc_stats_t;

/* Get recent events for a PID */
typedef struct {
    pid_t   pid;
    u32     max_events;         /* Max events caller wants */
    u32     returned;           /* Output: actual events returned */
    u32     total;              /* Output: total events recorded (may wrap) */
    u64     buf;                /* Userspace pointer to struct tsc_event[] */
} tsc_ioc_events_t;

/* --- ioctl numbers (continue from TMS at 110-113, CMD at 100) --- */
#define TRUST_IOC_TSC_START_TRACE   _IOWR('T', 120, tsc_ioc_trace_t)
#define TRUST_IOC_TSC_STOP_TRACE    _IOWR('T', 121, tsc_ioc_trace_t)
#define TRUST_IOC_TSC_GET_STATS     _IOWR('T', 122, tsc_ioc_stats_t)
#define TRUST_IOC_TSC_GET_EVENTS    _IOWR('T', 123, tsc_ioc_events_t)

/* --- API functions (called from trust_core.c) --- */

int  tsc_init(void);
void tsc_cleanup(void);

int  tsc_start_trace(u32 subject_id, pid_t pid, u8 category_mask);
void tsc_stop_trace(pid_t pid);

/* Query interface */
struct tsc_pid_slot *tsc_find_slot_by_pid(pid_t pid);
int  tsc_is_pid_traced(pid_t pid);

/* ioctl handler (dispatched from trust_core.c) */
long tsc_ioctl(unsigned int cmd, unsigned long arg);

#endif /* TRUST_SYSCALL_H */
