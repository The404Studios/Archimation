/*
 * trust_algedonic.h — Beer VSM algedonic ("pain/pleasure") bypass channel.
 *
 * S74 Agent 8, Cluster 2B. Implements Stafford Beer's Viable System Model
 * primitive: a sub-millisecond kernel->cortex signalling path that bypasses
 * the normal perception->decision chain during emergencies. Packets are
 * fixed-size (40 B, cache-line-friendly), queued lock-free in a 64-slot
 * ring, and readable from userspace via /dev/trust_algedonic.
 *
 * Userspace reader pattern:
 *   fd = open("/dev/trust_algedonic", O_RDONLY);
 *   while (read(fd, &pkt, sizeof(pkt)) == sizeof(pkt)) {
 *       cortex_event_bus.dispatch(pkt);
 *   }
 *
 * See docs/architecture-meta-exploit-s73.md §Cluster 2B.
 */

#ifndef TRUST_ALGEDONIC_H
#define TRUST_ALGEDONIC_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
#endif

/* Reason codes — why the bypass fired. Keep stable (userspace ABI). */
enum trust_alg_reason {
    TRUST_ALG_POOL_EXHAUSTION            = 1, /* subject_pool near full */
    TRUST_ALG_APE_EXHAUSTION             = 2, /* APE proof pool depleted */
    TRUST_ALG_CASCADE_APOPTOSIS          = 3, /* apoptotic cascade > N deep */
    TRUST_ALG_QUORUM_DISPUTED_REPEATEDLY = 4, /* chromosomal quorum fails */
    TRUST_ALG_MORPHOGEN_HOT_SPOT         = 5, /* 32x32 field INFLAMED zone */
    TRUST_ALG_CANCER_DETECTED            = 6, /* runaway spawn */
    TRUST_ALG_TPM_DRIFT                  = 7, /* PCR 11 mismatch */
    TRUST_ALG_PROOF_CHAIN_BREAK          = 8, /* self-consuming chain broke */
    TRUST_ALG_TOKEN_STARVATION_STORM     = 9, /* many subjects starving */
    TRUST_ALG_MAX
};

/* Severity thresholds. Userspace may down-rank but >32768 is "critical". */
#define TRUST_ALG_SEVERITY_INFO      1024
#define TRUST_ALG_SEVERITY_WARN      16384
#define TRUST_ALG_SEVERITY_CRITICAL  32768
#define TRUST_ALG_SEVERITY_MAX       65535

/* Wire format — 40 bytes, fits one cache line with room for tail metadata. */
struct trust_algedonic_packet {
    __u64 ts_ns;            /* ktime_get_ns() at emission */
    __u32 subject_pid;      /* PID or 0 for system-wide */
    __u16 severity;         /* 0..65535; >32768 => critical */
    __u16 reason;           /* TRUST_ALG_* */
    __u64 data[3];          /* reason-specific payload */
} __attribute__((packed));

#ifdef __KERNEL__

/* Kernel-side emit. Non-sleeping, safe from IRQ/softirq/task context.
 * Returns 0 on success, -ENOSPC if the ring dropped (oldest evicted). */
int trust_algedonic_emit(__u32 subject_pid, __u16 severity, __u16 reason,
                         const __u64 data[3]);

/* Module init/exit (called from trust_core). */
int  trust_algedonic_init(void);
void trust_algedonic_exit(void);

#endif /* __KERNEL__ */

#endif /* TRUST_ALGEDONIC_H */
