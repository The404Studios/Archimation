/*
 * trust_dna_gate.c - DNA Gate: Privilege Translation Bridge
 *
 * The DNA Gate sits between Windows and Linux privilege domains.
 * It handles:
 *   1. Capability translation (Trust caps <-> Linux capabilities)
 *   2. Threshold enforcement per cross-domain translation
 *   3. Bridge/Separation: PE processes access Linux through the Gate
 *
 * The IRNA Translator (NT SECURITY_DESCRIPTOR <-> uid/gid/mode)
 * is conceptually part of this module but implemented as stubs
 * until full NT security descriptor support is needed.
 */

#include <linux/module.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include "trust_internal.h"

/*
 * Static translation table:
 * Maps trust capabilities to Linux capabilities and minimum trust scores.
 *
 * trust_cap           -> linux_cap         -> min_score
 * TRUST_CAP_FILE_READ    (none)               100
 * TRUST_CAP_NET_CONNECT  (none)               200
 * TRUST_CAP_NET_LISTEN   CAP_NET_BIND_SERVICE 400
 * TRUST_CAP_PROCESS_CREATE (none)             300
 * TRUST_CAP_DEVICE_ACCESS CAP_SYS_RAWIO       600
 * TRUST_CAP_KERNEL_CALL   CAP_SYS_ADMIN       900
 */

static const cap_translation_entry_t g_translations[] = {
    { TRUST_CAP_FILE_READ,      -1,                     100  },
    { TRUST_CAP_FILE_WRITE,     -1,                     150  },
    { TRUST_CAP_NET_CONNECT,    -1,                     200  },
    { TRUST_CAP_NET_LISTEN,     CAP_NET_BIND_SERVICE,   400  },
    { TRUST_CAP_PROCESS_CREATE, -1,                     300  },
    { TRUST_CAP_PROCESS_SIGNAL, CAP_KILL,               350  },
    { TRUST_CAP_REGISTRY_READ,  -1,                     50   },
    { TRUST_CAP_REGISTRY_WRITE, -1,                     200  },
    { TRUST_CAP_DEVICE_ACCESS,  CAP_SYS_RAWIO,          600  },
    { TRUST_CAP_SERVICE_CONTROL,-1,                     400  },
    { TRUST_CAP_FIREWALL_MODIFY,CAP_NET_ADMIN,          500  },
    { TRUST_CAP_TRUST_MODIFY,   -1,                     700  },
    { TRUST_CAP_AI_CONTROL,     -1,                     800  },
    { TRUST_CAP_KERNEL_CALL,    CAP_SYS_ADMIN,          900  },
};

#define NUM_TRANSLATIONS (sizeof(g_translations) / sizeof(g_translations[0]))

void trust_dna_gate_init(void)
{
    pr_info("trust: DNA Gate initialized with %lu translation entries\n",
            (unsigned long)NUM_TRANSLATIONS);
}

/*
 * trust_dna_gate_check - Check if a subject can use a trust capability
 *
 * This is the fast-path check: does the subject have sufficient trust
 * score for the requested capability's translation threshold?
 */
int trust_dna_gate_check(u32 subject_id, u32 trust_cap)
{
    trust_subject_t subj;
    size_t i;

    if (trust_tlb_lookup(subject_id, &subj) < 0)
        return -1;

    if (subj.flags & TRUST_FLAG_FROZEN)
        return -1;

    for (i = 0; i < NUM_TRANSLATIONS; i++) {
        if (g_translations[i].trust_cap == trust_cap) {
            /* Check minimum trust score */
            if (subj.trust_score < g_translations[i].min_score)
                return -1;

            /* Check Linux capability if required.
             * ns_capable() checks if the calling process (current)
             * has the required capability in its user namespace. */
            if (g_translations[i].linux_cap >= 0) {
                if (!ns_capable(current_user_ns(),
                                g_translations[i].linux_cap)) {
                    pr_debug("trust: DNA Gate: subject %u lacks Linux cap %d\n",
                             subject_id, g_translations[i].linux_cap);
                    return -1;
                }
            }

            return 0; /* Allowed */
        }
    }

    /* No translation entry found: deny by default */
    return -1;
}

/*
 * trust_dna_gate_translate - Cross-domain capability transfer
 *
 * When a PE process (Win32 domain) needs to access a Linux resource,
 * this function checks:
 *   1. The subject has the trust capability in the source domain
 *   2. The subject meets the translation threshold
 *   3. Any required Linux capabilities are present
 *
 * Returns 0 on success (transfer allowed), -1 on denial.
 */
int trust_dna_gate_translate(u32 subject_id, u32 trust_cap,
                             u16 from_domain, u16 to_domain)
{
    trust_subject_t subj;
    size_t i;

    if (trust_tlb_lookup(subject_id, &subj) < 0)
        return -1;

    /* Verify the subject is in the source domain */
    if (subj.domain != from_domain) {
        pr_warn("trust: DNA Gate: subject %u domain mismatch (%u != %u)\n",
                subject_id, subj.domain, from_domain);
        return -1;
    }

    /* Check each capability bit in the request */
    for (i = 0; i < NUM_TRANSLATIONS; i++) {
        if (!(trust_cap & g_translations[i].trust_cap))
            continue;

        /* Must have the capability in current set */
        if (!(subj.capabilities & g_translations[i].trust_cap)) {
            pr_debug("trust: DNA Gate: subject %u lacks cap 0x%x\n",
                     subject_id, g_translations[i].trust_cap);
            return -1;
        }

        /* Must meet minimum score threshold */
        if (subj.trust_score < g_translations[i].min_score) {
            pr_debug("trust: DNA Gate: subject %u score %d < required %d for cap 0x%x\n",
                     subject_id, subj.trust_score,
                     g_translations[i].min_score,
                     g_translations[i].trust_cap);
            return -1;
        }

        /* Verify the calling process has required Linux capabilities */
        if (g_translations[i].linux_cap >= 0) {
            if (!ns_capable(current_user_ns(),
                            g_translations[i].linux_cap)) {
                pr_debug("trust: DNA Gate: caller lacks Linux cap %d for trust cap 0x%x\n",
                         g_translations[i].linux_cap,
                         g_translations[i].trust_cap);
                return -1;
            }
        }
    }

    /* Record the cross-domain transfer action */
    trust_risc_record_action(subject_id, TRUST_ACTION_DOMAIN_TRANSFER, 0);

    pr_debug("trust: DNA Gate: subject %u transfer domain %u->%u caps=0x%x OK\n",
             subject_id, from_domain, to_domain, trust_cap);

    (void)to_domain;
    return 0;
}

MODULE_LICENSE("GPL");
