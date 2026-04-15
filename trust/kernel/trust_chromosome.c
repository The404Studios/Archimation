/*
 * trust_chromosome.c - Chromosomal Authority Model
 *
 * Implements the 23-pair chromosomal authority system from the Root of
 * Authority paper. Each subject carries 46 segments (23 pairs):
 *
 *   A-segments (1-23): Runtime behavioral DNA
 *     Continuously updated from live behavior: action patterns, resource
 *     usage, syscall distributions, network patterns, etc.
 *
 *   B-segments (1-23): Construction identity DNA
 *     Computed from static properties: binary hash, library dependencies,
 *     configuration, signatures, hardware identity, etc.
 *
 * The 23rd pair implements XY Sex Determination:
 *   A23 = behavioral conformance score (0-255)
 *   B23 = construction conformance score (0-255)
 *
 *   XX: Both >= theta (conformant) → maintain/renew authority
 *   XY: A23 < theta, B23 >= theta → behavioral divergence → demote
 *   YX: A23 >= theta, B23 < theta → construction divergence → promote
 *   YY: Both < theta → strongly divergent → apoptosis candidate
 *
 * The chromosome is the "DNA" of each entity — it determines identity,
 * behavior classification, and authority transitions. Mutations (segment
 * changes) are tracked and fed back into the trust system.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/crc32.h>
#include "trust_internal.h"

/*
 * Initialize a fresh chromosome for a new subject.
 * All segments start at neutral values. The 23rd pair is set to
 * conformant (XX) by default — new subjects are assumed conformant
 * until proven otherwise.
 */
void trust_chromosome_init(trust_chromosome_t *chromo, u32 subject_id,
                            u32 parent_id, u8 generation)
{
    memset(chromo, 0, sizeof(*chromo));

    /* Set 23rd pair to conformant (above theta) */
    chromo->a_segments[CHROMO_A_SEX] = CHROMO_CONFORMANCE_THETA + 50;
    chromo->b_segments[CHROMO_B_SEX] = CHROMO_CONFORMANCE_THETA + 50;

    chromo->sex = CHROMO_SEX_XX;
    chromo->generation = generation;
    chromo->division_count = 0;
    chromo->parent_id = parent_id;
    chromo->birth_timestamp = ktime_get_ns();
    chromo->mutation_count = 0;
    chromo->checksum = trust_chromosome_checksum(chromo);
}

/*
 * Update a runtime behavioral (A) segment.
 *
 * Performance: the checksum here is a CRC32 over ~200 bytes of data.
 * trust_risc_record_action calls update_a up to 4 times in a row,
 * paying 4x CRC32 even though only the last snapshot matters for
 * readers. We skip the checksum recompute when the new value equals
 * the old (common idle-heartbeat case) and leave the rolling
 * "deferred then flushed" semantics to the caller — the decay timer
 * and immune tick walk live entries and will pick up the stale
 * checksum on the NEXT verify call, which is acceptable for the data
 * integrity check (not crypto).
 *
 * NOTE: we still recompute checksum on every change here because
 * external callers (including the ioctl GET_CHROMOSOME path) rely on
 * checksum being in sync with segments.  For a batch of updates,
 * use trust_chromosome_update_a_deferred and flush with
 * trust_chromosome_finalize.
 */
void trust_chromosome_update_a(trust_chromosome_t *chromo, u32 segment_idx,
                                u32 new_value)
{
    if (segment_idx >= TRUST_CHROMOSOME_PAIRS)
        return;

    if (chromo->a_segments[segment_idx] != new_value) {
        chromo->a_segments[segment_idx] = new_value;
        chromo->mutation_count++;

        /* Recompute sex if 23rd pair changed */
        if (segment_idx == CHROMO_A_SEX)
            chromo->sex = trust_chromosome_determine_sex(chromo);

        chromo->checksum = trust_chromosome_checksum(chromo);
    }
}

/*
 * Update a construction identity (B) segment.
 * Increments mutation count and recomputes sex determination.
 */
void trust_chromosome_update_b(trust_chromosome_t *chromo, u32 segment_idx,
                                u32 new_value)
{
    if (segment_idx >= TRUST_CHROMOSOME_PAIRS)
        return;

    if (chromo->b_segments[segment_idx] != new_value) {
        chromo->b_segments[segment_idx] = new_value;
        chromo->mutation_count++;

        /* Recompute sex if 23rd pair changed */
        if (segment_idx == CHROMO_B_SEX)
            chromo->sex = trust_chromosome_determine_sex(chromo);

        chromo->checksum = trust_chromosome_checksum(chromo);
    }
}

/*
 * Deferred update helpers: batch multiple segment writes and pay only
 * ONE CRC32 at the end.  Used by the hot path trust_risc_record_action
 * which mutates 4 A-segments per call.
 *
 * Performance: record_action on a subject now computes ~1 CRC32 per
 * call instead of 4, reducing a sub-microsecond but highly repetitive
 * cost across every fork, fopen, setsockopt, etc.  On old HW without
 * a CRC32 instruction this matters more than on new HW with SSE4.2.
 */
void trust_chromosome_update_a_deferred(trust_chromosome_t *chromo,
                                         u32 segment_idx, u32 new_value)
{
    if (segment_idx >= TRUST_CHROMOSOME_PAIRS)
        return;
    if (chromo->a_segments[segment_idx] != new_value) {
        chromo->a_segments[segment_idx] = new_value;
        chromo->mutation_count++;
        if (segment_idx == CHROMO_A_SEX)
            chromo->sex = trust_chromosome_determine_sex(chromo);
        /* checksum left stale — caller MUST finalize before unlock */
    }
}

void trust_chromosome_finalize(trust_chromosome_t *chromo)
{
    chromo->checksum = trust_chromosome_checksum(chromo);
}

/*
 * Determine the sex type from the 23rd chromosomal pair.
 *
 * The 23rd pair works like biological sex determination:
 *   A23 and B23 are each compared against theta (conformance threshold).
 *   Values >= theta are "X" (conformant), < theta are "Y" (divergent).
 *
 * Returns CHROMO_SEX_XX/XY/YX/YY.
 */
u8 trust_chromosome_determine_sex(const trust_chromosome_t *chromo)
{
    u32 a23 = chromo->a_segments[CHROMO_A_SEX];
    u32 b23 = chromo->b_segments[CHROMO_B_SEX];
    int a_conformant = (a23 >= CHROMO_CONFORMANCE_THETA);
    int b_conformant = (b23 >= CHROMO_CONFORMANCE_THETA);

    if (a_conformant && b_conformant)
        return CHROMO_SEX_XX;   /* Both conformant: maintain */
    else if (!a_conformant && b_conformant)
        return CHROMO_SEX_XY;   /* Behavioral divergence: demote */
    else if (a_conformant && !b_conformant)
        return CHROMO_SEX_YX;   /* Construction divergence: promote */
    else
        return CHROMO_SEX_YY;   /* Both divergent: apoptosis candidate */
}

/*
 * Compute integrity checksum over all chromosomal segments.
 * Uses CRC32 for speed (this is a kernel data integrity check, not crypto).
 */
u32 trust_chromosome_checksum(const trust_chromosome_t *chromo)
{
    u32 crc;

    /* Hash over both segment arrays */
    crc = crc32(0, (const u8 *)chromo->a_segments,
                sizeof(chromo->a_segments));
    crc = crc32(crc, (const u8 *)chromo->b_segments,
                sizeof(chromo->b_segments));
    /* Include generation and parent in checksum */
    crc = crc32(crc, &chromo->generation, sizeof(chromo->generation));
    crc = crc32(crc, (const u8 *)&chromo->parent_id,
                sizeof(chromo->parent_id));
    return crc;
}

/*
 * Verify chromosome integrity by recomputing checksum.
 * Returns 0 if valid, -EINVAL if corrupted.
 */
int trust_chromosome_verify(const trust_chromosome_t *chromo)
{
    u32 expected = trust_chromosome_checksum(chromo);
    if (chromo->checksum != expected)
        return -EINVAL;
    return 0;
}

/*
 * Inherit chromosome from parent during mitotic division.
 *
 * The child inherits all segments from the parent, but:
 *   - Generation counter is incremented
 *   - Birth timestamp is set to now
 *   - Division count is reset to 0
 *   - Mutation count is reset to 0
 *   - Parent ID is set
 *   - A-segments that reflect runtime state are partially reset
 *     (token balance, trust state trajectory reset to neutral)
 */
void trust_chromosome_inherit(trust_chromosome_t *child,
                               const trust_chromosome_t *parent, u8 gen)
{
    /* Copy all segments from parent */
    memcpy(child->a_segments, parent->a_segments,
           sizeof(child->a_segments));
    memcpy(child->b_segments, parent->b_segments,
           sizeof(child->b_segments));

    /* Reset runtime-specific A-segments for child */
    child->a_segments[CHROMO_A_TOKEN_BALANCE] = 0;   /* Fresh tokens */
    child->a_segments[CHROMO_A_TRUST_STATE] = 0;     /* Fresh trajectory */
    child->a_segments[CHROMO_A_LIFETIME] = 0;         /* Just born */
    child->a_segments[CHROMO_A_SPAWN_RATE] = 0;       /* No spawns yet */

    /* Set child-specific fields */
    child->generation = gen;
    child->division_count = 0;
    child->parent_id = 0;  /* Caller must set this */
    child->birth_timestamp = ktime_get_ns();
    child->mutation_count = 0;

    /* Recompute sex and checksum */
    child->sex = trust_chromosome_determine_sex(child);
    child->checksum = trust_chromosome_checksum(child);
}

/*
 * Compute a rolling hash update for a behavioral A-segment.
 * Used to track action patterns, syscall distributions, etc.
 * The hash uses a simple mixing function suitable for kernel context.
 */
u32 trust_chromosome_rolling_hash(u32 hash_state, u32 new_input)
{
    /* FNV-1a style mixing */
    u32 hash = hash_state ^ new_input;
    hash *= 0x01000193;  /* FNV prime */
    hash ^= (hash >> 16);
    return hash;
}
