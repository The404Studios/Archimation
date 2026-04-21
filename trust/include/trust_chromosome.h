/*
 * trust_chromosome.h - 23-pair Chromosomal Authority Side-Table
 *
 * Implements the Roberts/Eli/Leelee Root of Authority spec
 * (Zenodo 18710335, sec. Chromosomal Proof Structure):
 *
 *   Parent A (runtime/behavioral): 23 named u64 segments
 *   Parent B (construction/hardware): 23 named u64 segments
 *
 * Stored on the side (not in trust_subject_t — that struct is locked at
 * 496 B). Indexed by subject_id in an RCU-readable hashtable. Keyed
 * lookups are RCU-safe; mutators take a spinlock.
 *
 * Per-subject memory: sizeof(struct trust_chromosome_pair) = 23*8*2 = 368 B.
 */

#ifndef TRUST_CHROMOSOME_H
#define TRUST_CHROMOSOME_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t  u8;
#endif

/* Forward declaration (full definition in trust_internal.h) */
struct trust_subject;

#define TRUST_CHR_A_COUNT 23
#define TRUST_CHR_B_COUNT 23

/* ----- Named A-segment indices (Parent A — runtime/behavioral) ----- */
enum trust_chr_a_idx {
    TRUST_CHR_A_ACTION_HASH        = 0,
    TRUST_CHR_A_TOKEN_BALANCE      = 1,
    TRUST_CHR_A_TRUST_STATE        = 2,
    TRUST_CHR_A_NONCE              = 3,
    TRUST_CHR_A_TIMESTAMP          = 4,
    TRUST_CHR_A_RING_LEVEL         = 5,
    TRUST_CHR_A_GATE_RECORD        = 6,
    TRUST_CHR_A_RESISTANCE_VALUE   = 7,
    TRUST_CHR_A_HYSTERESIS_STATE   = 8,
    TRUST_CHR_A_ENTITY_ID          = 9,
    TRUST_CHR_A_THERMAL_READING    = 10,
    TRUST_CHR_A_MEMORY_USAGE       = 11,
    TRUST_CHR_A_INSTRUCTION_COUNT  = 12,
    TRUST_CHR_A_INTERRUPT_STATE    = 13,
    TRUST_CHR_A_BUS_ACTIVITY       = 14,
    TRUST_CHR_A_CACHE_STATE        = 15,
    TRUST_CHR_A_EXECUTION_PATH     = 16,
    TRUST_CHR_A_STACK_DEPTH        = 17,
    TRUST_CHR_A_PERIPHERAL_ACCESS  = 18,
    TRUST_CHR_A_POWER_DRAW         = 19,
    TRUST_CHR_A_CLOCK_DELTA        = 20,
    TRUST_CHR_A_ECC_ERROR_COUNT    = 21,
    TRUST_CHR_A_PROOF_FRAGMENT_XY  = 22,  /* low bit = X(0)/Y(1) */
};

/* ----- Named B-segment indices (Parent B — construction/hardware) ----- */
enum trust_chr_b_idx {
    TRUST_CHR_B_FIRMWARE_HASH            = 0,
    TRUST_CHR_B_FUSE_CONFIG              = 1,
    TRUST_CHR_B_SILICON_LOT_ID           = 2,
    TRUST_CHR_B_BOOT_CHAIN_HASH          = 3,
    TRUST_CHR_B_MICROCODE_VERSION        = 4,
    TRUST_CHR_B_HW_TOPOLOGY              = 5,
    TRUST_CHR_B_PIN_CONFIG               = 6,
    TRUST_CHR_B_VOLTAGE_RAIL             = 7,
    TRUST_CHR_B_CLOCK_TREE               = 8,
    TRUST_CHR_B_MEMORY_MAP               = 9,
    TRUST_CHR_B_INTERRUPT_VECTOR_TABLE   = 10,
    TRUST_CHR_B_DMA_CONFIG               = 11,
    TRUST_CHR_B_BUS_ARBITRATION          = 12,
    TRUST_CHR_B_THERMAL_DESIGN           = 13,
    TRUST_CHR_B_POWER_DELIVERY           = 14,
    TRUST_CHR_B_DEBUG_STATE_REGISTER     = 15,
    TRUST_CHR_B_SECURITY_FUSES           = 16,
    TRUST_CHR_B_ROM_CHECKSUM             = 17,
    TRUST_CHR_B_PLL_CONFIG               = 18,
    TRUST_CHR_B_IO_MUX_ROUTING           = 19,
    TRUST_CHR_B_REDUNDANCY_PATH          = 20,
    TRUST_CHR_B_MANUFACTURING_TEST_HASH  = 21,
    TRUST_CHR_B_HW_SEED_FRAGMENT_X       = 22,  /* always X — low bit = 0 */
};

/* ----- Storage structs ----- */
struct trust_chromosome_a { u64 v[TRUST_CHR_A_COUNT]; };
struct trust_chromosome_b { u64 v[TRUST_CHR_B_COUNT]; };

struct trust_chromosome_pair {
    struct trust_chromosome_a a;
    struct trust_chromosome_b b;
};

#ifdef __KERNEL__

/* ===================================================================
 * S68 Agent E audit removal: 8 orphan declarations deleted.
 *
 * The block below (trust_chromosome_alloc/free/get/zero_a/copy_b/
 * blind_a_pick/populate_a_runtime/populate_b_hardware) was specified
 * by S48 Agent 7 but never implemented -- no matching definitions
 * exist in trust/kernel/trust_chromosome.c and grep across .c/.h/.py
 * finds ZERO callers outside this header. They were a link-time
 * failure waiting for a caller to appear. If/when a caller needs
 * these semantics, re-declare here AND add the definition in one
 * atomic change. The lower-level trust_chromosome_{init,update_*,
 * verify,inherit} API in trust_chromosome.c remains untouched.
 * =================================================================== */

/* Init/teardown (called from trust module init/exit) */
int  trust_chromosome_table_init(void);
void trust_chromosome_table_exit(void);

#endif /* __KERNEL__ */

/* ===================================================================
 * Named getter macros — emit one inline per spec'd segment (46 total).
 *
 * GENERATE_CHR_A(name, idx) -> chr_a_<name>(c) returns c->a.v[idx]
 *                          and chr_a_set_<name>(c, val) writes c->a.v[idx]
 * GENERATE_CHR_B(name, idx) -> mirrors for B.
 *
 * All callers must hold rcu_read_lock if they obtained `c` via
 * trust_chromosome_get(). Setters are intended for in-place mutation
 * by the populate_*() helpers — outside that, take the table spinlock.
 * =================================================================== */
#define _TRUST_CHR_DEFINE_AB_GETTERS(letter, name, idx) \
    static inline u64 chr_##letter##_##name(const struct trust_chromosome_pair *c) \
    { return c->letter.v[idx]; } \
    static inline void chr_##letter##_set_##name(struct trust_chromosome_pair *c, u64 val) \
    { c->letter.v[idx] = val; }

/* --- A-segment named accessors (23) --- */
_TRUST_CHR_DEFINE_AB_GETTERS(a, action_hash,        TRUST_CHR_A_ACTION_HASH)
_TRUST_CHR_DEFINE_AB_GETTERS(a, token_balance,      TRUST_CHR_A_TOKEN_BALANCE)
_TRUST_CHR_DEFINE_AB_GETTERS(a, trust_state,        TRUST_CHR_A_TRUST_STATE)
_TRUST_CHR_DEFINE_AB_GETTERS(a, nonce,              TRUST_CHR_A_NONCE)
_TRUST_CHR_DEFINE_AB_GETTERS(a, timestamp,          TRUST_CHR_A_TIMESTAMP)
_TRUST_CHR_DEFINE_AB_GETTERS(a, ring_level,         TRUST_CHR_A_RING_LEVEL)
_TRUST_CHR_DEFINE_AB_GETTERS(a, gate_record,        TRUST_CHR_A_GATE_RECORD)
_TRUST_CHR_DEFINE_AB_GETTERS(a, resistance_value,   TRUST_CHR_A_RESISTANCE_VALUE)
_TRUST_CHR_DEFINE_AB_GETTERS(a, hysteresis_state,   TRUST_CHR_A_HYSTERESIS_STATE)
_TRUST_CHR_DEFINE_AB_GETTERS(a, entity_id,          TRUST_CHR_A_ENTITY_ID)
_TRUST_CHR_DEFINE_AB_GETTERS(a, thermal_reading,    TRUST_CHR_A_THERMAL_READING)
_TRUST_CHR_DEFINE_AB_GETTERS(a, memory_usage,       TRUST_CHR_A_MEMORY_USAGE)
_TRUST_CHR_DEFINE_AB_GETTERS(a, instruction_count,  TRUST_CHR_A_INSTRUCTION_COUNT)
_TRUST_CHR_DEFINE_AB_GETTERS(a, interrupt_state,    TRUST_CHR_A_INTERRUPT_STATE)
_TRUST_CHR_DEFINE_AB_GETTERS(a, bus_activity,       TRUST_CHR_A_BUS_ACTIVITY)
_TRUST_CHR_DEFINE_AB_GETTERS(a, cache_state,        TRUST_CHR_A_CACHE_STATE)
_TRUST_CHR_DEFINE_AB_GETTERS(a, execution_path,     TRUST_CHR_A_EXECUTION_PATH)
_TRUST_CHR_DEFINE_AB_GETTERS(a, stack_depth,        TRUST_CHR_A_STACK_DEPTH)
_TRUST_CHR_DEFINE_AB_GETTERS(a, peripheral_access,  TRUST_CHR_A_PERIPHERAL_ACCESS)
_TRUST_CHR_DEFINE_AB_GETTERS(a, power_draw,         TRUST_CHR_A_POWER_DRAW)
_TRUST_CHR_DEFINE_AB_GETTERS(a, clock_delta,        TRUST_CHR_A_CLOCK_DELTA)
_TRUST_CHR_DEFINE_AB_GETTERS(a, ecc_error_count,    TRUST_CHR_A_ECC_ERROR_COUNT)
_TRUST_CHR_DEFINE_AB_GETTERS(a, proof_fragment_xy,  TRUST_CHR_A_PROOF_FRAGMENT_XY)

/* --- B-segment named accessors (23) --- */
_TRUST_CHR_DEFINE_AB_GETTERS(b, firmware_hash,           TRUST_CHR_B_FIRMWARE_HASH)
_TRUST_CHR_DEFINE_AB_GETTERS(b, fuse_config,             TRUST_CHR_B_FUSE_CONFIG)
_TRUST_CHR_DEFINE_AB_GETTERS(b, silicon_lot_id,          TRUST_CHR_B_SILICON_LOT_ID)
_TRUST_CHR_DEFINE_AB_GETTERS(b, boot_chain_hash,         TRUST_CHR_B_BOOT_CHAIN_HASH)
_TRUST_CHR_DEFINE_AB_GETTERS(b, microcode_version,       TRUST_CHR_B_MICROCODE_VERSION)
_TRUST_CHR_DEFINE_AB_GETTERS(b, hw_topology,             TRUST_CHR_B_HW_TOPOLOGY)
_TRUST_CHR_DEFINE_AB_GETTERS(b, pin_config,              TRUST_CHR_B_PIN_CONFIG)
_TRUST_CHR_DEFINE_AB_GETTERS(b, voltage_rail,            TRUST_CHR_B_VOLTAGE_RAIL)
_TRUST_CHR_DEFINE_AB_GETTERS(b, clock_tree,              TRUST_CHR_B_CLOCK_TREE)
_TRUST_CHR_DEFINE_AB_GETTERS(b, memory_map,              TRUST_CHR_B_MEMORY_MAP)
_TRUST_CHR_DEFINE_AB_GETTERS(b, interrupt_vector_table,  TRUST_CHR_B_INTERRUPT_VECTOR_TABLE)
_TRUST_CHR_DEFINE_AB_GETTERS(b, dma_config,              TRUST_CHR_B_DMA_CONFIG)
_TRUST_CHR_DEFINE_AB_GETTERS(b, bus_arbitration,         TRUST_CHR_B_BUS_ARBITRATION)
_TRUST_CHR_DEFINE_AB_GETTERS(b, thermal_design,          TRUST_CHR_B_THERMAL_DESIGN)
_TRUST_CHR_DEFINE_AB_GETTERS(b, power_delivery,          TRUST_CHR_B_POWER_DELIVERY)
_TRUST_CHR_DEFINE_AB_GETTERS(b, debug_state_register,    TRUST_CHR_B_DEBUG_STATE_REGISTER)
_TRUST_CHR_DEFINE_AB_GETTERS(b, security_fuses,          TRUST_CHR_B_SECURITY_FUSES)
_TRUST_CHR_DEFINE_AB_GETTERS(b, rom_checksum,            TRUST_CHR_B_ROM_CHECKSUM)
_TRUST_CHR_DEFINE_AB_GETTERS(b, pll_config,              TRUST_CHR_B_PLL_CONFIG)
_TRUST_CHR_DEFINE_AB_GETTERS(b, io_mux_routing,          TRUST_CHR_B_IO_MUX_ROUTING)
_TRUST_CHR_DEFINE_AB_GETTERS(b, redundancy_path,         TRUST_CHR_B_REDUNDANCY_PATH)
_TRUST_CHR_DEFINE_AB_GETTERS(b, manufacturing_test_hash, TRUST_CHR_B_MANUFACTURING_TEST_HASH)
_TRUST_CHR_DEFINE_AB_GETTERS(b, hw_seed_fragment_x,      TRUST_CHR_B_HW_SEED_FRAGMENT_X)

#endif /* TRUST_CHROMOSOME_H */
