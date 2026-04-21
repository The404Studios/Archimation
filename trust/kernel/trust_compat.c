/*
 * trust_compat.c - Compile-time anchor for trust_compat.h
 *
 * Session 49 (2026-04-18, Agent E).  The actual compatibility helper
 * (trust_find_task_by_vpid_get) is a static inline in trust_compat.h so
 * it can be used from any translation unit without an extra call frame.
 *
 * This file exists so:
 *   1. Kbuild has a real .o to link, matching the Session-49 deliverable.
 *   2. We get a single compile-time check that <linux/pid.h>'s
 *      find_get_pid / get_pid_task / put_pid are visible to us — if a
 *      future kernel ever drops one of those exports too, this TU fails
 *      to build at exactly one site instead of every caller.
 *   3. There is a stable place to add additional version shims (e.g.
 *      kallsyms-based fallbacks) if Option-A ever becomes insufficient.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include "trust_compat.h"

/*
 * Compile-time sanity: take the address of each exported symbol we depend
 * on.  If any of them is unavailable to module scope this TU will fail to
 * link, giving a much clearer error than a downstream caller would.
 */
static void * const __maybe_unused trust_compat_export_check[] = {
	(void *)find_get_pid,
	(void *)get_pid_task,
	(void *)put_pid,
};
