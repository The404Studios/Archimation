/*
 * trust_uapi.h - Root of Authority Userspace API
 *
 * Convenience header: includes all user-facing types, constants,
 * and ioctl definitions needed to interact with /dev/trust.
 *
 * Implements the Dynamic Hyperlation architecture:
 *   Self-Consuming Proof Chains, Chromosomal Authority Model,
 *   Token Economy, Mitotic/Meiotic Lifecycle, Immune Response
 *
 * Userspace callers should include this single header.
 */

#ifndef TRUST_UAPI_H
#define TRUST_UAPI_H

#include "trust_types.h"
#include "trust_ioctl.h"

/* /dev/trust device path */
#define TRUST_DEVICE_PATH   "/dev/trust"

/* Module/version info for userspace tools */
#define TRUST_MODULE_NAME   "trust"
#define TRUST_VERSION_MAJOR 1
#define TRUST_VERSION_MINOR 0

/* Architecture identifier */
#define TRUST_ARCHITECTURE  "Root of Authority (Dynamic Hyperlation)"

/* Helper: default capabilities for a given authority level */
static inline uint32_t trust_default_caps(uint32_t authority)
{
    switch (authority) {
    case TRUST_AUTH_KERNEL:  return TRUST_CAPS_KERNEL;
    case TRUST_AUTH_ADMIN:   return TRUST_CAPS_ADMIN;
    case TRUST_AUTH_SERVICE: return TRUST_CAPS_SERVICE;
    case TRUST_AUTH_USER:    return TRUST_CAPS_USER;
    default:                 return 0;
    }
}

/* Helper: default initial score for a given authority level */
static inline int32_t trust_default_score(uint32_t authority)
{
    switch (authority) {
    case TRUST_AUTH_KERNEL:  return TRUST_SCORE_MAX;
    case TRUST_AUTH_ADMIN:   return 700;
    case TRUST_AUTH_SERVICE: return 400;
    case TRUST_AUTH_USER:    return TRUST_SCORE_DEFAULT;
    default:                 return 0;
    }
}

#endif /* TRUST_UAPI_H */
