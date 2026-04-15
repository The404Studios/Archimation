/*
 * iouring_stats_priv.h — PRIVATE to the measurement layer.
 */
#ifndef COH_IOURING_STATS_PRIV_H
#define COH_IOURING_STATS_PRIV_H

/*
 * Fetch io_uring stats from the AI daemon. Cached 250ms.
 * Returns 0 on fresh success, -EAGAIN if returning cached-but-stale-failed,
 * or negative errno otherwise. On any failure, the out-pointers still hold
 * the last-known values (possibly zero), so the caller can always rely on
 * reading finite numbers.
 */
int iouring_stats_fetch(double *sq_depth_out, double *sq_lat_us_out);

/*
 * Fetch thermal packed from the AI daemon. Same contract.
 */
int thermal_packed_fetch(double *temp_c_out);

/*
 * Wipe caches (used in measurement_shutdown()).
 */
int iouring_stats_reset_cache(void);

#endif /* COH_IOURING_STATS_PRIV_H */
