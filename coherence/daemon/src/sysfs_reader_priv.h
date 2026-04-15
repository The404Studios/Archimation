/*
 * sysfs_reader_priv.h — PRIVATE to the measurement layer.
 */
#ifndef COH_SYSFS_READER_PRIV_H
#define COH_SYSFS_READER_PRIV_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Slurp a /sys scalar line; always NUL-terminated. Returns count or -errno. */
ssize_t sf_pread_line(int fd, char *buf, size_t cap);

/* Parse buf as a signed 64-bit decimal. Returns 0 or -EINVAL. */
int sf_parse_i64(const char *buf, size_t len, int64_t *out);

/* Open O_RDONLY|O_CLOEXEC; returns fd or -errno. */
int sf_open_scalar(const char *path);

/* Returns 1 if exists, 0 if ENOENT, -errno on other error. */
int sf_path_exists(const char *path);

#endif /* COH_SYSFS_READER_PRIV_H */
