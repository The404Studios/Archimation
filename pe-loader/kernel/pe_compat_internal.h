/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PE_COMPAT_INTERNAL_H
#define PE_COMPAT_INTERNAL_H

/*
 * pe_compat kernel module - internal header
 *
 * Shared declarations between the pe_compat kernel module source files.
 * This header is NOT exported to userspace; the userspace interface is
 * defined in include/compat/pe_compat_ioctl.h.
 */

#include <linux/types.h>

/* Module parameters (defined in pe_compat_main.c) */
extern int pe_debug;
extern int pe_syscall_mode;

/* pe_compat_binfmt.c */
int pe_binfmt_register(void);
void pe_binfmt_unregister(void);

/* pe_compat_syscall.c */
int pe_syscall_init(void);
void pe_syscall_cleanup(void);
u64 pe_syscall_intercepted_count(void);

/* pe_compat_memory.c */
void pe_memory_init(void);
long pe_memory_ioctl(unsigned int cmd, unsigned long arg);

/* pe_compat_ioctl.c */
int pe_ioctl_init(void);
void pe_ioctl_cleanup(void);

/* pe_compat_process.c */
int pe_process_init(void);
void pe_process_cleanup(void);
int pe_process_register(pid_t pid, u64 image_base, u64 image_size,
			u32 subsystem, u32 nt_version);
int pe_process_unregister(pid_t pid);
bool pe_process_is_pe(pid_t pid);
u32 pe_process_count(void);

#endif /* PE_COMPAT_INTERNAL_H */
