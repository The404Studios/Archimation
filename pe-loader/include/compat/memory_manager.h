#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include <stddef.h>
#include <stdint.h>

void *mem_reserve(void *addr, size_t size, uint32_t type);
int   mem_commit(void *addr, size_t size, uint32_t protect);
int   mem_decommit(void *addr, size_t size);
int   mem_release(void *addr);
int   mem_protect(void *addr, size_t size, uint32_t new_protect, uint32_t *old_protect);
int   mem_query(void *addr, void *info, size_t info_size);

#endif /* MEMORY_MANAGER_H */
