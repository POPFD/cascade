#ifndef PMEM_H
#define PMEM_H

#include <stddef.h>
#include <stdint.h>

void pmem_init(void);
uintptr_t pmem_alloc_page(void);
uintptr_t pmem_alloc_contiguous(size_t bytes);
void pmem_free_page(uintptr_t page);

#endif /* PMEM_H */