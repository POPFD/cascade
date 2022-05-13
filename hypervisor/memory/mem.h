#ifndef MEM_H
#define MEM_H

#include "platform/standard.h"
#include "ia32_compact.h"

enum copy_dir {
    COPY_READ,
    COPY_WRITE
};

uintptr_t mem_va_to_pa(cr3 table, void *va);
bool mem_copy_virtual_memory(enum copy_dir dir, cr3 table,
                             uintptr_t addr, void *buffer, size_t size);

#endif /* MEM_H */