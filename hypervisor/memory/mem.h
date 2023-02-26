#ifndef MEM_H
#define MEM_H

#include "platform/standard.h"
#include "ia32_compact.h"

enum copy_dir {
    COPY_READ,
    COPY_WRITE
};

uintptr_t mem_va_to_pa(cr3 table, void *va);
bool mem_copy_virt_tofrom_host(enum copy_dir dir, cr3 table,
                             uintptr_t addr, void *buffer, size_t size);
bool mem_copy_virt_to_virt(cr3 src_cr3, void *src, cr3 dest_cr3, void *dest, size_t size);


#endif /* MEM_H */