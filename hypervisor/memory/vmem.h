#ifndef VMEM_H
#define VMEM_H

#include "platform/standard.h"
#include "ia32_compact.h"

#define MEM_READ_ONLY   (0)
#define MEM_WRITE       (1 << 0)
#define MEM_EXECUTE     (1 << 1)

void vmem_init(cr3 *original_cr3, cr3 *new_cr3);
void *vmem_alloc(size_t size, unsigned int flags);
void vmem_change_perms(void *addr, size_t size, unsigned int flags);

#endif /* VMEM_H */