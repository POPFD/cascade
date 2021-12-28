#ifndef VMEM_H
#define VMEM_H

#include "platform/standard.h"

#define MEM_READ_ONLY   (0)
#define MEM_WRITE       (1 << 0)
#define MEM_EXECUTE     (1 << 1)

void vmem_init(void);
void *vmem_alloc(size_t size, unsigned int flags);

#endif /* VMEM_H */