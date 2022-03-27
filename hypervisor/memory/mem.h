#ifndef MEM_H
#define MEM_H

#include "platform/standard.h"
#include "ia32_compact.h"

uintptr_t mem_va_to_pa(cr3 table, void *va);

#endif /* MEM_H */