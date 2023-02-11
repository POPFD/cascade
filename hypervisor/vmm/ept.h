#ifndef EPT_H
#define EPT_H

#include "ia32_compact.h"

struct ept_ctx *ept_init(void);
eptp *ept_get_pointer(struct ept_ctx *ctx);
ept_pde_2mb *get_ept_pml2e(struct ept_ctx *ctx, uintptr_t phys_addr);
ept_pte *ept_get_pml1e(struct ept_ctx *ctx, uintptr_t phys_addr);
void ept_invalidate_and_flush(struct ept_ctx *ctx);

#endif /* EPT_H */