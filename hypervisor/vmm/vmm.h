#ifndef VMM_H
#define VMM_H

#include "ia32_compact.h"

struct vmm_init_params {
    cr3 guest_cr3;
    cr3 host_cr3;
};

void vmm_init(struct vmm_init_params *params);

#endif /* VMM_H */