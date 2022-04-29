#ifndef VMM_H
#define VMM_H

#include "ia32_compact.h"

struct vmm_init_params {
    __attribute__((aligned(0x10))) cr3 guest_cr3;
    __attribute__((aligned(0x10))) cr3 host_cr3;
    __attribute__((aligned(0x10))) segment_descriptor_register_64 guest_idtr;
    __attribute__((aligned(0x10))) segment_descriptor_register_64 host_idtr;
};

void vmm_init(struct vmm_init_params *params);

#endif /* VMM_H */