#ifndef VMM_REG_H
#define VMM_REG_H

#include "ia32_compact.h"

struct control_registers {
    cr0 reg_cr0;
    cr3 reg_cr3;
    cr4 reg_cr4;
    uintptr_t gs_base;
    ia32_debugctl_register debugctl;
    uintptr_t dr7;
};

#endif /* VMM_REG_H */