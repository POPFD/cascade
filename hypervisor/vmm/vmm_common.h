#ifndef VMM_COMMON_H
#define VMM_COMMON_H

#include "vmm_reg.h"
#include "ia32_compact.h"

/* At max, support up to 100 vCPUs. */
#define VCPU_MAX 100

/* Defines the size of the host stack. */
#define HOST_STACK_SIZE 0x6000

struct vmm_init_params {
    __attribute__((aligned(0x10))) cr3 guest_cr3;
    __attribute__((aligned(0x10))) cr3 host_cr3;
    __attribute__((aligned(0x10))) segment_descriptor_register_64 guest_idtr;
    __attribute__((aligned(0x10))) segment_descriptor_register_64 host_idtr;
};

/* Holds the global context for the VMM. */
struct vmm_ctx {
    __attribute__ ((aligned (PAGE_SIZE))) uint8_t msr_trap_bitmap[PAGE_SIZE];

    struct vmm_init_params init;
    struct vcpu_ctx *vcpu[VCPU_MAX];
    struct ept_ctx *ept;
};

/* Holds the context specific to a singular vCPU. */
struct vcpu_ctx {
    __attribute__ ((aligned (PAGE_SIZE))) uint8_t host_stack[HOST_STACK_SIZE];
    __attribute__ ((aligned (PAGE_SIZE))) vmxon host_vmxon;
    __attribute__ ((aligned (PAGE_SIZE))) vmcs guest_vmcs;

    struct control_registers guest_ctrl_regs;
    struct vcpu_context guest_context;
    struct gdt_config gdt_cfg;

    bool running_as_guest;
};

#endif /* VMM_COMMON_H */