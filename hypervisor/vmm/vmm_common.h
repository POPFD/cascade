#ifndef VMM_COMMON_H
#define VMM_COMMON_H

#include "platform/intrin.h"
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

/*
 * Holds whether a vCPU currently has a cached interrupt
 * to deliver to the guest.
 *
 * No synchronisation method is needed for this as
 * set/get of this structure will happen within same
 * vCPU.
 *
 * TODO: HOWEVER we should probably account for multiple
 * interrupts happening within same VMEXIT frame eventually.
 */
struct cached_interrupt {
    exception_vector vector;
    exception_error_code code;
    bool pending;
};

/* Holds the global context for the VMM. */
struct vmm_ctx {
    __attribute__ ((aligned (PAGE_SIZE))) uint8_t msr_trap_bitmap[PAGE_SIZE];

    struct vmm_init_params init;
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
    struct cached_interrupt cached_int;

    struct vmm_ctx *vmm;
    bool running_as_guest;
};

static inline struct vcpu_ctx *vmm_get_vcpu_ctx(void)
{
    /* 
     * Dirty hack, as GS_BASE is actually unused on x86_64
     * we can use this field in the host context to store/retrieve
     * the vCPU context pointer.
     */
    struct vcpu_ctx *vcpu = (struct vcpu_ctx *)__vmread(VMCS_HOST_GS_BASE);
    die_on(!vcpu, "vCPU context not correct.");
    return vcpu;
}

static inline void vmm_set_cached_interrupt(exception_vector vector, exception_error_code code)
{
    struct vcpu_ctx *vcpu = vmm_get_vcpu_ctx();

    vcpu->cached_int.vector = vector;
    vcpu->cached_int.code = code;
    vcpu->cached_int.pending = true;
}

#endif /* VMM_COMMON_H */