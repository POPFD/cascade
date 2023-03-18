#ifndef VMM_COMMON_H
#define VMM_COMMON_H

#include <linux/types.h>
#include "platform/intrin.h"
#include "platform/util.h"
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
    uintptr_t image_base;
    size_t image_size;
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
    struct vmm_init_params init;
    struct ept_ctx *ept;
    struct handler_ctx *handler;
    spinlock_t lock;
};

/* Holds the context specific to a singular vCPU. */
struct vcpu_ctx {
    __attribute__ ((aligned (PAGE_SIZE))) uint8_t host_stack[HOST_STACK_SIZE];
    __attribute__ ((aligned (PAGE_SIZE))) vmxon host_vmxon;
    __attribute__ ((aligned (PAGE_SIZE))) vmcs guest_vmcs;
    __attribute__ ((aligned (PAGE_SIZE))) uint8_t msr_trap_bitmap[PAGE_SIZE];

    struct control_registers guest_ctrl_regs;
    struct vcpu_context guest_context;
    struct gdt_config gdt_cfg;
    struct cached_interrupt cached_int;

    struct vmm_ctx *vmm;
    struct nested_ctx *nested;
    size_t idx;

    bool running_as_guest;
    size_t last_ignored_msr;
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

static inline size_t vmm_read_gp_register(struct vcpu_ctx *vcpu, uint64_t base_reg)
{
    assert(base_reg < 16);

    size_t reg_val;
    if (base_reg == 4 /* RSP is 4th in array context. */)
        reg_val = __vmread(VMCS_GUEST_RSP);
    else {
        uint64_t *gp_arr = &vcpu->guest_context.rax;
        reg_val = gp_arr[base_reg];
    }
    return reg_val;
}

static inline size_t vmm_read_seg_register(struct vcpu_ctx *vcpu, uint64_t seg_index)
{
    assert(seg_index < 6);

    switch (seg_index) {
    case 0:
        return vcpu->guest_context.seg_es;
    case 1:
        return vcpu->guest_context.seg_cs;
    case 2:
        return vcpu->guest_context.seg_ss;
    case 3:
        return vcpu->guest_context.seg_ds;
    case 4:
        return vcpu->guest_context.seg_fs;
    case 5:
        return vcpu->guest_context.seg_gs;
    }
}

static inline void vmm_set_cached_interrupt(exception_vector vector, exception_error_code code)
{
    struct vcpu_ctx *vcpu = vmm_get_vcpu_ctx();

    vcpu->cached_int.vector = vector;
    vcpu->cached_int.code = code;
    vcpu->cached_int.pending = true;
}

static inline void vmm_msr_trap_enable(uint8_t *bitmap, size_t msr, bool trap)
{
    static const size_t LOW_START = 0x0;
    static const size_t LOW_END = 0x1fff;
    static const size_t HIGH_START = 0xc0000000;
    static const size_t HIGH_END = 0xc0001fff;

    uint8_t *read_low = &bitmap[0];
    uint8_t *read_high = &bitmap[1024];
    uint8_t *write_low = &bitmap[2048];
    uint8_t *write_high = &bitmap[3072];

    if ((msr >= LOW_START) && (msr <= LOW_END)) {
        if (trap) {
            bitmap_set_bit(read_low, msr);
            bitmap_set_bit(write_low, msr);
        } else {
            bitmap_clear_bit(read_low, msr);
            bitmap_clear_bit(write_low, msr);
        }
    } else if ((msr >= HIGH_START) && (msr <= HIGH_END)) {
        size_t offset = msr - HIGH_START;
        if (trap) {
            bitmap_set_bit(read_high, offset);
            bitmap_set_bit(write_high, offset);
        } else {
            bitmap_clear_bit(read_high, offset);
            bitmap_clear_bit(write_high, offset);
        }
    } else {
        die_on(false, "MSR 0x%lX out of valid range", msr);
    }
}

static inline uint8_t vmm_virt_addr_bits()
{
	return __vmread(VMCS_HOST_CR4) & CR4_LA57_MASK ? 57 : 48;
}

static inline uint64_t get_canonical(uint64_t la, uint8_t vaddr_bits)
{
	return ((int64_t)la << (64 - vaddr_bits)) >> (64 - vaddr_bits);
}

static inline bool is_noncanonical_address(uint64_t la)
{
	return get_canonical(la, vmm_virt_addr_bits()) != la;
}

void vmm_inject_guest_event(exception_vector vector, exception_error_code code);

#endif /* VMM_COMMON_H */