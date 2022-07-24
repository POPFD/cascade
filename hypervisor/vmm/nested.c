#define DEBUG_MODULE
#include "platform/standard.h"
#include "memory/vmem.h"
#include "vmm_common.h"
#include "nested.h"

struct nested_ctx {
    uint64_t dummy;
};

static bool is_nested_enabled(struct vcpu_ctx *vcpu)
{
    return (vcpu->nested != NULL);
}

static void enable_nested_vmx(struct vcpu_ctx *vcpu)
{
    assert(!is_nested_enabled(vcpu));

    vcpu->nested = vmem_alloc(sizeof(struct nested_ctx), MEM_WRITE);
    die_on(!vcpu->nested, "Unable to allocate memory for vCPU %d nested virt.", vcpu->idx);

    DEBUG_PRINT("Nested virtualization enabled.");
}

static bool is_attempt_enable_vmx(struct vcpu_ctx *vcpu,
                                  vmx_exit_qualification_cr_access qual)
{
    if (qual.cr_number != VMX_EXIT_QUALIFICATION_REGISTER_CR4)
        return false;

    if (qual.access_type != VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR)
        return false;

    /* For RSP register access we have to directly read guest RSP. */
    uint64_t reg_val;
    if (qual.gp_register == VMX_EXIT_QUALIFICATION_GENREG_RSP)
        reg_val = __vmread(VMCS_GUEST_RSP);
    else {
        uint64_t *gp_arr = &vcpu->guest_context.rax;
        reg_val = gp_arr[qual.gp_register];
    }

    DEBUG_PRINT("Attempt to set CR4 to val 0x%lX", reg_val);

    /* Check to see if guest is trying to set VMXE. */
    if (!(reg_val & CR4_VMXE_MASK))
        return false;

    /* If nested is already enabled do nothing. */
    if (is_nested_enabled(vcpu))
        return false;

    enable_nested_vmx(vcpu);
    return true;
}

bool nested_mov_crx(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    (void)vcpu;

    /* Verify to see whether the MOV CRX is relevant to nested. */
    vmx_exit_qualification_cr_access qual;
    qual.flags = __vmread(VMCS_EXIT_QUALIFICATION);
    DEBUG_PRINT("Exit qualification 0x%lX", qual.flags);

    if (is_attempt_enable_vmx(vcpu, qual)) {
        *move_to_next = true;
        return true;
    }

    *move_to_next = false;
    return false;
}