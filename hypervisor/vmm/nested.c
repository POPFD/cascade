#define DEBUG_MODULE
#include "platform/standard.h"
#include "memory/mem.h"
#include "memory/vmem.h"
#include "vmm.h"
#include "vmm_common.h"
#include "nested.h"

#define NESTED_REVISION_ID 0x0000BEEF

struct nested_ctx {
    uint32_t vm_instruction_error;
    gpa_t vmxon_ptr;
};

static void set_vmx_success_flags()
{
    rfl rflags;
    rflags.flags = __vmread(VMCS_GUEST_RFLAGS);

    rflags.carry_flag = 0;
    rflags.parity_flag = 0;
    rflags.auxiliary_carry_flag = 0;
    rflags.zero_flag = 0;
    rflags.sign_flag = 0;
    rflags.overflow_flag = 0;
    __vmwrite(VMCS_GUEST_RFLAGS, rflags.flags);
}

static void set_vmx_fail_invalid_flags()
{
    rfl rflags;
    rflags.flags = __vmread(VMCS_GUEST_RFLAGS);

    rflags.carry_flag = 1;
    rflags.parity_flag = 0;
    rflags.auxiliary_carry_flag = 0;
    rflags.zero_flag = 0;
    rflags.sign_flag = 0;
    rflags.overflow_flag = 0;
    __vmwrite(VMCS_GUEST_RFLAGS, rflags.flags);
}

// static void set_vmx_fail_valid_flags(struct nested_ctx *nested, uint32_t err_no)
// {
//     rfl rflags;
//     rflags.flags = __vmread(VMCS_GUEST_RFLAGS);

//     rflags.carry_flag = 0;
//     rflags.parity_flag = 0;
//     rflags.auxiliary_carry_flag = 0;
//     rflags.zero_flag = 1;
//     rflags.sign_flag = 0;
//     rflags.overflow_flag = 0;
//     __vmwrite(VMCS_GUEST_RFLAGS, rflags.flags);
//     nested->vm_instruction_error = err_no;
// }

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
    uint64_t reg_val = vmm_read_gp_register(vcpu, qual.gp_register);
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

static bool get_vmx_mem_address(struct vcpu_ctx *vcpu,
                                uintptr_t qual,
                                vmx_vmexit_instruction_info_vmx_and_xsaves info,
                                gpa_t *mem_address)
{
    gpa_t offset = qual;
    DEBUG_PRINT("Qual set to offset value 0x%lX", offset);

    if (info.base_register_invalid == false) {
        /* Read the base register and add to offset. */
        uint64_t base_reg = vmm_read_gp_register(vcpu, info.base_register);
        offset += base_reg;
        DEBUG_PRINT("Adding base register %d value 0x%lX new offset 0x%lX",
                    info.base_register, base_reg, offset);
    }

    if (info.gp_register_invalid == false) {
        /* Read the index register, and add to offset with scale. */
        uint64_t index_reg = vmm_read_gp_register(vcpu, info.gp_register);
        offset += (index_reg << info.scaling);
        DEBUG_PRINT("Adding index register 0x%lX with scaling 0x%X new offset 0x%lX",
                    index_reg, info.scaling, offset);
    }

    /* Deal with the address sizing. */
    if (info.address_size == 1 /* 32 bit */)
        offset &= 0xFFFFFFFF;
    else if (info.address_size == 0 /* 16 bit */)
        offset &= 0xFFFF;

    /*
     * Check to see if guest in long mode,
     * if not we throw a fault as we do not support anything else.
     */
    ia32_efer_register efer;
    efer.flags = __vmread(VMCS_GUEST_EFER);
    die_on(!efer.ia32e_mode_enable, "Nested virt not supported when not in long mode");

    /* If GS or FS set, add these to the offset. */
    if (info.segment_register == SEG_FS)
        offset += __vmread(VMCS_GUEST_FS_BASE);
    else if (info.segment_register == SEG_GS)
        offset += __vmread(VMCS_GUEST_GS_BASE);

    /* Ensure address falls in range of canonical addresses. */
    if (is_noncanonical_address(offset)) {
        DEBUG_PRINT("Non canonical address specified 0x%lX", offset);
        static const exception_error_code DEFAULT_EC = { 0 };
        vmm_inject_guest_event(info.segment_register == SEG_SS ?
                               stack_segment_fault : general_protection,
                               DEFAULT_EC);
        return false;
    } else {
        *mem_address = offset;
        return true;
    }
}

static bool get_vmptr(struct vcpu_ctx *vcpu, gpa_t *vmptr)
{
    /* Attempt to read the VMXON/VMCS region for the host. */
    vmx_vmexit_instruction_info_vmx_and_xsaves info;
    info.flags = __vmread(VMCS_EXIT_INSTR_INFO);

    uintptr_t qual = __vmread(VMCS_EXIT_QUALIFICATION);
    DEBUG_PRINT("VMXON instruction info 0x%lX qual 0x%lX", info.flags, qual);

    /* Get the address of the VMXON pointer in guest virtual memory. */
    uintptr_t guest_addr;
    if (!get_vmx_mem_address(vcpu, qual, info, &guest_addr))
        return false;

    cr3 guest_cr3;
    guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
    if (!mem_copy_virtual_memory(COPY_READ, guest_cr3, guest_addr, vmptr, sizeof(*vmptr))) {
        DEBUG_PRINT("Unable to read guest memory for VMXON pointer");
        return false;
    }

    DEBUG_PRINT("VMX guest mem address 0x%lX vmptr 0x%lX", guest_addr, *vmptr);
    return true;
}

void nested_init(struct vcpu_ctx *vcpu)
{
    /*
     * Adjust the MSR bitmap to indicate which nested VMX related
     * MSRs we need to trap on.
     */
    vmm_msr_trap_enable(vcpu->msr_trap_bitmap, IA32_VMX_BASIC, true);
}

bool nested_rdmsr(struct vcpu_ctx *vcpu, size_t msr, size_t *value)
{
    (void)vcpu;

    switch (msr) {
    case IA32_VMX_BASIC:
        ia32_vmx_basic_register basic = { 0 };
        basic.vmcs_revision_id = NESTED_REVISION_ID;
        basic.vmcs_size_in_bytes = PAGE_SIZE;
        basic.memory_type = MEMORY_TYPE_WB;
        basic.ins_outs_vmexit_information = true;
        basic.true_controls = true;
        *value = basic.flags;
        break;
    default:
        return false;
    }

    return true;
}

bool nested_wrmsr(struct vcpu_ctx *vcpu, size_t msr, size_t value)
{
    (void)vcpu;
    (void)msr;
    (void)value;
    return false;
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

bool nested_vmxon(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    static const exception_error_code DEFAULT_EC = { 0 };

    /* Verify that VMXE is enabled for the guest. */
    if (!(__vmread(VMCS_GUEST_CR4) & CR4_VMXE_MASK)) {
        vmm_inject_guest_event(invalid_opcode, DEFAULT_EC);
        *move_to_next = false;
        return true;
    }

    /* Verify that we are CPL 0. */
    segment_selector cs;
    cs.flags = __vmread(VMCS_GUEST_CS_SEL);
    if (cs.request_privilege_level != 0) {
        vmm_inject_guest_event(general_protection, DEFAULT_EC);
        *move_to_next = false;
        return true;
    }

    /* Attempt to get the VMXON pointer. */
    gpa_t vmptr;
    if (!get_vmptr(vcpu, &vmptr)) {
        *move_to_next = false;
        return true;
    }

    if (!vmptr) {
        DEBUG_PRINT("Unlikely null vmptr region, indicating failure.");
        set_vmx_fail_invalid_flags();
        *move_to_next = true;
        return true;
    }

    /* Ensure that the guest VMXON pointer is page aligned. */
    if (vmptr & PAGE_MASK) {
        DEBUG_PRINT("Non page aligned vmxon region defined 0x%lX", vmptr);
        set_vmx_fail_invalid_flags();
        *move_to_next = true;
        return true;
    }

    /* Verify VMXON VMCS revision ID matches. */
    uint32_t revision = *(uint32_t *)vmptr;

    /*
     * vmptr is a physical address of the guest, as we're identity mapped this is
     * mapped 1:1 into our virtual address space. No need to do conversion from
     * virtual guest to physical host.
     */
    if (revision != NESTED_REVISION_ID) {
        DEBUG_PRINT("Guest specified revision 0x%X does not match host supported 0x%X",
                    revision, NESTED_REVISION_ID);
        set_vmx_fail_invalid_flags();
        *move_to_next = true;
        return true;
    } else {
        DEBUG_PRINT("Guest vmcs revision 0x%X", revision);
    }

    /* TODO: Allocate the vmxon fields for nested support. */
    vcpu->nested->vmxon_ptr = vmptr;
    set_vmx_success_flags();

    *move_to_next = true;
    return true;
}