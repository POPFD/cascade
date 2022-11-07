#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/intrin.h"
#include "memory/mem.h"
#include "interrupt/idt.h"
#include "plugin/event.h"
#include "vmm_common.h"
#include "vmcall.h"
#include "nested.h"
#include "ia32_compact.h"

static void handle_cached_interrupts(struct vcpu_ctx *vcpu)
{
    /*
     * Check to see if there are any pending interrupts
     * to be delivered that were caught from the host IDT
     * that need to be redirected to the guest.
     * 
     * We only do this if there is NOT already a pending
     * interrupt.
     */
    if (vcpu->cached_int.pending) {
        DEBUG_PRINT("Forwarding vector 0x%lX error code 0x%lX",
                      vcpu->cached_int.vector, vcpu->cached_int.code);
        vmm_inject_guest_event(vcpu->cached_int.vector, vcpu->cached_int.code);
        vcpu->cached_int.pending = false;
    }
}

static bool handle_cpuid(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    /* Override leafs. */
    #define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS 0x40000000
    #define HYPERV_CPUID_INTERFACE 0x40000001

    /* Bitmasks in certain leafs. */
    static const size_t CPUID_VI_BIT_HYPERVISOR_PRESENT = 0x80000000;

    /* Read the CPUID into the leafs array. */
    uint64_t leaf = vcpu->guest_context.rax;
    uint64_t sub_leaf = vcpu->guest_context.rcx;
    int out_regs[4] = { 0 };
    __cpuidex(out_regs, leaf, sub_leaf);

    /* Override certain target leafs. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
    switch (leaf) {
    case CPUID_VERSION_INFO:
        out_regs[2] &= ~(uint64_t)CPUID_VI_BIT_HYPERVISOR_PRESENT;
        break;
    case HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS:
        out_regs[0] = HYPERV_CPUID_INTERFACE;
        out_regs[1] = 'csac';
        out_regs[2] = '\0eda';
        out_regs[3] = '\0\0\0\0';
        break;
    case HYPERV_CPUID_INTERFACE:
        out_regs[0] = 'csac';
        out_regs[1] = 0;
        out_regs[2] = 0;
        out_regs[3] = 0;
        break;
    }
#pragma GCC diagnostic pop

    DEBUG_PRINT("CPUID leaf 0x%lX sub_leaf 0x%lX - 0x%lX 0x%lX 0x%lX 0x%lX",
                  leaf, sub_leaf, out_regs[0], out_regs[1], out_regs[2], out_regs[3]);

    /* Store these leafs back into the guest context and move to next. */
    vcpu->guest_context.rax = out_regs[0];
    vcpu->guest_context.rbx = out_regs[1];
    vcpu->guest_context.rcx = out_regs[2];
    vcpu->guest_context.rdx = out_regs[3];
    *move_to_next = true;
    return true;
}

static bool handle_xsetbv(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    static const exception_error_code DEFAULT_EC = { 0 };

    /* Check to ensure that os_xsave is enabled. */
    cr4 guest_cr4;
    guest_cr4.flags = __vmread(VMCS_GUEST_CR4);
    if (!guest_cr4.os_xsave) {
        DEBUG_PRINT("XSETBV when CR4.os_xsave not set");
        vmm_inject_guest_event(invalid_opcode, DEFAULT_EC);
        *move_to_next = false;
        return true;
    }

    /* Check that a valid XCR index is set (only 0 supported). */
    uint32_t field = (uint32_t)vcpu->guest_context.rcx;
    if (field) {
        DEBUG_PRINT("XSETBV invalid XCR field 0x%X", field);
        vmm_inject_guest_event(general_protection, DEFAULT_EC);
        *move_to_next = false;
        return true;
    }

    /*
     * Running XSETBV requires os_xsave to be set in CR4
     * this is not the cast in an EFI booted environment
     * so we enable it before the call.
     */
    cr4 host_cr4;
    host_cr4.flags = __readcr4();
    host_cr4.os_xsave = true;
    __writecr4(host_cr4.flags);

    uint64_t value = (vcpu->guest_context.rdx << 32) | (uint32_t)vcpu->guest_context.rax;

    DEBUG_PRINT("XSETBV field 0x%lX value 0x%lX", field, value);
    __xsetbv(field, value);
    
    *move_to_next = true;
    return true;
}

static bool handle_invd(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    (void)vcpu;
    
    DEBUG_PRINT("INVD");
    __invd();
    *move_to_next = true;
    return true;
}

static bool handle_rdmsr(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    static const exception_error_code DEFAULT_EC = { 0 };
    size_t msr = (uint32_t)vcpu->guest_context.rcx;

    /* Check to see if valid RPL to perform the read. */
    segment_selector cs;
    cs.flags = __vmread(VMCS_GUEST_CS_SEL);
    if (cs.request_privilege_level != 0) {
        DEBUG_PRINT("RDMSR 0x%lX wrong RPL 0x%X", msr, cs.request_privilege_level);
        vmm_inject_guest_event(general_protection, DEFAULT_EC);
        *move_to_next = false;
        return true;
    }

    /* Check to see if within valid MSR range. */
    if ((msr && (msr <= 0x1FFF)) || ((msr >= 0xC0000000) && (msr <= 0xC0001FFF))) {
        DEBUG_PRINT("Guest attempted to read MSR 0x%lX at rip 0x%lX", msr, vcpu->guest_context.rip);
        die_on(true, "Dead");

        *move_to_next = true;
        return true;
    }

    /* Invalid MSR which is out of range. */
    DEBUG_PRINT("RDMSR 0x%lX out of range", msr);
    vmm_inject_guest_event(general_protection, DEFAULT_EC);
    *move_to_next = false;
    return true;
}

static bool handle_wrmsr(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    static const exception_error_code DEFAULT_EC = { 0 };
    size_t msr_id = (uint32_t)vcpu->guest_context.rcx;
    size_t msr_val = (vcpu->guest_context.rdx << 32) | (uint32_t)vcpu->guest_context.rax;

    /* Check to see if valid RPL to perform the read. */
    segment_selector cs;
    cs.flags = __vmread(VMCS_GUEST_CS_SEL);
    if (cs.request_privilege_level != 0) {
        DEBUG_PRINT("WRMSR 0x%lX 0x%lX wrong RPL 0x%X", msr_id, msr_val, cs.request_privilege_level);
        vmm_inject_guest_event(general_protection, DEFAULT_EC);
        *move_to_next = false;
        return true;
    }

    /* Check to see if within valid MSR range. */
    if ((msr_id && (msr_id <= 0x1FFF)) || ((msr_id >= 0xC0000000) && (msr_id <= 0xC0001FFF))) {
        DEBUG_PRINT("Guest attempted to write MSR 0x%lX val 0x%lX at rip 0x%lX",
                      msr_id, msr_val, vcpu->guest_context.rip);
        die_on(true, "Dead");

        *move_to_next = true;
        return true;
    }

    /* Invalid MSR which is out of range. */
    DEBUG_PRINT("WRMSR 0x%lX 0x%lX out of range", msr_id, msr_val);
    vmm_inject_guest_event(general_protection, DEFAULT_EC);
    *move_to_next = false;
    return true;
}

static bool handle_init_signal(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    (void)vcpu;
    __vmwrite(VMCS_GUEST_ACTIVITY_STATE, vmx_wait_for_sipi);
    *move_to_next = false;
    return true;
}

static bool handle_sipi(struct vcpu_ctx *vcpu, bool *move_to_next)
{
#define SEGMENT_LIMIT_DEFAULT 0xFFFF

	/* Use the exit qualification to gather the SIPI vector.
	 * Only bits 7:0 contain the vector, the rest are zero'd. */
	UINT64 sipi_vector = __vmread(VMCS_EXIT_QUALIFICATION);

    /* Initialise all the VMCS fields to initial values. */

    /* Set up the guest control registers. */
    cr0 guest_cr0;
    guest_cr0.flags = 0;
    guest_cr0.extension_type = TRUE;
    guest_cr0.numeric_error = TRUE;
    guest_cr0.not_write_through = TRUE;
    guest_cr0.cache_disable = TRUE;
    __vmwrite(VMCS_GUEST_CR0, guest_cr0.flags);

    cr4 guest_cr4;
    guest_cr4.flags = 0;
    guest_cr4.vmx_enable = TRUE;
    __vmwrite(VMCS_GUEST_CR4, guest_cr4.flags);

    cr3 guest_cr3;
    guest_cr3.flags = 0;
    __vmwrite(VMCS_GUEST_CR3, guest_cr3.flags);

    dr7 guest_dr7;
    guest_dr7.flags = 0;
    __vmwrite(VMCS_GUEST_DR7, guest_dr7.flags);

    /* Set up VMCS guest registers. */
    rfl guest_rfl;
    guest_rfl.flags = 0;
    guest_rfl.read_as_1 = TRUE;
    __vmwrite(VMCS_GUEST_RFLAGS, guest_rfl.flags);

    __vmwrite(VMCS_GUEST_RSP, 0);
    __vmwrite(VMCS_GUEST_RIP, 0);

    /*
     * Set up the guest segmentation registers.
     * CS has to be set up using the SIPI vector.
     * TODO: Actually check if this is true, as per 27.2.1 it states:
     *  - For a start-up IPI (SIPI), the exit qualification contains the SIPI vector
     *    informationin bits 7:0. Bits 63:8 of the exit qualification are cleared to 0.
     */
    __vmwrite(VMCS_GUEST_CS_SEL, sipi_vector << 8);
    __vmwrite(VMCS_GUEST_CS_BASE, sipi_vector << 12);
    __vmwrite(VMCS_GUEST_CS_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, 0x0009B);

    __vmwrite(VMCS_GUEST_DS_SEL, 0);
    __vmwrite(VMCS_GUEST_DS_BASE, 0);
    __vmwrite(VMCS_GUEST_DS_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, 0x00093);

    __vmwrite(VMCS_GUEST_ES_SEL, 0);
    __vmwrite(VMCS_GUEST_ES_BASE, 0);
    __vmwrite(VMCS_GUEST_ES_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, 0x00093);

    __vmwrite(VMCS_GUEST_FS_SEL, 0);
    __vmwrite(VMCS_GUEST_FS_BASE, 0);
    __vmwrite(VMCS_GUEST_FS_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, 0x00093);

    __vmwrite(VMCS_GUEST_GS_SEL, 0);
    __vmwrite(VMCS_GUEST_GS_BASE, 0);
    __vmwrite(VMCS_GUEST_GS_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, 0x00093);

    __vmwrite(VMCS_GUEST_SS_SEL, 0);
    __vmwrite(VMCS_GUEST_SS_BASE, 0);
    __vmwrite(VMCS_GUEST_SS_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, 0x00093);

    __vmwrite(VMCS_GUEST_TR_SEL, 0);
    __vmwrite(VMCS_GUEST_TR_BASE, 0);
    __vmwrite(VMCS_GUEST_TR_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, 0x0008b);

    __vmwrite(VMCS_GUEST_LDTR_SEL, 0);
    __vmwrite(VMCS_GUEST_LDTR_BASE, 0);
    __vmwrite(VMCS_GUEST_LDTR_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0x00082);

    __vmwrite(VMCS_GUEST_GDTR_BASE, 0);
    __vmwrite(VMCS_GUEST_GDTR_LIMIT, SEGMENT_LIMIT_DEFAULT);
    __vmwrite(VMCS_GUEST_IDTR_BASE, 0);
    __vmwrite(VMCS_GUEST_IDTR_LIMIT, SEGMENT_LIMIT_DEFAULT);

    /* Set up other VMCS guest information. */
    __vmwrite(VMCS_GUEST_EFER, 0);

    __vmwrite(VMCS_GUEST_SYSENTER_CS, 0);
    __vmwrite(VMCS_GUEST_SYSENTER_EIP, 0);
    __vmwrite(VMCS_GUEST_SYSENTER_ESP, 0);

    /*
     * Indicate guest activity is back in active state.
     * and indicate no pending interrupts etc.
     */
    __vmwrite(VMCS_GUEST_ACTIVITY_STATE, vmx_active);
    __vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
    __vmwrite(VMCS_CTRL_ENTRY_INTERRUPTION_INFO, 0);

    /* Read the previous VM entry controls, but disable IA32E guest mode. */
    ia32_vmx_entry_ctls_register entryControls;
    entryControls.flags = __vmread(VMCS_CTRL_ENTRY);
    entryControls.ia32e_mode_guest = false;

    __vmwrite(VMCS_CTRL_ENTRY, entryControls.flags);

    /* Set the guest registers. */
    vcpu->guest_context.rdx = 0x600;
    vcpu->guest_context.rax = 0;
    vcpu->guest_context.rbx = 0;
    vcpu->guest_context.rcx = 0;
    vcpu->guest_context.rsi = 0;
    vcpu->guest_context.rdi = 0;
    vcpu->guest_context.rbp = 0;
    vcpu->guest_context.r8 = 0;
    vcpu->guest_context.r9 = 0;
    vcpu->guest_context.r10 = 0;
    vcpu->guest_context.r11 = 0;
    vcpu->guest_context.r12 = 0;
    vcpu->guest_context.r13 = 0;
    vcpu->guest_context.r14 = 0;
    vcpu->guest_context.r15 = 0;

    *move_to_next = false;
    return true;
}

static bool handle_mov_crx(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    /* Check to see if the MOV CRX is relevant to nested. */
    bool result = nested_mov_crx(vcpu, move_to_next);
    if (result)
        return true;

    /* If not do something else (currently nothing as nothing else should trigger). */
    *move_to_next = false;
    return false;
}

static bool handle_vmxon(struct vcpu_ctx *vcpu, bool *move_to_next)
{
#ifdef CONFIG_NESTED
    return nested_vmxon(vcpu, move_to_next);
#else
    static const exception_error_code DEFAULT_EC = { 0 };

    vmm_inject_guest_event(invalid_opcode, DEFAULT_EC);
    *move_to_next = false;
    return true;
#endif
}

static void handle_exit_reason(struct vcpu_ctx *vcpu)
{
    typedef bool (*fn_exit_handler)(struct vcpu_ctx *vcpu, bool *move_next_instr);

    static const fn_exit_handler EXIT_HANDLERS[] = {
        [VMX_EXIT_REASON_CPUID] = handle_cpuid,
        [VMX_EXIT_REASON_XSETBV] = handle_xsetbv,
        [VMX_EXIT_REASON_INVD] = handle_invd,
        [VMX_EXIT_REASON_RDMSR] = handle_rdmsr,
        [VMX_EXIT_REASON_WRMSR] = handle_wrmsr,
        [VMX_EXIT_REASON_VMCALL] = vmcall_handle,
        [VMX_EXIT_REASON_INIT_SIGNAL] = handle_init_signal,
        [VMX_EXIT_REASON_SIPI] = handle_sipi,
        [VMX_EXIT_REASON_MOV_CRX] = handle_mov_crx,
        [VMX_EXIT_REASON_VMXON] = handle_vmxon,
    };

    /* Determine the exit reason and then call the appropriate exit handler. */
    size_t reason = __vmread(VMCS_EXIT_REASON) & 0xFFFF;
    bool success;
    bool move_to_next_instr = false;

    /* Check to see if the exit is to be handled by a plugin, if so
     * we can do nothing. */
    success = plugin_handle_event(vcpu, reason, &move_to_next_instr);
    if (!success) {
        /* If not handled by plugin we should do it here. */
        die_on(reason >= ARRAY_SIZE(EXIT_HANDLERS),
            "Exit reason 0x%lX rip 0x%lX not within range of handler table",
            reason, vcpu->guest_context.rip);

        die_on(!EXIT_HANDLERS[reason],
            "Exit reason 0x%lX rip 0x%lX not declared in handler table",
            reason, vcpu->guest_context.rip);

        success = EXIT_HANDLERS[reason](vcpu, &move_to_next_instr);
    }

    size_t qual = __vmread(VMCS_EXIT_QUALIFICATION);
    die_on(!success,
           "Exit handler for 0x%lX rip 0x%lX failed with exit qualification 0x%lX",
           reason, vcpu->guest_context.rip, qual);

    /*
     * If the exit handler indicated to increment RIP, do so.
     * We cannot use the guest_context.rip field to increment as
     * this will not be restored on re-enter to the guest, we need to
     * directly write to the VMCS field instead.
     */
    if (move_to_next_instr) {
        size_t guest_rip = __vmread(VMCS_GUEST_RIP);
        guest_rip += __vmread(VMCS_EXIT_INSTR_LENGTH);
        __vmwrite(VMCS_GUEST_RIP, guest_rip);
    }

    handle_cached_interrupts(vcpu);
}

__attribute__((ms_abi)) void handler_guest_to_host(struct vcpu_context *guest_ctx)
{
    /*
     * Because we had to use RCX in shim_guest_to_host as a parameter
     * for the __capture_context which gets passed to this handler
     * we have to retrieve this value and store it back in the guest_context. */
    uint64_t restore_rsp = guest_ctx->rsp + sizeof(uint64_t);
    guest_ctx->rcx = *(uint64_t *)((uintptr_t)guest_ctx - sizeof(guest_ctx->rcx));

    /* Set what the guest RIP and RSP were. */
    guest_ctx->rsp = __vmread(VMCS_GUEST_RSP);
    guest_ctx->rip = __vmread(VMCS_GUEST_RIP);

    /*
     * Find the vcpu_ctx structure by backtracing from the guest_ctx which we can
     * assume was stored on the host_stack.
     */
    struct vcpu_ctx *vcpu = vmm_get_vcpu_ctx();

    /* Indicate running as host and then copy the guest context from stack to vcpu struct. */
    vcpu->running_as_guest = false;
    vcpu->guest_context = *guest_ctx;

    /* Handle the VMEXIT reason. */
    handle_exit_reason(vcpu);

    /* 
     * Trigger the return back into guest mode, by adjusting RIP in our stored
     * guest context and then adjust the context RIP to our VMRESUME handler.
     */
    vcpu->guest_context.rsp = restore_rsp;
    vcpu->guest_context.rip = (uint64_t)__vmresume;
    __restore_context(&vcpu->guest_context);
}