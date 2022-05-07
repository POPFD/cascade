#include "platform/standard.h"
#include "platform/intrin.h"
#include "interrupt/idt.h"
#include "vmm_common.h"
#include "ia32_compact.h"

#define DEBUG_HANDLER
#ifdef DEBUG_HANDLER
    #define HANDLER_PRINT(...) debug_print(__VA_ARGS__)
#else
    #define HANDLER_PRINT(...)
#endif

static bool event_has_error_code(exception_vector vector)
{
    switch (vector) {
        case double_fault:
        case invalid_tss:
        case segment_not_present:
        case stack_segment_fault:
        case general_protection:
        case page_fault:
        case alignment_check:
            return true;
        default:
            return false;
    }
}

static void inject_guest_event(exception_vector vector, exception_error_code code)
{
    vmentry_interrupt_info info = { 0 };
    interruption_type type;

    /* Determine if the vector has an error code associated with it. */
    info.deliver_error_code = event_has_error_code(vector);

    /* Determine the interrupt type. */
    switch (vector) {
        case breakpoint:
        case overflow:
            type = software_exception;
            break;
        case debug:
            type = privileged_software_exception;
            break;
        default:
            type = hardware_exception;
            break;
    }

    /* Override if vector was greater than 0x20 */
    if (vector >= 0x20) {
        type = external_interrupt;
    }

    info.vector = vector;
    info.interruption_type = type;
    info.valid = true;
    __vmwrite(VMCS_CTRL_ENTRY_INTERRUPTION_INFO, info.flags);

    if (info.deliver_error_code)
        __vmwrite(VMCS_CTRL_ENTRY_EXCEPTION_ERRCODE, code.flags);

    HANDLER_PRINT("Injected guest event 0x%lX type 0x%lX code 0x%lX", vector, type, code.flags);
}

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
        HANDLER_PRINT("Forwarding vector 0x%lX error code 0x%lX",
                      vcpu->cached_int.vector, vcpu->cached_int.code);
        inject_guest_event(vcpu->cached_int.vector, vcpu->cached_int.code);
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

    HANDLER_PRINT("CPUID leaf 0x%lX sub_leaf 0x%lX - 0x%lX 0x%lX 0x%lX 0x%lX",
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
    /* TODO: XSETBV shall trigger a #GP if called with an unimplemented
     *       XCR, or wrong privilege level in guest we should actually handle
     *       this properly rather than trying to call it blindly. */

    /*
     * Running XSETBV requires os_xsave to be set in CR4
     * this is not the cast in an EFI booted environment
     * so we enable it before the call.
     */
    cr4 host_cr4;
    host_cr4.flags = __readcr4();
    host_cr4.os_xsave = true;
    __writecr4(host_cr4.flags);

    uint32_t field = (uint32_t)vcpu->guest_context.rcx;
    uint64_t value = (vcpu->guest_context.rdx << 32) | vcpu->guest_context.rax;
    
    HANDLER_PRINT("XSETBV field 0x%lX value 0x%lX", field, value);
    __xsetbv(field, value);
    
    *move_to_next = true;
    return true;
}

static bool handle_invd(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    (void)vcpu;
    
    HANDLER_PRINT("INVD");
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
        HANDLER_PRINT("RSMSR 0x%lX wrong RPL 0x%X", msr, cs.request_privilege_level);
        inject_guest_event(general_protection, DEFAULT_EC);
        *move_to_next = false;
        return true;
    }

    /* Check to see if within valid MSR range. */
    if ((msr && (msr <= 0x1FFF)) || ((msr >= 0xC0000000) && (msr <= 0xC0001FFF))) {
        size_t msr_val = rdmsr(msr);
        HANDLER_PRINT("RDMSR 0x%lX - 0x%lX", msr, msr_val);
        vcpu->guest_context.rdx = msr_val >> 32;
        vcpu->guest_context.rax = (uint32_t)msr_val;
        *move_to_next = true;
        return true;
    }

    /* Invalid MSR which is out of range. */
    HANDLER_PRINT("RDMSR 0x%lX out of range", msr);
    inject_guest_event(general_protection, DEFAULT_EC);
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
        HANDLER_PRINT("WRMSR 0x%lX 0x%lX wrong RPL 0x%X", msr_id, msr_val, cs.request_privilege_level);
        inject_guest_event(general_protection, DEFAULT_EC);
        *move_to_next = false;
        return true;
    }

    /* Check to see if within valid MSR range. */
    if ((msr_id && (msr_id <= 0x1FFF)) || ((msr_id >= 0xC0000000) && (msr_id <= 0xC0001FFF))) {
        HANDLER_PRINT("WRMSR 0x%lX 0x%lX", msr_id, msr_val);
        wrmsr(msr_id, msr_val);
        *move_to_next = true;
        return true;
    }

    /* Invalid MSR which is out of range. */
    HANDLER_PRINT("WRMSR 0x%lX 0x%lX out of range", msr_id, msr_val);
    inject_guest_event(general_protection, DEFAULT_EC);
    *move_to_next = false;
    return true;
}

static void handle_exit_reason(struct vcpu_ctx *vcpu)
{
    typedef bool (*fn_exit_handler)(struct vcpu_ctx *vcpu, bool *move_next_instr);

    static const fn_exit_handler EXIT_HANDLERS[] = {
        [VMX_EXIT_REASON_CPUID] = handle_cpuid,
        [VMX_EXIT_REASON_XSETBV] = handle_xsetbv,
        [VMX_EXIT_REASON_INVD] = handle_invd,
        [VMX_EXIT_REASON_RDMSR] = handle_rdmsr,
        [VMX_EXIT_REASON_WRMSR] = handle_wrmsr
    };

    /* Determine the exit reason and then call the appropriate exit handler. */
    size_t reason = __vmread(VMCS_EXIT_REASON) & 0xFFFF;

    die_on(reason >= ARRAY_SIZE(EXIT_HANDLERS),
           "Exit reason 0x%lX rip 0x%lX not within range of handler table",
           reason, vcpu->guest_context.rip);

    die_on(!EXIT_HANDLERS[reason],
           "Exit reason 0x%lX rip 0x%lX not declared in handler table",
           reason, vcpu->guest_context.rip);

    bool move_to_next_instr = false;
    bool success = EXIT_HANDLERS[reason](vcpu, &move_to_next_instr);

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