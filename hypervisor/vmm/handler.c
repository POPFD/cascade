#define DEBUG_MODULE
#include "platform/intrin.h"
#include "memory/mem.h"
#include "memory/vmem.h"
#include "interrupt/idt.h"
#include "vmm_common.h"
#include "handler.h"
#include "ia32_compact.h"

struct vmexit_handler {
    /* Doubly linked list so multiple exit handlers can be daisy chained. */
    struct vmexit_handler *next, *prev;
    /* The callback for the exit to be called. */
    vmexit_cbk_t callback;
    /* Callback specific data. */
    void *opaque;
    /* If called, prevent other daisy chained callbacks from being called. */
    bool override;
};

struct handler_ctx {
    /* An array of exit handler structures.
     * Each VMEXIT can have multiple handlers daisy chained.
     * therefore we have to keep track of pointers.
     *
     * We can store up to the maximum exit reason which is XRSTORS
     * (well at least currently). */
    #define MAX_EXIT_HANDLERS VMX_EXIT_REASON_XRSTORS
    struct vmexit_handler *handlers[MAX_EXIT_HANDLERS];
    /* Back reference to the VMM context */
    struct vmm_ctx *vmm;
};

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

static void handle_cpuid(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next)
{
    /* Override leafs. */
    #define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS 0x40000000
    #define HYPERV_CPUID_INTERFACE 0x40000001

    /* Bitmasks in certain leafs. */
    static const size_t CPUID_VI_BIT_HYPERVISOR_PRESENT = 0x80000000;

    (void)opaque;

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
}

static void handle_xsetbv(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next)
{
    static const exception_error_code DEFAULT_EC = { 0 };

    (void)opaque;

    /* Check to ensure that os_xsave is enabled. */
    cr4 guest_cr4;
    guest_cr4.flags = __vmread(VMCS_GUEST_CR4);
    if (!guest_cr4.os_xsave) {
        DEBUG_PRINT("XSETBV when CR4.os_xsave not set");
        vmm_inject_guest_event(invalid_opcode, DEFAULT_EC);
        *move_to_next = false;
        return;
    }

    /* Check that a valid XCR index is set (only 0 supported). */
    uint32_t field = (uint32_t)vcpu->guest_context.rcx;
    if (field) {
        DEBUG_PRINT("XSETBV invalid XCR field 0x%X", field);
        vmm_inject_guest_event(general_protection, DEFAULT_EC);
        *move_to_next = false;
        return;
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
}

static void handle_invd(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next)
{
    (void)vcpu;
    (void)opaque;

    DEBUG_PRINT("INVD");
    __invd();
    *move_to_next = true;
}

static void handle_init_signal(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next)
{
    (void)vcpu;
    (void)opaque;

    __vmwrite(VMCS_GUEST_ACTIVITY_STATE, vmx_wait_for_sipi);
    *move_to_next = false;
}

static void handle_sipi(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next)
{
#define SEGMENT_LIMIT_DEFAULT 0xFFFF

    (void)opaque;

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
}

static void handle_exit_reason(struct vcpu_ctx *vcpu)
{
    /* Retrieve the handler context from the vCPU. */
    struct handler_ctx *ctx = vcpu->vmm->handler;

    /* Determine the exit reason and then call the appropriate exit handler. */
    size_t reason = __vmread(VMCS_EXIT_REASON) & 0xFFFF;
    bool move_to_next_instr = false;

    /* Check to see if the exit reason is out of range. */
    die_on(reason >= MAX_EXIT_HANDLERS,
        "Exit reason 0x%lX rip 0x%lX not within range of handler table",
        reason, vcpu->guest_context.rip);

    struct vmexit_handler *exit_head = ctx->handlers[reason];

    /* Check to see if we actually have a handler for it. */
    die_on(!exit_head, "No exit reason handlers for 0x%lX at rip 0x%lX present",
           reason, vcpu->guest_context.rip);

    /* Iterate from tail to head calling each, stop at override. */
    struct vmexit_handler *curr_handler = exit_head->prev;
    while (true) {
        /* Call the callback for the VMEXIT. If this handler has the override
         * set, this means we SHOULDN'T call any others, so break. */
        curr_handler->callback(vcpu, curr_handler->opaque, &move_to_next_instr);
    
        if (curr_handler->override)
            break;

        if (curr_handler == exit_head)
            break;
        
        curr_handler = curr_handler->prev;
    };

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

static void register_generic_handlers(struct handler_ctx *ctx)
{
    static const vmexit_cbk_t GENERIC_HANDLERS[] = {
        [VMX_EXIT_REASON_CPUID] = handle_cpuid,
        [VMX_EXIT_REASON_XSETBV] = handle_xsetbv,
        [VMX_EXIT_REASON_INVD] = handle_invd,
        [VMX_EXIT_REASON_INIT_SIGNAL] = handle_init_signal,
        [VMX_EXIT_REASON_SIPI] = handle_sipi,
    };

    /* Register all of our generic handlers
     * This is done by iterating a key/value array of exit to internal handlers. */
    for (int exit_reason = 0; exit_reason < MAX_EXIT_HANDLERS; exit_reason++) {
        vmexit_cbk_t cbk = GENERIC_HANDLERS[exit_reason];

        if (cbk) {
            DEBUG_PRINT("Registering generic exit 0x%lX callback 0x%lX", exit_reason, cbk);
            handler_register_exit(ctx, exit_reason, cbk, NULL, false);
        }
    }
}

struct handler_ctx *handler_init(struct vmm_ctx *vmm)
{
    struct handler_ctx *ctx = vmem_alloc(sizeof(struct handler_ctx), MEM_WRITE);
    die_on(!ctx, "Unable to allocate context for VMEXIT handlers.");
    vmm->handler = ctx;
    ctx->vmm = vmm;

    register_generic_handlers(ctx);
    return ctx;
}

void handler_register_exit(struct handler_ctx *ctx,
                           size_t exit_reason,
                           vmexit_cbk_t callback,
                           void *opaque,
                           bool override)
{
    /* Ensure synchronization. */
    spin_lock(&ctx->vmm->lock);

    die_on(exit_reason >= MAX_EXIT_HANDLERS, "Invalid exit handler index 0x%lX", exit_reason);

    /* Allocate a new vmexit handler. */
    struct vmexit_handler *new_handler = vmem_alloc(sizeof(struct vmexit_handler), MEM_WRITE);
    die_on(!new_handler, "Unable to allocate memory for VMEXIT handler.");

    /* Fill out the information for the handler. */
    new_handler->callback = callback;
    new_handler->opaque = opaque;
    new_handler->override = override;

    /* Now manipulate the linked list for vmexit entry. */
    struct vmexit_handler **exit_base = &ctx->handlers[exit_reason];
    struct vmexit_handler *exit_head = *exit_base;
    new_handler->next = NULL;
    if (exit_head == NULL) {
        /* No current exit handlers. */
        new_handler->prev = new_handler;
        *exit_base = new_handler;
    } else {
        /* An event already exists.
         * Add our new handler to the tail of the list. */
        struct vmexit_handler *exit_tail = exit_head->prev;
        die_on(override && exit_tail->override,
               "Cannot override if an override for exit 0x%X already set",
               exit_reason);

        new_handler->prev = exit_tail;
        exit_tail->next = new_handler;
    }

    DEBUG_PRINT("VMEXIT registered for 0x%lX cbk 0x%lX opaque 0x%lX override %d",
                exit_reason, callback, opaque, override);
    spin_unlock(&ctx->vmm->lock);
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