#include "platform/standard.h"
#include "platform/intrin.h"
#include "vmm_common.h"
#include "ia32_compact.h"

#define DEBUG_HANDLER
#ifdef DEBUG_HANDLER
    #define HANDLER_PRINT(...) debug_print(__VA_ARGS__)
#else
    #define HANDLER_PRINT(...)
#endif

static void handle_exit_reason(struct vcpu_ctx *vcpu)
{
    typedef bool (*fn_exit_handler)(struct vcpu_ctx *vcpu, bool *move_next_instr);

    static const fn_exit_handler EXIT_HANDLERS[1] = {
        NULL
    };

    /* Determine the exit reason and then call the appropriate exit handler. */
    size_t reason = __vmread(VMCS_EXIT_REASON) & 0xFFFF;

    die_on(reason >= ARRAY_SIZE(EXIT_HANDLERS),
           L"Exit reason 0x%lX rip 0x%lX not within range of handler table\n",
           reason, vcpu->guest_context.rip);

    HANDLER_PRINT(L"VMEXIT reason: 0x%lX rip: 0x%lX\n", reason, vcpu->guest_context.rip);
    bool move_to_next_instr = false;
    bool success = EXIT_HANDLERS[reason](vcpu, &move_to_next_instr);

    size_t qual = __vmread(VMCS_EXIT_QUALIFICATION);
    die_on(!success,
           L"Exit handler for 0x%lX rip 0x%lX failed with exit qualification 0x%lX\n",
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
    struct vcpu_ctx *vcpu = (struct vcpu_ctx *)((uintptr_t)(guest_ctx + 1) - HOST_STACK_SIZE);

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