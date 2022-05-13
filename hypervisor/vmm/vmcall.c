#include "platform/standard.h"
#include "platform/intrin.h"
#include "memory/mem.h"
#include "vmcall.h"
#include "vmcall_if.h"
#include "vmm_common.h"

static size_t handle_check_presence(struct vcpu_ctx *vcpu, struct vmcall_param *host_param)
{
    (void)vcpu;
    (void)host_param;
    return ~VMCALL_SECRET_KEY;
}

bool vmcall_handle(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    typedef size_t (*fn_vmcall_handler)(struct vcpu_ctx *vcpu, struct vmcall_param *host_param);

    static const exception_error_code DEFAULT_EC = { 0 };
    static const fn_vmcall_handler VMCALL_HANDLERS[] = {
        [ACTION_CHECK_PRESENCE] = handle_check_presence
    };

    /*
     * Handled VMCALL's from the guest.
     * calling convention for the VMCALL interface is as follows:
     *
     * RCX = SECRET_KEY
     * RDX = (struct vmcall_param *) - guest pointer
     * 
     * On return:
     * RAX = result code
     *
     * If RCX is not equal to the secret key, no action taken.
     * If present, attempt to read the action parameter and parse.
     */
    size_t secret_key = vcpu->guest_context.rcx;
    uintptr_t guest_param = vcpu->guest_context.rdx;

    if (secret_key != VMCALL_SECRET_KEY) {
        *move_to_next = false;
        vmm_inject_guest_event(invalid_opcode, DEFAULT_EC);
        return true;
    }

    /* If guest param not set, do nothing. */
    size_t result = 0;
    if (guest_param) {
        /* Copy the parameter from the guest into host context. */
        cr3 guest_cr3;
        guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
        die_on(!guest_cr3.flags, "Guest CR3 value cannot be retrieved.");

        /* Attempt to copy params from guest to host, if fail do nothing. */
        struct vmcall_param host_param = { 0 };
        if (mem_copy_virtual_memory(COPY_READ, guest_cr3, guest_param,
                                    &host_param, sizeof(host_param))) {

            /* Check to see if handler is defined for action. */
            if ((host_param.action < ARRAY_SIZE(VMCALL_HANDLERS)) &&
                VMCALL_HANDLERS[host_param.action]){

                /* Call the targeted handler. */
                size_t tmp_res = VMCALL_HANDLERS[host_param.action](vcpu, &host_param);

                /* Copy the modified host parameter back to guest memory as it may be modified. */
                if (mem_copy_virtual_memory(COPY_WRITE, guest_cr3, guest_param,
                                            &host_param, sizeof(host_param))) {
                    result = tmp_res;
                }
            }
        }
    }

    vcpu->guest_context.rax = result;
    *move_to_next = true;
    return true;
}