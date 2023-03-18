#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/intrin.h"
#include "memory/mem.h"
#include "app/mem_hide.h"
#include "handler.h"
#include "vmcall.h"
#include "vmcall_if.h"
#include "vmm_common.h"

static bool read_guest_action_param(struct vmcall_param *host_param,
                                      void *action_param,
                                      size_t action_param_size)
{
    /* A vmcall_param sent from the guest can contain a second set of parameters,
     * we will refer to these as action parameters.
     * For example if the ACTION_RW_MEM is called we a second set of params
     * indicating the actual plugin buffer must be sent along too.
     * This utility reads them from the guest and allows the hypervisor to
     * access them. */
    if (!host_param->param || (host_param->param_size != action_param_size)) {
        DEBUG_PRINT("Invalid vmcall parameters %p size %lu for action %d.",
            host_param->param, host_param->param_size, host_param->action);
        return false;
    }

    cr3 guest_cr3;
    guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
    if (!mem_copy_virt_tofrom_host(COPY_READ, guest_cr3, (uintptr_t)host_param->param,
                                 action_param, action_param_size)) {
        DEBUG_PRINT("Unable to copy action param %p size %lu for action %d",
            host_param->param, host_param->param_size, host_param->action);
        return false;
    }

    return true;
}

static size_t handle_check_presence(struct vcpu_ctx *vcpu, struct vmcall_param *host_param)
{
    (void)vcpu;
    (void)host_param;
    DEBUG_PRINT("Guest checked presence.");
    return 0;
}

static size_t handle_mem_hide(struct vcpu_ctx *ctx, struct vmcall_param *host_param)
{
    /* Memory hide takes no parameters. */
    (void)host_param;

    /* Simple call to the memory hiding module for init.
     * This CANNOT fail, therefore we return always success. */
    DEBUG_PRINT("Hiding hypervisor memory.");
    mem_hide_init(ctx->vmm);
    return 0;
}

static size_t handle_rw_mem(struct vcpu_ctx *ctx, struct vmcall_param *host_param)
{
    (void)ctx;

    /* Read the parameters that are needed for arbitrary read/write. */
    struct vmcall_param_rw_mem mem_param = { 0 };
    if (!read_guest_action_param(host_param, &mem_param, sizeof(mem_param))) {
        return -1;
    }

    /* Store the current guest CR3, as this is where the callee needs some data read/wrote */
    cr3 guest_cr3;
    guest_cr3.flags = __vmread(VMCS_GUEST_CR3);

    cr3 src_cr3;
    uintptr_t src_addr;
    cr3 dest_cr3;
    uintptr_t dest_addr;
    size_t size = mem_param.size;
    if (mem_param.dir == DIRECTION_READ) {
        src_cr3 = mem_param.target_cr3;
        src_addr = mem_param.target_addr;
        dest_cr3 = guest_cr3;
        dest_addr = mem_param.local_addr;
    } else {
        src_cr3 = guest_cr3;
        src_addr = mem_param.local_addr;
        dest_cr3 = mem_param.target_cr3;
        dest_addr = mem_param.target_addr;
    }

    bool copy_result = mem_copy_virt_to_virt(src_cr3, (void *)src_addr,
                                             dest_cr3, (void *)dest_addr,
                                             size);
    return copy_result ? 0 : -1;
}

static void vmcall_handle(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next)
{
    typedef size_t (*fn_vmcall_handler)(struct vcpu_ctx *vcpu, struct vmcall_param *host_param);

    static const exception_error_code DEFAULT_EC = { 0 };
    static const fn_vmcall_handler VMCALL_HANDLERS[] = {
        [ACTION_CHECK_PRESENCE] = handle_check_presence,
        [ACTION_HIDE_HV_MEM] = handle_mem_hide,
        [ACTION_RW_MEM] = handle_rw_mem
    };

    (void)opaque;

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
        return;
    }

    /* If guest param not set, do nothing. */
    size_t result = -1;
    if (guest_param) {
        /* Copy the parameter from the guest into host context. */
        cr3 guest_cr3;
        guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
        die_on(!guest_cr3.flags, "Guest CR3 value cannot be retrieved.");

        /* Attempt to copy params from guest to host, if fail do nothing. */
        struct vmcall_param host_param = { 0 };
        if (mem_copy_virt_tofrom_host(COPY_READ, guest_cr3, guest_param,
                                    &host_param, sizeof(host_param))) {

            DEBUG_PRINT("action 0x%lX param 0x%lX param_size 0x%lX",
                        host_param.action, host_param.param, host_param.param_size);

            /* Check to see if handler is defined for action. */
            if ((host_param.action < ARRAY_SIZE(VMCALL_HANDLERS)) &&
                VMCALL_HANDLERS[host_param.action]){

                /* Call the targeted handler. */
                size_t tmp_res = VMCALL_HANDLERS[host_param.action](vcpu, &host_param);

                /* Copy the modified host parameter back to guest memory as it may be modified. */
                if (mem_copy_virt_tofrom_host(COPY_WRITE, guest_cr3, guest_param,
                                            &host_param, sizeof(host_param))) {
                    result = tmp_res;
                }
            }
        }
    }

    vcpu->guest_context.rax = result;
    *move_to_next = true;
}

void vmcall_init(struct vmm_ctx *vmm)
{
    handler_register_exit(vmm->handler, VMX_EXIT_REASON_VMCALL, vmcall_handle, NULL, false);
}