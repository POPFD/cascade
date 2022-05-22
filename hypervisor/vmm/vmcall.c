#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/intrin.h"
#include "memory/mem.h"
#include "plugin/plugin.h"
#include "vmcall.h"
#include "vmcall_if.h"
#include "vmm_common.h"

static size_t handle_check_presence(struct vcpu_ctx *vcpu, struct vmcall_param *host_param)
{
    (void)vcpu;
    (void)host_param;
    return 0;
}

static size_t handle_load_plugin(struct vcpu_ctx *vcpu, struct vmcall_param *host_param)
{
    /* Ensure parameters for loading plugin are set. */
    if (!host_param->param || (host_param->param_size != sizeof(struct vmcall_param_load_plugin))) {
        DEBUG_PRINT("Invalid vmcall parameters for loading plugin.");
        return -1;
    }

    /* Read the plugin specific parameters, these will be passed to plugin loader. */
    struct vmcall_param_load_plugin plugin_param = { 0 };
    cr3 guest_cr3;
    guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
    if (!mem_copy_virtual_memory(COPY_READ, guest_cr3, (uintptr_t)host_param->param,
                                 &plugin_param, sizeof(plugin_param))) {
        DEBUG_PRINT("Unable to copy plugin parameter to host.");
        return -1;
    }

    /* 
     * Now pass the plugin parameters to our plugin loader module
     * so that it can be dynamically loaded.
     */
    return plugin_load(vcpu->vmm, plugin_param.plugin, plugin_param.raw_size);
}

bool vmcall_handle(struct vcpu_ctx *vcpu, bool *move_to_next)
{
    typedef size_t (*fn_vmcall_handler)(struct vcpu_ctx *vcpu, struct vmcall_param *host_param);

    static const exception_error_code DEFAULT_EC = { 0 };
    static const fn_vmcall_handler VMCALL_HANDLERS[] = {
        [ACTION_CHECK_PRESENCE] = handle_check_presence,
        [ACTION_LOAD_PLUGIN] = handle_load_plugin
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