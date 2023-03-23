#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/intrin.h"
#include "memory/mem.h"
#include "memory/vmem.h"
#include "handler.h"
#include "vmcall.h"
#include "vmcall_if.h"
#include "vmm_common.h"

struct vmcall_handler {
    /* Linked list pointer. */
    struct vmcall_handler *next;
    /* The action ID for identification. */
    vmcall_id_t id;
    /* The callback for the vmcall. */
    vmcall_cbk_t callback;
    /* Callback specific data. */
    void *opaque;
};

struct vmcall_ctx {
    /* Hold a linked list of vmcall handlers. */
    struct vmcall_handler *handlers;
    /* Back reference to the VMM context */
    struct vmm_ctx *vmm;
};

static struct vmcall_handler *find_handler(struct vmcall_ctx *ctx, vmcall_id_t id)
{
    struct vmcall_handler *curr = ctx->handlers;
    while (curr) {
        if (curr->id == id)
            return curr;

        curr = curr->next;
    }
    return NULL;
}

static vmcall_status_t handle_check_presence(uint8_t *buffer, void *opaque)
{
    (void)buffer;
    (void)opaque;
    DEBUG_PRINT("Guest checked presence.");
    return VMCALL_STATUS_OK;
}

static void vmcall_exit_handle(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next)
{
    static const exception_error_code DEFAULT_EC = { 0 };

    /*
     * Handled VMCALL's from the guest.
     * calling convention for the VMCALL interface is as follows:
     *
     * RCX = SECRET_KEY
     * RDX = (struct vmcall_param *) - guest pointer
     * 
     * On return:
     * RAX = vmcall status
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

    /* Ensure we actually have a parameter specified. */
    vmcall_status_t status;
    if (!guest_param) {
        status = VMCALL_STATUS_INVALID_PARAM;
        goto tidyup;
    }

    /* Copy the parameter from the guest into host context. */
    cr3 guest_cr3;
    guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
    die_on(!guest_cr3.flags, "Guest CR3 value cannot be retrieved.");

    struct vmcall_param host_param = { 0 };
    if (!mem_copy_virt_tofrom_host(COPY_READ, guest_cr3, guest_param,
                                   &host_param, sizeof(host_param))) {
        status = VMCALL_STATUS_INVALID_PARAM;
        goto tidyup;
    }

    /* Now lets actually do the VMCALL callback handling. */
    struct vmcall_ctx *ctx = (struct vmcall_ctx *)opaque;

    spin_lock(&ctx->vmm->lock);

    /* Find the handler relevant for the VMCALL. */
    struct vmcall_handler *handler = find_handler(ctx, host_param.id);
    if (!handler) {
        status = VMCALL_STATUS_INVALID_ID;
        goto tidyup_locked;
    }

    /* Call the handler and store status. */
    status = handler->callback(host_param.buffer, handler->opaque);
    DEBUG_PRINT("VMCALL callback id=%ld status=%ld", host_param.id, status);

    /* Copy the modified host parameter back to guest memory. */
    if (!mem_copy_virt_tofrom_host(COPY_WRITE, guest_cr3, guest_param,
                                   &host_param, sizeof(host_param))) {
        status = VMCALL_STATUS_INTERNAL_ERROR;
    }

    /* Now store success status. */
tidyup_locked:
    spin_unlock(&ctx->vmm->lock);
tidyup:
    vcpu->guest_context.rax = status;
    *move_to_next = true;
}

struct vmcall_ctx *vmcall_init(struct vmm_ctx *vmm)
{
    /* Allocate our context structure for VMCALL handling. */
    struct vmcall_ctx *ctx = vmem_alloc(sizeof(struct vmcall_ctx), MEM_WRITE);
    die_on(!ctx, "Unable to allocate context for VMCALL handlers.");
    vmm->vmcall = ctx;
    ctx->vmm = vmm;

    /* Register a VMEXIT reason handler so we can catch & parse VMCALLs. */
    handler_register_exit(vmm->handler, VMX_EXIT_REASON_VMCALL, vmcall_exit_handle, ctx, false);

    /* Register our generic VMCALL events. */
    vmcall_register_action(ctx, VMCALL_ACTION_CHECK_PRESENCE, handle_check_presence, ctx);

    return ctx;
}

void vmcall_register_action(struct vmcall_ctx *ctx,
                            vmcall_id_t id,
                            vmcall_cbk_t callback,
                            void *opaque)
{
    /* Ensure synchronization. */
    spin_lock(&ctx->vmm->lock);

    /* Ensure there isn't already a VMCALL handler registered with same ID. */
    die_on(find_handler(ctx, id),
           "Handler already existing for VMCALL id=%ld", id);

    /* Allocate a new handler structure. */
    struct vmcall_handler *new_handler = vmem_alloc(sizeof(struct vmcall_handler), MEM_WRITE);
    die_on(!new_handler, "Unable to allocate memory for VMCALL handler.");

    new_handler->id = id;
    new_handler->callback = callback;
    new_handler->opaque = opaque;

    /* Now add it to the head of our handler list. */
    if (!ctx->handlers)
        ctx->handlers = new_handler;
    else {
        new_handler->next = ctx->handlers;
        ctx->handlers = new_handler;
    }

    DEBUG_PRINT("VMCALL registered for id %ld cbk 0x%lX opaque 0x%lX",
                id, callback, opaque);
    spin_unlock(&ctx->vmm->lock);
}