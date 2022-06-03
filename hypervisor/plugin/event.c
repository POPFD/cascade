#define DEBUG_MODULE
#include "platform/standard.h"
#include "vmm/vmm_common.h"
#include "memory/vmem.h"
#include "event.h"

struct plugin_event {
    struct plugin_event *next, *prev; /* Doubly linked list. */
    size_t exit_reason;
    event_cbk_t cbk;
    void *opaque;
};

bool plugin_handle_event(struct vcpu_ctx *vcpu, size_t exit_reason, bool *move_to_next)
{
    bool handled = false;
    /*
     * Iterate the plugin list and check to see if any of the registered
     * handlers have the same matching exit reason.
     * 
     * TODO: Create a lighter lock to use, REALLY WE SHOULD BE SPINLOCKED HERE
     *       to prevent issues with multi vCPU's exiting, however we don't want
     *       to use the main VMM lock as it'll slow the system down to a crawl.
     */
    for (struct plugin_event *evt = vcpu->vmm->plugin_event_list; evt != NULL; evt = evt->next) {
        
        /* Check to see if reason matches. */
        if (evt->exit_reason == exit_reason) {

            /* 
             * Call the handler with the exit reason,
             * if returns true then that means the event handler
             * has acknowledged this event was meant for them.
             * 
             * This is IMPORTANT as it's possible to have multiple
             * plugins registered on EPT violation for example but
             * one certain are for one etc. We need to make sure
             * that ALL plugins get the chance to handle if needed.
             */
            if (evt->cbk(vcpu, evt->opaque, move_to_next)) {
                handled = true;
            }
        }
    }

    return handled;
}

void plugin_event_register(struct vmm_ctx *vmm, size_t exit_reason, event_cbk_t cbk, void *opaque)
{
    /* TODO: We need plugin info passed in here too, as in future we will
     * need to unregister all callbacks upon plugin unload. */

    spin_lock(&vmm->lock);

    /* Allocate a new event structure. */
    struct plugin_event *new_event = vmem_alloc(sizeof(struct plugin_event), MEM_WRITE);
    die_on(!new_event, "Unable to allocate memory for new plugin event.");

    /* Fill out the base info of the structure. */
    new_event->exit_reason = exit_reason;
    new_event->cbk = cbk;
    new_event->opaque = opaque;

    /* Now manipulate the doubly link list. */
    if (vmm->plugin_event_list) {
        /* First event in the list. */
        vmm->plugin_event_list = new_event;
        vmm->plugin_event_list->prev = new_event;
        vmm->plugin_event_list->next = NULL;
    } else {
        /* Get the most recent, amend it to point to newest and also amend first item. */
        struct plugin_event *last_event = vmm->plugin_event_list->prev;

        vmm->plugin_event_list->prev = new_event;
        last_event->next = new_event;
    }

    DEBUG_PRINT("Event registered: exit reason 0x%lX cbk 0x%lX", exit_reason, cbk);
    spin_unlock(&vmm->lock);
}

void plugin_event_unregister(struct vmm_ctx *vmm, event_cbk_t cbk)
{
    (void)vmm;
    (void)cbk;
}