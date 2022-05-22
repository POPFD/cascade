#define DEBUG_MODULE
#include "platform/standard.h"
#include "plugin.h"

int plugin_load(struct vmm_ctx *vmm, void *guest_raw, size_t plugin_size)
{
    /* Check validity of the parameters. */
    if (!guest_raw || !plugin_size) {
        DEBUG_PRINT("Invalid plugin parameters, raw 0x%lX size 0x%lX\n");
        return -1;
    }
}