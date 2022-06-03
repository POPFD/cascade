#ifndef PLUGIN_SHIM_H
#define PLUGIN_SHIM_H

/*
 * Plugin shim module to deal with differing ABI's between hypervisor (Linux GCC)
 * and DLL interface (MS_ABI).
 * 
 * I was really stupid mixing different toolchains and such therefore I have to
 * deal with it this way. I SHOULD change this in the future so that a shared
 * ABI is used both for the hypervisor and plugins.
 *
 * That way I can get rid of A LOT of the ms_abi f***ery.
 */

#include "plugin_if.h"
#include "platform/standard.h"
#include "memory/pmem.h"
#include "memory/vmem.h"
#include "plugin/event.h"

static void MS_ABI shim_print(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    debug_print(format, args);
    va_end(args);
}

static uintptr_t MS_ABI shim_phys_alloc_page(void)
{
    return pmem_alloc_page();
}

static uintptr_t MS_ABI shim_phys_alloc_contiguous(size_t bytes)
{
    return pmem_alloc_contiguous(bytes);
}

static void MS_ABI shim_phys_free_page(uintptr_t page)
{
    return pmem_free_page(page);
}

static void MS_ABI shim_plugin_event_reg(struct vmm_ctx *vmm,
                                         size_t exit_reason,
                                         event_cbk_t cbk,
                                         void *opaque)
{
    plugin_event_register(vmm, exit_reason, cbk, opaque);
}

static void MS_ABI shim_plugin_event_unreg(struct vmm_ctx *vmm, event_cbk_t cbk)
{
    plugin_event_unregister(vmm, cbk);
}

static void *MS_ABI shim_virt_alloc(size_t size, bool write, bool exec)
{
    unsigned int flags = 0;
    if (write)
        flags |= MEM_WRITE;
    if (exec)
        flags |= MEM_EXECUTE;

    return vmem_alloc(size, flags);
}

static const struct plugin_if PLUGIN_INTERFACE = {
    .version = PLUGIN_IF_VERSION,
    .debug = {
        .print = shim_print
    },
    .mem = {
        .phys = {
            .alloc_page = shim_phys_alloc_page,
            .alloc_contiguous = shim_phys_alloc_contiguous,
            .free_page = shim_phys_free_page
        },
        .virt = {
            .alloc = shim_virt_alloc
        }
    },
    .event = {
        .register_event = shim_plugin_event_reg,
        .unregister_event = shim_plugin_event_unreg
    }
};


#endif /* PLUGIN_SHIM_H */