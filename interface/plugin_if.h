#ifndef PLUGIN_IF_H
#define PLUGIN_IF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Describes the interface that is provided to dynamically loaded plugins.
 * 
 * For example, within the guest we may want to monitor a malicious process,
 * and to do this we have a "tester" application loaded in the guest that then
 * communicates with cascade via the defined VMCALL to load a plugin built
 * explicitly for logging.
 * 
 * Once a plugin (DLL) is loaded it will be provided on init with a
 * structure (plugin_if) providing the ability to make modifications to the
 * hypervisor, such as allocating/freeing memory, registering callbacks etc.
 */
#define PLUGIN_IF_VERSION 1u

typedef struct vmm_ctx *vmm_ctx_t;
typedef struct vcpu_ctx *vcpu_ctx_t;

/* Definition of the ABI used for structure. */
#define MS_ABI __attribute__((ms_abi))

/* Callback to take place from a specific event. */
typedef int (MS_ABI *event_cbk_t)(struct vcpu_ctx *vcpu, void *opaque);

struct plugin_if {
    uint8_t version;

    struct {
        void (MS_ABI *print)(const char *format, ...);
    } debug;

    struct {
        struct {
            /* Allocate physical page within host hypervisor context. */
            uintptr_t (MS_ABI *alloc_page)(void);
            /* Allocate contiguous physical memory within host hypervisor context. */
            uintptr_t (MS_ABI *alloc_contiguous)(size_t bytes);
            /* Free physical page within host hypervisor context. */
            void (MS_ABI *free_page)(uintptr_t page);
        } phys;

        struct {
            /* Allocate virtual memory within host hypervisor context. */
            void *(MS_ABI *alloc)(size_t size, bool write, bool exec);
            /* TODO: Create free routine. */
        } virt;

        struct {
            /* TODO: guest to host conversions. */
            /* TODO: virt to phys conversion. */
        } conv;
    } mem;

    struct {
        /* Register an event handler for a specific VMEXIT. */
        int (MS_ABI *register_event_cbk)(size_t exit_reason, event_cbk_t callback);
        int (MS_ABI *unregister_event_cbk)(event_cbk_t callback);
    } event;
};

/* Callback/export for when plugin has been loaded into host. */
#define PLUGIN_LOAD_EXPORT_NAME "HypervisorLoad"
typedef int (MS_ABI *plugin_load_t)(struct vmm_ctx *vmm, const struct plugin_if *hv_if);

#ifdef __cplusplus
}
#endif

#endif /* PLUGIN_IF_H */