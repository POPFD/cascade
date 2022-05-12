#ifndef VMCALL_IF_H
#define VMCALL_IF_H

/*
 * As cascade is an introspection framework we want to be able to
 * control the introspection + host capabilities from within
 * guest applications.
 * 
 * This VMCALL interface gives applications within the guest
 * rudimentary ability to perform such actions.
 *
 * The interface gives the ability to load a plugin (DLL)
 * directly to the host environment without having to re-vuild or make
 * any code changes to the hypervisor.
 * 
 * Alongside this the VMCALL interface can be used for retrieving
 * events that have been logged.
 */
#include <stdint.h>
#include <stdbool.h>

#define VMCALL_SECRET_KEY 0x0CA5CADE

enum vmcall_action {
    ACTION_LOAD_PLUGIN,
    ACTION_GATHER_EVENTS
};

/*
 * NOTE: All pointers within this interface are guest virtual addresses.
 * It is the responsibility of the hypervisor to convert these to a usable
 * physical address for read/write while in VM ROOT/HOST.
 */
struct vmcall_param {
    enum vmcall_action action;
    void *param;
    size_t param_size;
};

struct vmcall_param_load_plugin {
    size_t plugin_size;
    uint8_t plugin_buff[];
};

#endif /* VMCALL_IF_H */