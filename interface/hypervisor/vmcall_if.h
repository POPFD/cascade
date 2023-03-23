#ifndef VMCALL_IF_H
#define VMCALL_IF_H

/*
 * As cascade is an introspection framework we want to be able to
 * control the introspection + host capabilities from within
 * guest applications.
 * 
 * This VMCALL interface gives applications within the guest
 * rudimentary ability to perform such actions.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * Secret key which the guest needs to utilise to allow for
 * accessing the VMCALL interface.
 */
#define VMCALL_SECRET_KEY ((size_t)0x0CA5CADE)

/*
 * Generic VMCALL actions that the hypervisor provides.
 */
#define VMCALL_ACTION_CHECK_PRESENCE (0ull)

/* Definition of an action identifier for a VMCALL. */
typedef size_t vmcall_id_t;

/* Definition of a return status code for a VMCALL. */
typedef size_t vmcall_status_t;

#define VMCALL_STATUS_OK 0ull
#define VMCALL_STATUS_INVALID_PARAM 1ull
#define VMCALL_STATUS_INVALID_ID 2ull
#define VMCALL_STATUS_INTERNAL_ERROR 3ull

/*
 * Definition of a VMCALL exit handler callback.
 * buffer is the HOST copy of the buffer provided in
 * the vmcall_param. Upon completion of the callback
 * this will then get copied back into guest context.
 *
 * Opaque is whatever was passed in when registering
 * the VMCALL event by the hypervisor.
 *
 * Return value size_t is a status code for the VMCALL.
 */
typedef vmcall_status_t (*vmcall_cbk_t)(uint8_t *buffer, void *opaque);

/*
 * Definition of the parameter struct a guest uses when performing a
 * VMCALL to the hypervisor.
 */
struct vmcall_param {
    /* The unique identifier of the action to call. */
    vmcall_id_t id;
    /*
     * Extra buffer space for a vmcall parameter.
     * This can be utilised for storing extra data
     * to be communicated between host <-> guest on
     * the VMCALL. Statically fixed to this size to
     * just make life easier when dealing with reading
     * memory to prevent having to alloc & free all
     * the time.
     */
    uint8_t buffer[4096];
};

void vmcall_register_action(struct vmcall_ctx *ctx,
                            vmcall_id_t id,
                            vmcall_cbk_t callback,
                            void *opaque);

#endif /* VMCALL_IF_H */