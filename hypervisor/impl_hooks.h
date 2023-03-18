#ifndef IMPL_HOOKS_H
#define IMPL_HOOKS_H

/*
 * This header defines all hooks (aka missing code) that
 * the user of this library needs to implement.
 *
 * This is to allow the hypervisor to successfully compile.
 *
 * At time of linking of the library with the consuming application
 * if none of these hooks are implemented you will get an error,
 * aka implement them.
 */
#include "platform/standard.h"

/* Used so the hypervisor can run a specific callback on each physical processor. */
bool impl_run_all_processors(__attribute__((ms_abi)) void (*callback)(void *opaque), void *opaque);

/* Used for retrieving the current processor index. */
bool impl_get_processor_index(size_t *index);

#endif /* IMPL_HOOKS_H */