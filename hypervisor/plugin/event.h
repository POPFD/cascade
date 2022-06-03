#ifndef PLUGIN_EVENT_H
#define PLUGIN_EVENT_H

#include "plugin_if.h"

bool plugin_handle_event(struct vcpu_ctx *vcpu, size_t exit_reason, bool *move_to_next);
void plugin_event_register(struct vmm_ctx *vmm, size_t exit_reason, event_cbk_t cbk, void *opaque);
void plugin_event_unregister(struct vmm_ctx *vmm, event_cbk_t cbk);

#endif /* PLUGIN_EVENT_H */