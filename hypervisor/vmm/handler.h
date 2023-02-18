#ifndef HANDLER_H
#define HANDLER_H

#include "platform/standard.h"

typedef void (*exit_cbk_t)(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next);

struct handler_ctx *handler_init(void);
void handler_register_exit(struct handler_ctx *ctx,
                           size_t exit_reason,
                           exit_cbk_t callback,
                           void *opaque,
                           bool override);
__attribute__((ms_abi)) void handler_guest_to_host(struct vcpu_context *guest_ctx);

#endif /* HANDLER_H */