#ifndef HANDLER_H
#define HANDLER_H

#include "platform/standard.h"
#include "handler_common.h"

struct handler_ctx *handler_init(struct vmm_ctx *vmm);
void handler_register_exit(struct handler_ctx *ctx,
                           size_t exit_reason,
                           vmexit_cbk_t callback,
                           void *opaque,
                           bool override);
__attribute__((ms_abi)) void handler_guest_to_host(struct vcpu_context *guest_ctx);

#endif /* HANDLER_H */