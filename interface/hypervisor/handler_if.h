#ifndef HANDLER_COMMON_H
#define HANDLER_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef void (*vmexit_cbk_t)(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next);

void handler_register_exit(struct handler_ctx *ctx,
                           size_t exit_reason,
                           vmexit_cbk_t callback,
                           void *opaque,
                           bool override);

#endif /* HANDLER_COMMON_H */