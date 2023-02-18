#ifndef HANDLER_COMMON_H
#define HANDLER_COMMON_H

typedef void (*vmexit_cbk_t)(struct vcpu_ctx *vcpu, void *opaque, bool *move_to_next);

#endif /* HANDLER_COMMON_H */