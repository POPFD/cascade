#ifndef HANDLER_H
#define HANDLER_H

#include "platform/standard.h"
#include "vmm_common.h"
#include "handler_if.h"

struct handler_ctx *handler_init(struct vmm_ctx *vmm);
__attribute__((ms_abi)) void handler_guest_to_host(struct vcpu_context *guest_ctx);

#endif /* HANDLER_H */