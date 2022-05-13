#ifndef VMCALL_H
#define VMCALL_H

#include "platform/standard.h"
#include "vmm_common.h"

bool vmcall_handle(struct vcpu_ctx *vcpu, bool *move_to_next);

#endif /* VMCALL_H */