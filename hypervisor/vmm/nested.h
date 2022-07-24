#ifndef NESTED_H
#define NESTED_H

#include "platform/standard.h"
#include "vmm_common.h"

bool nested_mov_crx(struct vcpu_ctx *vcpu, bool *move_to_next);
bool nested_vmxon(struct vcpu_ctx *vcpu, bool *move_to_next);

#endif /* NESTED_H */