#ifndef NESTED_H
#define NESTED_H

#include "platform/standard.h"
#include "vmm_common.h"

void nested_init(struct vmm_ctx *vmm);
void nested_init_vcpu(struct vcpu_ctx *vcpu);

#endif /* NESTED_H */