#ifndef VMCALL_H
#define VMCALL_H

#include "platform/standard.h"
#include "vmm_common.h"

struct vmcall_ctx *vmcall_init(struct vmm_ctx *vmm);

#endif /* VMCALL_H */