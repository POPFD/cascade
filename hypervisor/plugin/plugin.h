#ifndef PLUGIN_H
#define PLUGIN_H

#include "platform/standard.h"
#include "vmm/vmm_common.h"

int plugin_load(struct vmm_ctx *vmm, void *guest_raw);

#endif /* PLUGIN_H */