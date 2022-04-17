#include "platform/standard.h"
#include "vmm_reg.h"
#include "ia32_compact.h"


__attribute__((ms_abi)) void handler_guest_to_host(struct vcpu_context *guest_ctx)
{
    /* VMEXIT from guest to host. */
    (void)guest_ctx;
}