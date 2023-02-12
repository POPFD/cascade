#include "monitor.hpp"

monitor::monitor(std::string module_name)
    : m_module(module_name)
{
    /*
     * TODO: Determine where IoCreateDevice is in the kernel.
     * TODO: Retrieve what driver we're supposed to be monitoring (via device name).
     *
     * We will use this address to hook as soon as we're loaded in the hypervisor.
     * From there we then can set up some VMEXIT's related to EPT and CR3 loads.
     *
     * This should allow us to be able to monitor actions that a driver
     * is making.
     */
}

int monitor::hypervisor_load(struct vmm_ctx *vmm, const struct plugin_if *hv_if)
{
    return -1;
}