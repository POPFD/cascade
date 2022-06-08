/*
 * Module for monitoring a specific driver/module in kernel memory.
 */
#pragma once
#include <string>

class monitor {
    const std::string m_module;

public:
    monitor(std::string module_name);
    int hypervisor_load(struct vmm_ctx *vmm, const struct plugin_if *hv_if);
};
