#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include "hypervisor.hpp"

static bool g_call_fail = false;

static long exception_handler(_EXCEPTION_POINTERS *info)
{
    g_call_fail = true;
    std::cout << "Exception handler called.\n";
    return EXCEPTION_CONTINUE_EXECUTION;
}

void hypervisor::register_exception_handler()
{
    AddVectoredExceptionHandler(1 /* FIRST */, exception_handler);
}

bool hypervisor::check_and_clear_exception()
{
    bool result = g_call_fail;
    g_call_fail = false;
    return result;
}

bool hypervisor::send_call(vmcall_param &param)
{
    /*
     * Send the action via the VMCALL interface and check
     * the VEH global g_call_fail to see whether the HW
     * responded with a #UD or other fault.
     */
    size_t result;
    asm volatile
    (
        "vmcall\n\t"
        : "=a"(result)
        : "c"(VMCALL_SECRET_KEY), "d"(&param)
    );

    return !check_and_clear_exception() && (result == 0);
}

bool hypervisor::check_presence()
{
    /*
     * As it's possible the cascade hypervisor is
     * hiding it's presence we use the defined VMCALL
     * interface with secret key to query rather than
     * attempting to check presence via VMXE or CPUID
     * hypervisor leafs.
     */
    vmcall_param param = {};
    param.action = ACTION_CHECK_PRESENCE;
    return send_call(param);
}

bool hypervisor::load_plugin(std::string file_name)
{
    /* Load the plugin into this process dynamically then store image start. */
    HMODULE handle_plugin = LoadLibraryA(file_name.c_str());
    if (!handle_plugin) {
        std::cout << "Unable to load " << file_name << " into plugin loader.\n";
    }

    /*
     * It is not guaranteed that every page within the loaded image is currently
     * mapped into the process due to paging. As the hypervisor CANNOT deal with
     * paged out pages we attempt to read every page to attempt to get them all
     * present within memory.
     *
     * We can guarantee that every page within a DLL is readable.
     */
    uint8_t *raw_image = reinterpret_cast<uint8_t *>(handle_plugin);
    PIMAGE_DOS_HEADER idh = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_image);
    PIMAGE_NT_HEADERS inh = reinterpret_cast<PIMAGE_NT_HEADERS>(&raw_image[idh->e_lfanew]);

    for (size_t i = 0; i < inh->OptionalHeader.SizeOfImage; i += 0x1000) {
        /* Perform a bogus read of the page, using the if Sleep to prevent
         * optimisation. */
        if (raw_image[i])
            Sleep(0);
    }

    /* Set up the plugin loading action pointing to raw plugin bytes + size. */
    vmcall_param_load_plugin plugin_param = {};
    plugin_param.plugin = raw_image;

    /* Set up the main vmcall action pointing to our plugin parameters. */
    vmcall_param param = {};
    param.action = ACTION_LOAD_PLUGIN;
    param.param = &plugin_param;
    param.param_size = sizeof(plugin_param);
    return send_call(param);
}

hypervisor::hypervisor()
{
    /* Register VEH so we can catch #UD's on send failure. */
    register_exception_handler();
}