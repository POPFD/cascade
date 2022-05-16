#include <iostream>
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

hypervisor::hypervisor()
{
    /* Register VEH so we can catch #UD's on send failure. */
    register_exception_handler();
}