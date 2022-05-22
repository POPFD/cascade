#pragma once
#include "vmcall_if.h"

/*
 * Defines a standard C++ class for interfacing with
 * the hypervisor.
 */
class hypervisor {

    /* Windows VEH registration and checking.
     * we don't have access to __try & __except
     * intrinsincs as is MSVC so we must use VEH. */
    void register_exception_handler();
    bool check_and_clear_exception();

    /* Performs the sending of a VMCALL to the hypervisor. */
    bool send_call(vmcall_param &param);
public:
    hypervisor();

    /* Hypervisor specific actions. */
    bool check_presence();
    bool load_plugin(std::string file_name);
};