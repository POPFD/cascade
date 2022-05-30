#include <stdio.h>
#include <windows.h>
#include "cascade_if.h"

__declspec(dllexport) int MS_ABI HypervisorLoad(struct vmm_ctx *vmm, const struct plugin_if *hv_if)
{
    /*
     * This export is called by the hypervisor once it has been loaded into
     * hypervisor context.
     *
     * ANYTHING running in hypervisor context (this) cannot call standard
     * API's or utilise any of the CRT which MAY call underlying API's.
     *
     * Therefore, the limitation is to use ONLY code written in this program.
     * No printf, etc.
     *
     * Also a note, if you write unsafe code here, you're likely to crash
     * the whole system as the host IDT will be called. Just use your brain
     * before writing code here.
     *
     * YOU HAVE BEEN WARNED.
     */
    hv_if->debug.print("Hello world - FROM HOST CONTEXT!\n");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE handle_inst, DWORD reason, LPVOID reserved)
{
    /*
     * Plugins will be loaded within the plugin loader (usermode).
     * So this means we have the ability to use standard Windows API
     * and take advantage of the CRT.
     *
     * Hence, here we can use printf and all other exotic windows APIs.
     * This is added as the plugin may want to do initial setup such as
     * parsing some running processes (so that a PID or page table directory
     * for a process can be retrieved.)
     */
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        printf("Hello world - Attached from plugin loader.\n");
        break;

    case DLL_PROCESS_DETACH:
        printf("Hello world - Detached from plugin loader.\n");
        break;
    }
    return TRUE;
}