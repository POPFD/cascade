#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <efi.h>
#include <efilib.h>
#include "hypervisor.h"
#include "mp_service.h"

static EFI_MP_SERVICES_PROTOCOL *mp_protocol = NULL;

/*
 * Definitions of the callback hooks that are required to be implemented
 * by the system. In UEFI we implement these via EFI_MP_SERVICES.
 */
bool impl_run_all_processors(__attribute__((ms_abi)) void (*callback)(void *opaque), void *opaque)
{
    EFI_STATUS status;
    UINTN proc_count;
    UINTN enabled_procs;

    status = uefi_call_wrapper(mp_protocol->GetNumberOfProcessors, 3,
                               mp_protocol, &proc_count, &enabled_procs);
    if (status)
        return false;

    /* Call on this processor first. */
    callback(opaque);

    /* Call on other processors now. */
    if (enabled_procs > 1) {
        status = uefi_call_wrapper(mp_protocol->StartupAllAPs, 7,
                                   mp_protocol, (EFI_AP_PROCEDURE)callback,
                                   true, NULL, 0, opaque, NULL);
        if (status)
            return false;
    }

    return true;
}

bool impl_get_processor_index(size_t *index)
{
    EFI_STATUS status = uefi_call_wrapper(mp_protocol->WhoAmI, 2, mp_protocol, (UINTN *)index);
    return (status == EFI_SUCCESS);
}

EFI_STATUS EFIAPI efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
    static const EFI_GUID MP_GUID = EFI_MP_SERVICES_PROTOCOL_GUID;

    InitializeLib(image_handle, system_table);

    /* Locate the MP protocol so we can fill in our hooks for the hypervisor. */
    EFI_STATUS status = uefi_call_wrapper(system_table->BootServices->LocateProtocol, 3,
        &MP_GUID, NULL, &mp_protocol);

    if (status)
        return status;


    hypervisor_init();

    return EFI_SUCCESS;
}