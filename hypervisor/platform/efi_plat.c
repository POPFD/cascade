#include "efi_plat.h"
#include "mp_service.h"

/* Abstraction layer for all UEFI specific calls.
 * mp_service.h contains a ripped copy of the PI MPService header
 * as this isn't included in the gnu-efi package as it's intended
 * for firmware only (I don't care, I'm still using it). */


static EFI_MP_SERVICES_PROTOCOL *mp;

void efi_plat_init(EFI_SYSTEM_TABLE *st)
{
    static EFI_GUID MP_GUID = EFI_MP_SERVICES_PROTOCOL_GUID; 

    debug_print("ST: 0x%lX BS: 0x%lX LP: 0x%lX", st, st->BootServices, st->BootServices->LocateProtocol);

    EFI_STATUS status = uefi_call_wrapper(st->BootServices->LocateProtocol, 3, &MP_GUID, NULL, &mp);
    die_on(status != EFI_SUCCESS, "Could not locate MP services protocol.");
}

void efi_plat_run_all_processors(fn_callback_routine routine, void *opaque)
{
    UINTN proc_count;
    UINTN enabled_procs;

    EFI_STATUS status = uefi_call_wrapper(mp->GetNumberOfProcessors, 3,
        mp, &proc_count, &enabled_procs);
    die_on(status, "Unable to retrieve number of processors, status %d", status);

    /* Call on this processor first. */
    routine(opaque);

    if (enabled_procs > 1) {
        /* Call on the other processors now. */
        EFI_STATUS status = uefi_call_wrapper(mp->StartupAllAPs, 7,
            mp, (EFI_AP_PROCEDURE)routine, TRUE, NULL, 0, opaque, NULL);
        die_on(status, "Unable to run routine on all processors, status %d", status);
    }
}

void efi_plat_processor_index(size_t *index)
{
    EFI_STATUS status = uefi_call_wrapper(mp->WhoAmI, 2, mp, (UINTN *)index);
    die_on(status, "Unable to retrieve processor index, status %d", status);
}