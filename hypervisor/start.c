#include <efi.h>
#include <efilib.h>
#include "platform/standard.h"
#include "memory/pmem.h"
#include "memory/vmem.h"
#include "vmm/vmm.h"

BOOLEAN _DYNAMIC = TRUE;
 
EFI_STATUS
EFIAPI
efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  InitializeLib(ImageHandle, SystemTable);
  
  debug_print(L"Hello world!\n");

  pmem_init();
  vmem_init();
  vmm_init();

  debug_print(L"Exiting.\n");

  return EFI_SUCCESS;
}