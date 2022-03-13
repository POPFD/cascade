#include <efi.h>
#include <efilib.h>
#include "platform/standard.h"
#include "platform/efi_plat.h"
#include "memory/pmem.h"
#include "memory/vmem.h"
#include "interrupt/idt.h"
#include "vmm/vmm.h"

BOOLEAN _DYNAMIC = TRUE;
 
EFI_STATUS
EFIAPI
efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  InitializeLib(ImageHandle, SystemTable);
  
  debug_print(L"Hello world!\n");

  /* Initialise all of the required modules and set up the parameters
   * required for the VMM to start. */
  struct vmm_init_params vmm_params = {};

  efi_plat_init(SystemTable);
  pmem_init();
  vmem_init(&vmm_params.guest_cr3, &vmm_params.host_cr3);
  idt_init();
  vmm_init(&vmm_params);

  debug_print(L"Exiting.\n");

  return EFI_SUCCESS;
}