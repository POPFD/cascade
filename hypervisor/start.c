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
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
  InitializeLib(image_handle, system_table);

  EFI_LOADED_IMAGE *loaded_image = NULL;
  uefi_call_wrapper(system_table->BootServices->HandleProtocol, 3,
                    image_handle, &gEfiLoadedImageProtocolGuid, &loaded_image);
  debug_print(L"EFI image loaded at: 0x%lX\n", loaded_image->ImageBase);

//#define DEBUG_IDA
#ifdef DEBUG_IDA
  static volatile int wait_debug = 0;

  while (!wait_debug) {}
#endif
  
  /* Initialise all of the required modules and set up the parameters
   * required for the VMM to start. */
  struct vmm_init_params vmm_params = {};

  efi_plat_init(system_table);
  pmem_init();
  vmem_init(&vmm_params.guest_cr3, &vmm_params.host_cr3);
  idt_init(&vmm_params.guest_idtr, &vmm_params.host_idtr);
  vmm_init(&vmm_params);

  debug_print(L"Exiting.\n");

  return EFI_SUCCESS;
}