#include <efi.h>
#include <efilib.h>
#include "platform/standard.h"
#include "platform/efi_plat.h"
#include "platform/serial.h"
#include "memory/pmem.h"
#include "memory/vmem.h"
#include "interrupt/idt.h"
#include "vmm/vmm.h"

static const EFI_GUID gEfiEventExitBootServicesGuid  = { 0x27ABF055, 0xB1B8, 0x4C26, { 0x80, 0x48, 0x74, 0x8F, 0x37, 0xBA, 0xA2, 0xDF }};
static EFI_EVENT gEfiExitBootServicesEvent = NULL;

void EFIAPI cbk_exit_boot_services(EFI_EVENT evt, void *ctx)
{
  (void)evt;
  (void)ctx;
  debug_print("ExitBootServices!!!");
}

EFI_STATUS
EFIAPI
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
  InitializeLib(image_handle, system_table);

  EFI_LOADED_IMAGE *loaded_image = NULL;
  uefi_call_wrapper(system_table->BootServices->HandleProtocol, 3,
                    image_handle, &gEfiLoadedImageProtocolGuid, &loaded_image);
  debug_print("EFI image loaded at: 0x%lX", loaded_image->ImageBase);

  uefi_call_wrapper(system_table->BootServices->CreateEventEx, 6,
                    EVT_NOTIFY_SIGNAL, TPL_NOTIFY, cbk_exit_boot_services, NULL,
                    &gEfiEventExitBootServicesGuid, &gEfiExitBootServicesEvent);

//#define DEBUG_IDA
#ifdef DEBUG_IDA
  static volatile int wait_debug = 0;

  while (!wait_debug) {}
#endif
  
  /* Initialise all of the required modules and set up the parameters
   * required for the VMM to start. */
  struct vmm_init_params vmm_params = {
    .image_base = (uintptr_t)loaded_image->ImageBase,
    .image_size = (size_t)loaded_image->ImageSize
  };

  efi_plat_init(system_table);
  serial_init();
  pmem_init();
  vmem_init(&vmm_params.guest_cr3, &vmm_params.host_cr3);
  idt_init(&vmm_params.guest_idtr, &vmm_params.host_idtr);
  vmm_init(&vmm_params);

  /* DEBUG: Try trigger a VMEXIT just to test. */
  cpuid_eax_01 version_info;
  CPUID_LEAF_READ(CPUID_VERSION_INFO, version_info);

  debug_print("Exiting.");

  return EFI_SUCCESS;
}