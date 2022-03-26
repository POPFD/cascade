#ifndef EFI_PLAT_H
#define EFI_PLAT_H

#include "platform/standard.h"

typedef void (__attribute__((ms_abi)) *fn_callback_routine)(void *opaque);

void efi_plat_init(EFI_SYSTEM_TABLE *st);
void efi_plat_run_all_processors(fn_callback_routine routine, void *opaque);
void efi_plat_processor_index(size_t *index);

#endif /* EFI_PLAT_H */