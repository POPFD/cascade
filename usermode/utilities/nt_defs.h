#ifndef NT_DEFS_H
#define NT_DEFS_H

#include <stdint.h>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

struct rtl_process_module_information
{
	void *section;
	uintptr_t mapped_base;
	uintptr_t image_base;
	uint32_t image_size;
	uint32_t flags;
	uint16_t load_order_index;
	uint16_t init_order_index;
	uint16_t load_count;
	uint16_t offset_to_file_name;
	char full_path_name[256];
};

struct rtl_process_modules
{
	uint32_t number_of_modules;
	struct rtl_process_module_information modules[1];
};

#endif /* NT_DEFS_H */