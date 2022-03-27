#ifndef VMM_REG_H
#define VMM_REG_H

#include "ia32_compact.h"

struct control_registers {
    cr0 reg_cr0;
    cr3 reg_cr3;
    cr4 reg_cr4;
    uintptr_t gs_base;
    ia32_debugctl_register debugctl;
    uintptr_t dr7;
};

#pragma pack(push, 1)
struct task_state_segment_64
{
	uint32_t reserved0;
	uint64_t rsp0;
	uint64_t rsp1;
	uint64_t rsp2;
	uint64_t reserved1;
	uint64_t ist[7];
	uint64_t reserved3;
	uint16_t reserved4;
	uint16_t io_map_base_address;
};
#pragma pack(pop)

struct gdt_config {
    segment_descriptor_register_64 guest_gdtr;
    segment_descriptor_register_64 host_gdtr;
    segment_descriptor_64 host_gdt[32];
    segment_selector host_tr;
    struct task_state_segment_64 host_tss;
};

#endif /* VMM_REG_H */