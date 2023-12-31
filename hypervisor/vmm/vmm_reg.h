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

struct __attribute__ ((aligned (16))) m128a {
    uint64_t low;
    int64_t high;
};

struct __attribute__ ((aligned (16))) xmm_save_area32
{
    uint16_t control_word;
    uint16_t status_word;
    uint8_t tag_word;
    uint8_t reserved1;
    uint16_t error_opcode;
    uint32_t error_offset;
    uint16_t error_selector;
    uint16_t reserved2;
    uint32_t data_offset;
    uint16_t data_selector;
    uint16_t reserved3;
    uint32_t mx_csr;
    uint32_t mx_csr_mask;
    struct m128a float_registers[8];
    struct m128a xmm_registers[16];
    uint8_t reserved4[96];
};

struct __attribute__ ((aligned (16))) vcpu_context {
    uint64_t p1_home;
    uint64_t p2_home;
    uint64_t p3_home;
    uint64_t p4_home;
    uint64_t p5_home;
    uint64_t p6_home;
    uint32_t context_flags;
    uint32_t mx_csr;
    uint16_t seg_cs;
    uint16_t seg_ds;
    uint16_t seg_es;
    uint16_t seg_fs;
    uint16_t seg_gs;
    uint16_t seg_ss;
    uint32_t e_flags;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    union
    {
        struct xmm_save_area32 flt_save;
        struct
        {
            struct m128a header[2];
            struct m128a legacy[8];
            struct m128a xmm0;
            struct m128a xmm1;
            struct m128a xmm2;
            struct m128a xmm3;
            struct m128a xmm4;
            struct m128a xmm5;
            struct m128a xmm6;
            struct m128a xmm7;
            struct m128a xmm8;
            struct m128a xmm9;
            struct m128a xmm10;
            struct m128a xmm11;
            struct m128a xmm12;
            struct m128a xmm13;
            struct m128a xmm14;
            struct m128a xmm15;
        };
    };
    struct m128a vector_register[26];
    uint64_t vector_control;
    uint64_t debug_control;
    uint64_t last_branch_to_rip;
    uint64_t last_branch_from_rip;
    uint64_t last_exception_to_rip;
    uint64_t last_exception_from_rip;
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
    __attribute__ ((aligned (16))) segment_descriptor_64 host_gdt[32];
    __attribute__ ((aligned (16))) segment_descriptor_register_64 guest_gdtr;
    __attribute__ ((aligned (16))) segment_descriptor_register_64 host_gdtr;
    segment_selector guest_ldtr;
    segment_selector host_tr;
    struct task_state_segment_64 host_tss;
};

#endif /* VMM_REG_H */