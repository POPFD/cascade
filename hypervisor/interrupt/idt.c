#include "platform/standard.h"
#include "platform/intrin.h"
#include "idt.h"
#include "ia32_compact.h"

struct idt_entry {
    uint16_t offset_15_to_0;
    uint16_t segment_selector;
    uint8_t ist : 3;
    uint8_t reserved_0 : 5;
    uint8_t gate_type : 4;
    uint8_t reserved_1 : 1;
    uint8_t dpl : 2;
    uint8_t present : 1;
    uint16_t offset_31_to_16;
    uint32_t offset_63_to_32;
    uint32_t reserved_2;
} __attribute__((packed));

struct exception_stack {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t rax;
	uint64_t interrupt_number;
	uint64_t error_code;
	uint64_t rip;
	uint64_t cs;
	rfl r_flags;
};

#define IDT_ENTRY_COUNT 256

/* The IDT handler function, this is written in NASM rather
 * than in C as we need full control of what goes on. */
extern void *isr_stub_table[];

__attribute__((aligned(0x10))) static segment_descriptor_register_64 idtr;
__attribute__((aligned(0x10))) static struct idt_entry idt_table[IDT_ENTRY_COUNT] = { 0 };

static void set_entry(uint8_t vector, void *isr, uint8_t gate_type)
{
    struct idt_entry *entry = &idt_table[vector];

    entry->offset_15_to_0 = (uint16_t)((uintptr_t)isr);
    entry->segment_selector = __readcs();
    entry->ist = 0;
    entry->reserved_0 = 0;
    entry->gate_type = gate_type;
    entry->reserved_1 = 0;
    entry->dpl = 0;
    entry->present = true;
    entry->offset_31_to_16 = (uint16_t)((uintptr_t)isr >> 16);
    entry->offset_63_to_32 = (uint32_t)((uintptr_t)isr >> 32);
    entry->reserved_2 = 0;
}

/* The exception handler that the common IDT stub function will call. */
void idt_exception_handler(const struct exception_stack *stack)
{
    /* For now, just hang the computer until we have something better to do. */
    (void)stack;
    __asm__ volatile("cli; hlt");
}

void idt_init(void)
{
    /* Create the IDTR. */
    idtr.base_address = (uintptr_t)&idt_table[0];
    idtr.limit = (uint16_t)sizeof(struct idt_entry) * IDT_ENTRY_COUNT - 1;

    /* Fill out all of the IDT entries with their relevant stubs. */
    for (int i = 0; i < IDT_ENTRY_COUNT; i++) {
        set_entry(i, isr_stub_table[i], SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE);
    }
}