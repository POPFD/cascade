#ifndef IDT_H
#define IDT_H

#include "ia32_compact.h"

void idt_init(segment_descriptor_register_64 *orig_idtr, segment_descriptor_register_64 *new_idtr);

#endif /* IDT_H */