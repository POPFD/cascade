#include <stdint.h>
#include <stdbool.h>
#include "serial.h"
#include "arch.h"

#define SERIAL_PORT 0x3F8 /* COM1 */

static bool is_tx_empty(void)
{
    return (inb(SERIAL_PORT + 5) & 0x20) != 0;
}

static void print_char(char c)
{
    while (!is_tx_empty()) {};
    outb(SERIAL_PORT + 0, c);
}

void serial_init(void)
{
	outb(SERIAL_PORT + 1, 0x00);	/* Disable seiral interrupts. */
	outb(SERIAL_PORT + 3, 0x80);	/* Enable DLAB (set baud rate divisor). */
	outb(SERIAL_PORT + 0, 0x01);	/* Set divisor to 1 (lo byte) 115200/1 baud. */
	outb(SERIAL_PORT + 1, 0x00);	/*					(hi byte) */
	outb(SERIAL_PORT + 3, 0x03);	/* 8 bits, no parity, one stop bit. */
	outb(SERIAL_PORT + 2, 0xC7);	/* Enable FIFO, clear them with 14-byte threshold. */
	outb(SERIAL_PORT + 4, 0x0B);	/* IRQs enabled, RTS/DSR set. */
	outb(SERIAL_PORT + 4, 0x0F);
}

void serial_print(char *str)
{
    for (int i = 0; str[i]; i++) {
        print_char(str[i]);
    }
}