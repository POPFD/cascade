FILE_NAME := $(shell basename `pwd`)

OUT_OBJ_DIR := $(OBJDIR)/$(FILE_NAME)
OUT_SO_NAME := $(OBJDIR)/$(FILE_NAME)/$(FILE_NAME).so
OUT_EFI_NAME := $(BUILDDIR)/$(FILE_NAME).efi

EFI_LIB_PATH := /usr/lib/

CC := gcc
LD := ld
OC := objcopy

CFLAGS := -fno-stack-protector	\
	-fpic 						\
	-fshort-wchar				\
	-mno-red-zone				\
	-Wall						\
	-Wextra						\
	-Werror						\
	-I/usr/include/efi			\
	-I/usr/include/efi/x86_64	\
	-I.							\
	-DEFI_FUNCTION_WRAPPER


LDFLAGS := $(EFI_LIB_PATH)crt0-efi-x86_64.o	\
	-nostdlib								\
	-znocombreloc							\
	-T elf_x86_64_efi.lds					\
	-Bsymbolic								\
	-L $(EFI_LIB_PATH)						\
	-l:libgnuefi.a							\
	-l:libefi.a								\

OCFLAGS := -j .text			\
	-j .sdata				\
	-j .data				\
	-j .bss					\
	-j .dynamic				\
	-j .dynsym				\
	-j .rel					\
	-j .rela				\
	-j .reloc				\
	--target=efi-app-x86_64

# Use wildcards to gather all of the c files we need to find.
C_FILES := $(shell find . -name '*.c')
OBJ_FILES := $(patsubst %.c,%.o, $(C_FILES))

.PHONY: all
all: $(OUT_EFI_NAME)

%.o: %.c
	mkdir -p  $(OUT_OBJ_DIR)/$(dir $<)
	$(CC) -c -o $(OUT_OBJ_DIR)/$@ $< $(CFLAGS)

$(OUT_SO_NAME): $(OBJ_FILES)
	$(LD) -o $@ $(addprefix $(OUT_OBJ_DIR)/, $^) $(LDFLAGS)

$(OUT_EFI_NAME): $(OUT_SO_NAME)
	rm -f $(OUT_EFI_NAME)
	$(OC) $(OCFLAGS) $^ $@