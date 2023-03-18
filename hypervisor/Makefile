FILE_NAME := $(shell basename `pwd`)

OUT_OBJ_DIR := $(OBJDIR)/$(FILE_NAME)
OUT_LIB_NAME := $(BUILDDIR)/$(FILE_NAME).a

CC := gcc
AR := ar

CDEFINES := CONFIG_NESTED

CFLAGS := -fno-stack-protector		\
	-fdiagnostics-color				\
	-fshort-wchar					\
	-mno-sse						\
	-mno-red-zone					\
	-Wall							\
	-Wextra							\
	-Werror							\
	-I../submodules/ia32-doc/out/	\
	-I../interface/hypervisor/		\
	-I.								\
	-DPRINTF_DISABLE_SUPPORT_FLOAT	\
	$(addprefix -D, $(CDEFINES))

ASMFLAGS := -f elf64 \
	-Werror

# Use wildcards to gather all of the c files we need to find.
C_FILES := $(shell find . -name '*.c')
C_OBJ_FILES := $(patsubst %.c,%.o, $(C_FILES))

ASM_FILES := $(shell find . -name '*.asm')
ASM_OBJ_FILES := $(patsubst %.asm,%.oasm, $(ASM_FILES))

.PHONY: all
all: $(OUT_LIB_NAME)

%.o: %.c
	mkdir -p  $(OUT_OBJ_DIR)/$(dir $<)
	$(CC) -c -o $(OUT_OBJ_DIR)/$@ $< $(CFLAGS)

%.oasm: %.asm
	mkdir -p  $(OUT_OBJ_DIR)/$(dir $<)
	nasm $< -o $(OUT_OBJ_DIR)/$@ $(ASMFLAGS)

$(OUT_LIB_NAME): $(C_OBJ_FILES) $(ASM_OBJ_FILES)
	$(AR) rcs $@ $(addprefix $(OUT_OBJ_DIR)/, $^)
