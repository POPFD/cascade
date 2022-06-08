FILE_NAME := $(shell basename `pwd`)

OUT_OBJ_DIR := $(OBJDIR)/plugins/$(FILE_NAME)
OUT_EXE_NAME := $(BUILDDIR)/$(FILE_NAME).dll

CC := x86_64-w64-mingw32-g++
LD := x86_64-w64-mingw32-ld

CFLAGS := -Wall		\
	-Werror			\
	-I/usr/share/mingw-w64/include \
	-I../../interface/ \

LDFLAGS := -static	\
	-shared

# Use wildcards to gather all of the c files we need to find.
C_FILES := $(shell find . -name '*.cpp')
OBJ_FILES := $(patsubst %.cpp, %.o, $(C_FILES))

.PHONY: all
all: $(OUT_EXE_NAME)

%.o: %.cpp
	mkdir -p  $(OUT_OBJ_DIR)/$(dir $<)
	$(CC) -c -o $(OUT_OBJ_DIR)/$@ $< $(CFLAGS)

$(OUT_EXE_NAME): $(OBJ_FILES)
	echo $(OBJ_FILES)
	rm -f $(OUT_EXE_NAME)
	$(CC) -o $@ $(addprefix $(OUT_OBJ_DIR)/, $^) $(LDFLAGS)

