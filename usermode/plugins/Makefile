FILE_NAME := "plugin-loader"

OUT_OBJ_DIR := $(OBJDIR)/plugins/$(FILE_NAME)
OUT_EXE_NAME := $(BUILDDIR)/plugins/$(FILE_NAME).exe

CC := x86_64-w64-mingw32-g++
LD := x86_64-w64-mingw32-ld

CFLAGS := -Wall		\
	-Werror			\
	-I/usr/share/mingw-w64/include \
	-I../../interface/ \
	-I../ \
	-std=c++11		\

LDFLAGS := -static \
	-lstdc++

# Use wildcards to gather all of the c/cpp files we need to find.
# This only searches in the current directory as we don't want plugins
# to be accidentally included.
C_FILES := $(shell find . -maxdepth 1 -name '*.c' -o -name '*.cpp')
C_FILES := $(C_FILES) $(shell find ../utilities -maxdepth 1 -name '*.c' -o -name '*.cpp')
OBJ_FILES := $(patsubst %.c, %.o, $(C_FILES))
OBJ_FILES := $(patsubst %.cpp, %.o, $(OBJ_FILES))

.PHONY: all
all: $(OUT_EXE_NAME)
	$(MAKE) -C hello-world
	$(MAKE) -C driver-monitor

%.o: %.cpp
	mkdir -p  $(OUT_OBJ_DIR)/$(dir $<)
	$(CC) -c -o $(OUT_OBJ_DIR)/$@ $< $(CFLAGS)

$(OUT_EXE_NAME): $(OBJ_FILES)
	rm -f $(OUT_EXE_NAME)
	mkdir -p `dirname ${OUT_EXE_NAME}`
	$(CC) -o $@ $(addprefix $(OUT_OBJ_DIR)/, $^) $(LDFLAGS)

