
# Compiler and linker specified for hypervisor

# Directories
ROOTDIR := $(shell pwd)
BUILDDIR := $(ROOTDIR)/build
OBJDIR := $(BUILDDIR)/obj

# Child makefile flags
export ROOTDIR
export OBJDIR
export BUILDDIR

# Configuration for making all files.
.PHONY: all
all: prep_dirs
	$(MAKE) -C hypervisor

# Configuration that creates directories needed
prep_dirs:
	mkdir -p $(BUILDDIR)
	mkdir -p $(OBJDIR)

# Cleaning of unneeded files.
.PHONY: clean
clean:
	rm -rf $(OBJDIR)
	rm -rf $(BUILDDIR)