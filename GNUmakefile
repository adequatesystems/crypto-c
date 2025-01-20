
##
# GNUmakefile - C/C++ makefile for GNU Make
# Copyright 2021-2025 Adequate Systems, LLC. All Rights Reserved.
#

# REQUIRE bash shell
SHELL:= bash

# system directories
CUDADIR:= /usr/local/cuda

# project directories
BINDIR:= bin
BUILDDIR:= build
SUBDIR:= include
SOURCEDIR:= src
TESTBUILDDIR:= $(BUILDDIR)/test
TESTSOURCEDIR:= $(SOURCEDIR)/test
BINSOURCEDIR:= $(SOURCEDIR)/bin
SUBDIRS := $(wildcard $(SUBDIR)/**)

# version info
VERSION := $(shell git describe --always --dirty --tags 2>/dev/null)
VERSION := $(or $(VERSION),u$(shell date +u%g%j)) # untracked version

# compilers
NVCC := $(if $(NO_CUDA),,$(shell ls $(CUDADIR)/bin/nvcc 2>/dev/null | head -n 1))
GCC := $(shell ls /usr/{,local/}bin/gcc-[0-9]* 2>/dev/null | sort -t- -k2,2V | tail -n 1)
CC := $(or $(GCC),$(CC)) # some systems alias gcc elsewhere

# source files: test (base/cuda), base, cuda
BCSRCS:= $(sort $(wildcard $(BINSOURCEDIR)/*.c))
CUSRCS:= $(sort $(wildcard $(SOURCEDIR)/*.cu))
CSRCS:= $(sort $(wildcard $(SOURCEDIR)/*.c))
TCUSRCS:= $(sort $(wildcard $(TESTSOURCEDIR)/*-cu.c))
TCSRCS:= $(sort $(filter-out %-cu.c,$(wildcard $(TESTSOURCEDIR)/*.c)))

# object files: extended filename derived from file ext
COBJS:= $(patsubst $(SOURCEDIR)/%.c,$(BUILDDIR)/%.o,$(CSRCS))
CUOBJS:= $(patsubst $(SOURCEDIR)/%.cu,$(BUILDDIR)/%.cu.o,$(CUSRCS))
TCOBJS:= $(patsubst $(SOURCEDIR)/%.c,$(BUILDDIR)/%.o,$(TCSRCS))
TCUOBJS:= $(patsubst $(SOURCEDIR)/%-cu.c,$(BUILDDIR)/%-cu.o,$(TCUSRCS))
# ... collection of object files
OBJECTS := $(COBJS) $(if $(NVCC),$(CUOBJS))

# test coverage file
COVERAGE := $(BUILDDIR)/coverage.info

# library names: submodule, cuda, base
SUBLIBRARIES := $(patsubst $(SUBDIR)/%,%,$(SUBDIRS))
CULIBRARIES := $(if $(NVCC),cudart nvidia-ml stdc++)
LIBRARY := $(lastword $(notdir $(realpath .)))

# library files: submodule, base
SUBLIBRARYFILES := $(join $(SUBDIRS),$(patsubst $(SUBDIR)/%,/$(BUILDDIR)/lib%.a,$(SUBDIRS)))
LIBRARYFILE := $(BUILDDIR)/lib$(LIBRARY).a

# library directories: submodule, cuda
SUBLIBRARYDIRS := $(addsuffix /$(BUILDDIR),$(SUBDIRS))
CULIBRARYDIRS := $(if $(NVCC),$(addprefix $(CUDADIR),/lib64 /lib64/stubs))

# include directories: submodule, cuda
SUBINCLUDEDIRS := $(addsuffix /$(SOURCEDIR),$(SUBDIRS))
CUINCLUDEDIRS := $(if $(NVCC),$(CUDADIR)/include)

# linker and compiler flags
CXFLAGS := -MMD -MP -Wall -Werror -Wextra -Wpedantic
DFLAGS := $(addprefix -D,$(DEFINES) VERSION=$(VERSION))
IFLAGS := $(addprefix -I,$(SOURCEDIR) $(CUINCLUDEDIRS) $(SUBINCLUDEDIRS))
LFLAGS := $(addprefix -L,$(BUILDDIR) $(CULIBRARYDIRS) $(SUBLIBRARYDIRS))
lFlags := $(addprefix -l,m $(LIBRARY) $(CULIBRARIES) $(SUBLIBRARIES))
LCFLAGS := -pthread
# ... working set of flags
CCFLAGS := $(IFLAGS) $(CXFLAGS) $(CFLAGS) $(DFLAGS) $(LCFLAGS)
LDFLAGS := $(LFLAGS) -Wl,-\( $(lFlags) -Wl,-\) $(LCFLAGS)
NVCCFLAGS := $(IFLAGS) -Xptxas -Werror $(NVCFLAGS)

################################################################

.SUFFIXES: # disable rules predefined by MAKE
.PHONY: all clean coverage docs help library test

# default rule builds (local) library file containing all objects
all: $(SOURCEDIR) $(SUBLIBRARYFILES) $(LIBRARYFILE)

# remove build directory and files
clean:
	@rm -rf $(BUILDDIR)
	@$(if $(NO_RECURSIVE),,$(foreach DIR,$(SUBDIRS),make clean -C $(DIR);))

# build test coverage (requires lcov); depends on coverage file
coverage: $(COVERAGE)
	genhtml $(COVERAGE) --output-directory $(BUILDDIR)

# build documentation files (requires doxygen)
docs:
	@mkdir -p docs
	@cp .github/docs/config docs/config
	@echo 'PROJECT_NAME = "$(LIBRARY)"' | tr '[:lower:]' '[:upper:]' >>docs/config
	@echo 'PROJECT_NUMBER = "$(VERSION)"' >>docs/config
	-doxygen docs/config
	rm docs/config

# echo the value of a variable matching pattern
echo-%:
	@echo $* = $($*)

# display help information
help:
	@echo ""
	@echo "Usage:  make [options] [targets]"
	@echo "Options:"
	@echo "   DEFINES=\"<defines>\" for additional preprocessor definitions"
	@echo "      e.g. make all DEFINES=\"_GNU_SOURCE _XOPEN_SOURCE=600\""
	@echo "   NO_CUDA=1 to disable CUDA support"
	@echo "   NO_RECURSIVE=1 to disable recursive submodule actions"
	@echo "   CFLAGS=\"<flags>\" for additional C compiler flags"
	@echo "   NVCFLAGS=\"<flags>\" for additional NVIDIA compiler flags"
	@echo "      e.g. make all CFLAGS=\"-fsanitize=address\""
	@echo "   ... \"make --help\" for make specific options"
	@echo "User Targets:"
	@echo "   ... no user targets available ..."
	@echo "Utility Targets:"
	@echo "   make [all]       build all object files into a library"
	@echo "   make clean       remove build files (incl. within submodules)"
	@echo "   make coverage    build test coverage file and generate report"
	@echo "   make docs        build documentation files"
	@echo "   make echo-*      show the value of a variable matching *"
	@echo "   make help        prints this usage information"
	@echo "   make test        build and run (all) tests"
	@echo "   make test-*      build and run tests matching *"
	@echo ""

################################################################

# dynamic test objects, names and components; eye candy during tests
TESTOBJECTS:= $(TCOBJS) $(if $(NVCC),$(TCUOBJS))
TESTNAMES:= $(basename $(patsubst $(TESTBUILDDIR)/%,%,$(TESTOBJECTS)))
TESTCOMPS:= $(shell echo $(TESTOBJECTS) | sed 's/\s/\n/g' | \
	sed -E 's/\S*\/([^-]*)[-.]+\S*/\1/g' | sort -u)

# build and run specific tests matching pattern
test-%: $(SUBLIBRARYFILES) $(LIBRARYFILE)
	@echo -e "\n[--------] Performing $(words $(filter $*%,$(TESTNAMES)))" \
		"tests matching \"$*\""
	@$(foreach TEST,\
		$(addprefix $(TESTBUILDDIR)/,$(filter $*%,$(TESTNAMES))),\
		make $(TEST) -s && ( $(TEST) && echo "[ ✔ PASS ] $(TEST)" || \
		( touch $(TEST).fail && echo "[ ✖ FAIL ] $(TEST)" ) \
	 ) || ( touch $(TEST).fail && \ echo "[  ERROR ] $(TEST), ecode=$$?" ); )

# build and run tests
test: $(SUBLIBRARYFILES) $(LIBRARYFILE) $(TESTOBJECTS)
	@if test -d $(BUILDDIR); then find $(BUILDDIR) -name *.fail -delete; fi
	@echo -e "\n[========] Found $(words $(TESTNAMES)) tests" \
		"for $(words $(TESTCOMPS)) components in \"$(LIBRARY)\""
	@echo "[========] Performing all tests in \"$(LIBRARY)\" by component"
	@-$(foreach COMP,$(TESTCOMPS),make test-$(COMP) --no-print-directory; )
	@export FAILS=$$(find $(BUILDDIR) -name *.fail -delete -print | wc -l); \
	 echo -e "\n[========] Testing completed. Analysing results..."; \
	 echo -e "[ PASSED ] $$(($(words $(TESTNAMES))-FAILS)) tests passed."; \
	 echo -e "[ FAILED ] $$FAILS tests failed.\n"; \
	 exit $$FAILS

################################################################

# build (local) library, within build directory, from dynamic object set
$(LIBRARYFILE): $(OBJECTS)
	@mkdir -p $(dir $@)
	ar rcs $(LIBRARYFILE) $(OBJECTS)

# build coverage file, within out directory
$(COVERAGE):
	@mkdir -p $(dir $@)
	@make clean all NO_CUDA=1 "LCFLAGS=$(LCFLAGS) --coverage -O0"
	lcov -c -i -d $(BUILDDIR) -o $(COVERAGE)_base
	@make test NO_CUDA=1 "LCFLAGS=$(LCFLAGS) --coverage -O0"
	lcov -c -d $(BUILDDIR) -o $(COVERAGE)_test
	lcov -a $(COVERAGE)_base -a $(COVERAGE)_test -o $(COVERAGE) || \
		cp $(COVERAGE)_base $(COVERAGE)
	rm -rf $(COVERAGE)_base $(COVERAGE)_test
	lcov -r $(COVERAGE) '*/$(TESTSOURCEDIR)/*' -o $(COVERAGE)

# build test binaries ONLY [EXPERIMENTAL DEPENDENCY-LESS TEST CASES]
#$(TESTBUILDDIR)/%: $(TESTBUILDDIR)/%.o
#	@mkdir -p $(dir $@)
#	$(CC) $(TESTBUILDDIR)/$*.o -o $@

# build test objects ONLY [EXPERIMENTAL DEPENDENCY-LESS TEST CASES]
#$(TESTBUILDDIR)/%.o: $(TESTSOURCEDIR)/%.c
#	@mkdir -p $(dir $@)
#	$(CC) -c $(TESTSOURCEDIR)/$*.c -o $@ $(CCFLAGS)

# build binaries, within build directory, from associated objects
$(BUILDDIR)/%: $(SUBLIBRARYFILES) $(LIBRARYFILE) $(BUILDDIR)/%.o
	@mkdir -p $(dir $@)
	$(CC) $(BUILDDIR)/$*.o -o $@ $(LDFLAGS)

# build cuda objects, within build directory, from *.cu files
$(BUILDDIR)/%.cu.o: $(SOURCEDIR)/%.cu
	@mkdir -p $(dir $@)
	$(NVCC) -c $(SOURCEDIR)/$*.cu -o $@ $(NVCCFLAGS)

# build c objects, within build directory, from *.c files
$(BUILDDIR)/%.o: $(SOURCEDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(SOURCEDIR)/$*.c -o $@ $(CCFLAGS)

# build submodule libraries: depends on submodule source directories
$(SUBLIBRARYFILES): %: $(SUBSOURCEDIRS)
	@make -C $(SUBDIR)/$(word 2,$(subst /, ,$@))

# initialize submodule source directories
$(SUBSOURCEDIRS): %:
	git submodule update --init --recursive

# include depends rules created during "build object file" process
-include $(patsubst $(SOURCEDIR)/%.c,$(BUILDDIR)/%.d,\
   $(BCSRCS) $(CSRCS) $(TCSRCS) $(TCUSRCS) $(TCLSRCS))
