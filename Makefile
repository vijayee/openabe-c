# OpenABE C Library Makefile
#
# Copyright (c) 2018 Zeutro, LLC. All rights reserved.
#
# This file is part of Zeutro's OpenABE.
#
# OpenABE is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OpenABE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.

# Compiler settings
CC ?= gcc
CXX ?= g++
AR ?= ar
RANLIB ?= ranlib

# Compiler flags
CFLAGS += -std=c11 -Wall -Wextra -fPIC -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -fPIC -O2 -g

# RELIC and GMP paths
RELIC_DIR = deps/relic
RELIC_BUILD = $(RELIC_DIR)/build
RELIC_INCLUDE = $(RELIC_DIR)/include $(RELIC_DIR)/build/include
GMP_INCLUDE = /usr/include/x86_64-linux-gnu

CPPFLAGS += -I./include -I./deps/include -I$(RELIC_DIR)/include -I$(RELIC_BUILD)/include -I$(GMP_INCLUDE) -I./deps/googletest/googletest/include

# Linker flags
LDFLAGS += -L./deps/lib -L./build/gtest -L$(RELIC_BUILD)/lib

# GoogleTest
GTEST_DIR = deps/googletest/googletest
GTEST_OBJ = build/gtest/gtest-all.o

# Libraries - Use RELIC for pairing crypto
CRYPTO_LIBS = -lrelic_s -lgmp -lssl -lcrypto -lpthread
CFLAGS += -DWITH_RELIC
CXXFLAGS += -DWITH_RELIC

# Debug build
ifdef DEBUG
    CFLAGS += -DDEBUG -g -O0
    CXXFLAGS += -DDEBUG -g -O0
endif

# Directories
SRCDIR = src
INCDIR = include
BUILDDIR = build
TESTDIR = tests
EXAMPLEDIR = examples
DEPDIR = deps

# Source files - Core
CORE_SRCS = $(wildcard $(SRCDIR)/core/*.c)

# Source files - ZML (use RELIC implementation)
ZML_SRCS = $(SRCDIR)/zml/oabe_zml_relic.c

# Source files - Utils
UTILS_SRCS = $(wildcard $(SRCDIR)/utils/*.c)

# Source files - Keys
KEYS_SRCS = $(wildcard $(SRCDIR)/keys/*.c)

# Source files - ABE
ABE_SRCS = $(wildcard $(SRCDIR)/abe/*.c)

# Source files - SKE
SKE_SRCS = $(wildcard $(SRCDIR)/ske/*.c)

# Source files - PKE
PKE_SRCS = $(wildcard $(SRCDIR)/pke/*.c)

# Source files - API
API_SRCS = $(wildcard $(SRCDIR)/api/*.c)

# All C sources
ALL_C_SRCS = $(CORE_SRCS) $(ZML_SRCS) $(UTILS_SRCS) $(KEYS_SRCS) $(ABE_SRCS) $(SKE_SRCS) $(PKE_SRCS) $(API_SRCS)

# Object files
CORE_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(CORE_SRCS))
ZML_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(ZML_SRCS))
UTILS_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(UTILS_SRCS))
KEYS_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(KEYS_SRCS))
ABE_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(ABE_SRCS))
SKE_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SKE_SRCS))
PKE_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(PKE_SRCS))
API_OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(API_SRCS))

ALL_OBJS = $(CORE_OBJS) $(ZML_OBJS) $(UTILS_OBJS) $(KEYS_OBJS) $(ABE_OBJS) $(SKE_OBJS) $(PKE_OBJS) $(API_OBJS)

# Test sources
TEST_SRCS = $(wildcard $(TESTDIR)/*.cpp)
TEST_BINS = $(patsubst $(TESTDIR)/%.cpp,$(BUILDDIR)/tests/%,$(TEST_SRCS))

# Example sources
EXAMPLE_C_SRCS = $(wildcard $(EXAMPLEDIR)/*.c)
EXAMPLE_BINS = $(patsubst $(EXAMPLEDIR)/%.c,$(BUILDDIR)/examples/%,$(EXAMPLE_C_SRCS))

# Output libraries
STATIC_LIB = $(BUILDDIR)/liboabe_c.a
SHARED_LIB = $(BUILDDIR)/liboabe_c.so

# GoogleTest
GTEST_ALL = $(BUILDDIR)/gtest/gtest-all.o
GTEST_MAIN = $(BUILDDIR)/gtest/gtest_main.o

# Default target
.PHONY: all
all: $(BUILDDIR) $(STATIC_LIB) $(SHARED_LIB)

# Create build directories
$(BUILDDIR):
	@mkdir -p $(BUILDDIR)/core
	@mkdir -p $(BUILDDIR)/zml
	@mkdir -p $(BUILDDIR)/utils
	@mkdir -p $(BUILDDIR)/keys
	@mkdir -p $(BUILDDIR)/abe
	@mkdir -p $(BUILDDIR)/ske
	@mkdir -p $(BUILDDIR)/pke
	@mkdir -p $(BUILDDIR)/api
	@mkdir -p $(BUILDDIR)/tests
	@mkdir -p $(BUILDDIR)/examples
	@mkdir -p $(BUILDDIR)/gtest

# Build GoogleTest
$(BUILDDIR)/gtest/gtest-all.o: $(GTEST_DIR)/src/gtest-all.cc
	@mkdir -p $(BUILDDIR)/gtest
	$(CXX) $(CXXFLAGS) -I$(GTEST_DIR) -I$(GTEST_DIR)/include -c $< -o $@

$(BUILDDIR)/gtest/gtest_main.o: $(GTEST_DIR)/src/gtest_main.cc
	@mkdir -p $(BUILDDIR)/gtest
	$(CXX) $(CXXFLAGS) -I$(GTEST_DIR) -I$(GTEST_DIR)/include -c $< -o $@

.PHONY: gtest
gtest: $(BUILDDIR)/gtest/gtest-all.o $(BUILDDIR)/gtest/gtest_main.o

# Compile C files
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Build static library
$(STATIC_LIB): $(ALL_OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

# Build shared library
$(SHARED_LIB): $(ALL_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) $(CRYPTO_LIBS)

# Build tests
.PHONY: tests
tests: $(BUILDDIR) $(STATIC_LIB) gtest $(TEST_BINS)

$(BUILDDIR)/tests/%: $(TESTDIR)/%.cpp $(STATIC_LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $(BUILDDIR)/tests/$*.o
	$(CXX) $(BUILDDIR)/tests/$*.o $(GTEST_ALL) -o $@ -L$(BUILDDIR) -loabe_c $(LDFLAGS) $(CRYPTO_LIBS) -lpthread

# Build examples
.PHONY: examples
examples: $(BUILDDIR) $(STATIC_LIB) $(EXAMPLE_BINS)

$(BUILDDIR)/examples/%: $(EXAMPLEDIR)/%.c $(STATIC_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $(BUILDDIR)/examples/$*.o
	$(CC) $(BUILDDIR)/examples/$*.o -o $@ -L$(BUILDDIR) -loabe_c $(LDFLAGS) $(CRYPTO_LIBS)

# Clean
.PHONY: clean
clean:
	rm -rf $(BUILDDIR)

# Install
.PHONY: install
install: $(STATIC_LIB) $(SHARED_LIB)
	@mkdir -p $(PREFIX)/lib
	@mkdir -p $(PREFIX)/include/openabe
	cp $(STATIC_LIB) $(PREFIX)/lib/
	cp $(SHARED_LIB) $(PREFIX)/lib/
	cp -r $(INCDIR)/openabe/*.h $(PREFIX)/include/openabe/

# Run tests
.PHONY: test
test: tests
	@for test in $(BUILDDIR)/tests/*; do \
		echo "Running $$test..."; \
		$$test || exit 1; \
	done

# Print help
.PHONY: help
help:
	@echo "OpenABE C Library Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the library (default)"
	@echo "  tests     - Build tests"
	@echo "  examples  - Build examples"
	@echo "  test      - Run all tests"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install library (requires PREFIX)"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Options:"
	@echo "  USE_RELIC=1       - Use RELIC for pairing (default: OpenSSL)"
	@echo "  DEBUG=1           - Enable debug build"
	@echo "  PREFIX=/path      - Installation prefix (default: /usr/local)"

# Dependencies
-include $(ALL_OBJS:.o=.d)