# nettk: build system with sanitizers.
# Recipes use '>' instead of TAB (see .RECIPEPREFIX) so editors cannot break them.
.RECIPEPREFIX = >
.DEFAULT_GOAL := help
SHELL := /bin/bash

# BUILD is one of: asan (default) | tsan | release
BUILD ?= asan
CC    ?= cc
SUDO  ?= sudo
TOPO  ?= basic

BASE_CFLAGS := -std=c11 -D_GNU_SOURCE -g -fno-omit-frame-pointer \
  -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes

ifeq ($(BUILD),asan)
  BUILD_CFLAGS  := -O1 -fsanitize=address,undefined -fno-sanitize=object-size -fno-sanitize-recover=undefined
  BUILD_LDFLAGS := -fsanitize=address,undefined
else ifeq ($(BUILD),tsan)
  BUILD_CFLAGS  := -O1 -fsanitize=thread
  BUILD_LDFLAGS := -fsanitize=thread
else ifeq ($(BUILD),release)
  BUILD_CFLAGS  := -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
  BUILD_LDFLAGS := -pie -Wl,-z,relro,-z,now
else
  $(error BUILD must be asan, tsan, or release)
endif

OUT := build/$(BUILD)
CFLAGS  += $(BASE_CFLAGS) $(BUILD_CFLAGS) -Isrc/lib
LDFLAGS += $(BUILD_LDFLAGS)

# src/lib/*.c  -> $(OUT)/libnettk.a   (decode library, shared by every tool)
# src/<tool>/*.c -> $(OUT)/bin/<tool> (one binary per directory)
LIB_SRC := $(wildcard src/lib/*.c)
LIB_OBJ := $(LIB_SRC:src/%.c=$(OUT)/obj/%.o)
LIB     := $(OUT)/libnettk.a
LIBDEP  := $(if $(LIB_SRC),$(LIB))

TOOL_DIRS := $(filter-out src/lib/,$(wildcard src/*/))
TOOLS := $(foreach d,$(TOOL_DIRS),$(if $(wildcard $(d)*.c),$(notdir $(d:%/=%))))
BINS  := $(TOOLS:%=$(OUT)/bin/%)

define TOOL_RULE
$(1)_OBJ := $$(patsubst src/%.c,$(OUT)/obj/%.o,$$(wildcard src/$(1)/*.c))
$(OUT)/bin/$(1): $$($(1)_OBJ) $$(LIBDEP)
> @mkdir -p $$(@D)
> $$(CC) $$^ -o $$@ $$(LDFLAGS)
endef
$(foreach t,$(TOOLS),$(eval $(call TOOL_RULE,$(t))))

.PHONY: all help clean san-test fuzz fixtures deps \
        lab-up lab-down lab-status lab-check phase0

all: $(BINS) ## build every tool (BUILD=asan|tsan|release)

$(LIB): $(LIB_OBJ)
> @mkdir -p $(@D)
> ar rcs $@ $^

$(OUT)/obj/%.o: src/%.c
> @mkdir -p $(@D)
> $(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(shell find $(OUT)/obj -name '*.d' 2>/dev/null)

san-test: ## prove the sanitizers really catch bugs
> @$(MAKE) --no-print-directory BUILD=asan build/asan/bin/smoke
> @tests/sanitizer_check.sh build/asan/bin/smoke

fuzz: ## build libFuzzer targets (needs clang)
> @command -v clang >/dev/null || { echo "clang required for libFuzzer"; exit 1; }
> @mkdir -p build/fuzz
> @for f in fuzz/fuzz_*.c; do n=$$(basename $$f .c); \
>   clang -g -O1 -fsanitize=fuzzer,address,undefined -Isrc/lib $$f $(LIB_SRC) -o build/fuzz/$$n \
>   && echo "built build/fuzz/$$n"; done

fixtures: ## generate scapy test captures into fixtures/
> python3 py/gen_fixtures.py fixtures

deps: ## check required tools (lab/deps.sh --install to install)
> @lab/deps.sh

lab-up: ## create the lab (TOPO=basic|bridge3)
> $(SUDO) lab/up.sh $(TOPO) --force
lab-down: ## destroy the lab
> $(SUDO) lab/down.sh
lab-status: ## addresses, routes, neighbours
> $(SUDO) lab/status.sh
lab-check: ## smoke-test the running lab
> $(SUDO) lab/check.sh

phase0: ## full Phase 0 acceptance: sanitizers, fixtures, lab up, lab checks
> $(MAKE) san-test
> $(MAKE) fixtures
> $(MAKE) lab-up
> $(MAKE) lab-check

clean: ## remove build output
> rm -rf build

help: ## list targets
> @grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "%-12s %s\n", $$1, $$2}'
