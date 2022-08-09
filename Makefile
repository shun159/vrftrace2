# Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
.PHONY: all
all: libbpf ebpf_probes vrouter.btf vrft-ebpf

.ONESHELL:
SHELL = /bin/bash

CMD_CLANG   ?= clang
CMD_MAKE    ?= make
CMD_PKGCONF	?= pkg-config
CMD_GO		?= go
CMD_CP      ?= cp
CMD_RM		?= rm

OUTPUT_DIR = ./dist
BPF_PROG_DIR = ./internal/ebpf/c

LIBBPF_HEADERS = $(OUTPUT_DIR)/libbpf
LIBBPF_OBJECT  = $(OUTPUT_DIR)/libbpf/libbpf.a

# ================== helper functions ==================

define pkg_config
	$(CMD_PKGCONF) --libs $(1)
endef

# ================== libraries ==================

LIB_ELF ?= libelf
LIB_ZLIB ?= zlib

# ================== build dir ==================

$(OUTPUT_DIR):
	@mkdir -p $@
	@mkdir -p $@/libbpf/obj
# needed for embed.FS
	@mkdir -p $@/.place-holder 

# ================== libbpf ==================

LIBBPF_CFLAGS="-fPIC"
LIBBPF_LDFLAGS=
LIBBPF_SRC=./libbpf/src/

.PHONY: libbpf
libbpf: $(OUTPUT_DIR)/libbpf/libbpf.a

$(OUTPUT_DIR)/libbpf/libbpf.a:          \
	$(LIBBPF_SRC) 						\
	$(wildcard $(LIBBPF_SRC)/*.[ch])
#
	CC="$(CMD_CLANG)"								\
	CFLAGS="$(LIBBPF_CFLAGS)"						\
	LD_FLAGS="$(LIBBPF_LDFLAGS)"					\
	$(CMD_MAKE)										\
	-C $(LIBBPF_SRC) 								\
	BUILD_STATIC_ONLY=1								\
	DESTDIR=$(abspath $(OUTPUT_DIR)/libbpf/)		\
	OBJDIR=$(abspath $(OUTPUT_DIR)/libbpf/obj)		\
	INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir=	\
	install install_uapi_headers

# ================== eBPF Program ==================

ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := \
  -g \
  -O3 \
  -target bpf \
  -I$(OUTPUT_DIR)/vrftrace.bpf \
  -D__TARGET_ARCH_$(ARCH)

.PHONY: ebpf_probes
ebpf_probes: $(OUTPUT_DIR)/vrftrace_kprobe.bpf.o

$(OUTPUT_DIR)/vrftrace_kprobe.bpf.o: $(BPF_PROG_DIR)/vrftrace_kprobe.bpf.c
	$(CMD_CLANG) $(BPF_CFLAGS) -c $^ -o $@

# ================== tf-vrouter BTF info ==================

.PHONY: vrouter.btf
vrouter.btf: $(OUTPUT_DIR)/vrouter.btf
$(OUTPUT_DIR)/vrouter.btf: $(BPF_PROG_DIR)/vrouter.btf
	$(CMD_CP) -p $^ $@

# ================== Go Application ==================

CUSTOM_CGO_CFLAGS = "				\
-I$(abspath $(OUTPUT_DIR)/libbpf)	\
-I$(abspath bpf/) 					\
"

CUSTOM_CGO_LDFLAGS = "\
$(shell $(call pkg_config, $(LIB_ELF)))   \
$(shell $(call pkg_config, $(LIB_ZLIB)))  \
$(abspath $(OUTPUT_DIR)/libbpf/libbpf.a) \
"

CGO_EXT_LDFLAGS_EBPF =
CGO_EXT_LDFLAGS_EBPF += -static

GO_ENV_EBPF =
GO_ENV_EBPF += GOOS=linux
GO_ENV_EBPF += CC=$(CMD_CLANG)
GO_ENV_EBPF += GOARCH=$(GO_ARCH)
GO_ENV_EBPF += CGO_CFLAGS=$(CUSTOM_CGO_CFLAGS)
GO_ENV_EBPF += CGO_LDFLAGS=$(CUSTOM_CGO_LDFLAGS)

GO_TAGS_EBPF = core,ebpf
GO_FILES:=$(shell find . -type f -name '*.go' -print)
GO_UTEST_FILES:=$(shell find . -type f -name '*_test.go' -print)

.PHONY: vrft-ebpf
vrft-ebpf: bin/vrft
bin/vrft: $(GO_FILES)
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="-w -extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" -linkmode external"\
		-v -o $@ ./cmd/vrft

.PHONY: test-unit
test-unit:
	$(GO_ENV_EBPF) $(CMD_GO) test $(GO_UTEST_FILES) -v -tags $(GO_TAGS_EBPF)

.PHONY: clean
clean:
	$(CMD_RM) -rf bin/
	$(CMD_RM) -rf $(OUTPUT_DIR)
