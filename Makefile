CMD_CLANG ?= clang
CMD_MKDIR ?= mkdir
CMD_GIT ?= git
CMD_XXD ?= xxd
CMD_GO ?= go
CMD_RM ?= rm
CMD_PKGCONFIG ?= pkg-config

OUTPUT_DIR = ./dist
BTF_DIR = bpf/btf
BPF_DIR = bpf/

LIB_HEADERS = /usr/include/
LIBBPF_HEADERS = dist/libbpf
LIBBPF_OBJ = dist/libbpf/libbpf.a
LIBVRFT_OBJ = c_src/libvrft.a

$(OUTPUT_DIR):
	@$(CMD_MKDIR) -p $@
	@$(CMD_MKDIR) -p $@/libbpf
	@$(CMD_MKDIR) -p $@/libbpf/obj

.PHONY: all
all: deps.get libbpf.a xxd_bpf libvrft.a bin/vrft

## libbpf
LIBBPF_CFLAGS="-fPIC"
LIBBPF_LDFLAGS=
LIBBPF_SRC=./libbpf/src/

.PHONY: libbpf.a
libbpf.a: $(OUTPUT_DIR)/libbpf/libbpf.a

$(OUTPUT_DIR)/libbpf/libbpf.a: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.[ch])
#
	CC="$(CMD_CLANG)" \
	CFLAGS="$(LIBBPF_CFLAGS)" \
	LD_FLAGS="$(LIBBPF_LDFLAGS)" \
	$(MAKE) \
	-C $(LIBBPF_SRC) \
	BUILD_STATIC_ONLY=1 \
	DESTDIR=$(abspath ./$(OUTPUT_DIR)/libbpf/) \
	OBJDIR=$(abspath ./$(OUTPUT_DIR)/libbpf/obj) \
	INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= \
	install install_uapi_headers

## BPF probes
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := \
  -g \
  -O3 \
  -target bpf \
  -D__TARGET_ARCH_$(ARCH)

.PHONY: xxd_bpf
xxd_bpf: bpf/vrftrace_kprobe.bpf.o c_src/vrftrace_kprobe.bpf.o.h c_src/vrouter.bpf.h

bpf/vrftrace_kprobe.bpf.o: bpf/vrftrace_kprobe.bpf.c
	$(CMD_CLANG) $(BPF_CFLAGS) -c $^ -o $@

c_src/vrftrace_kprobe.bpf.o.h: bpf/vrftrace_kprobe.bpf.o
	$(CMD_XXD) -i $^ > $@

c_src/vrouter.bpf.h:
	$(CMD_XXD) -i $(BTF_DIR)/vrouter_r2011L4.btf > $@

## libvrftrace
OBJS := \
  c_src/symbols.o \
  c_src/portable.o

LDFLAGS := \
  -static \

CFLAGS := \
  -g \
  -Wall \
  -Wextra \
  -I ./bpf/

.PHONY: libvrft.a
libvrft.a: c_src/libvrft.a

c_src/libvrft.a: $(OBJS)
	ar rcs $@ $(OBJS)

#libs
LIB_ELF ?= libelf
LIB_ZLIB ?= zlib

define pkg_config
	$(CMD_PKGCONFIG) --libs $(1)
endef

CUSTOM_CGO_CFLAGS = "-I$(abspath $(OUTPUT_DIR)/libbpf) \
					-I$(abspath c_src/) -I$(abspath bpf/)"
CUSTOM_CGO_LDFLAGS = "$(shell $(call pkg_config, $(LIB_ELF))) \
					 $(shell $(call pkg_config, $(LIB_ZLIB))) \
					 $(abspath $(OUTPUT_DIR)/libbpf/libbpf.a) \
					 $(abspath c_src/libvrft.a)" 

GO_TAGS_EBPF = netgo

CGO_EXT_LDFLAGS_EBPF=
CGO_EXT_LDFLAGS_EBPF += -static

GO_ENV_EBPF =
GO_ENV_EBPF += GOOS=linux
GO_ENV_EBPF += CC=$(CMD_CLANG)
GO_ENV_EBPF += GOARCH=$(GO_ARCH)
GO_ENV_EBPF += CGO_CFLAGS=$(CUSTOM_CGO_CFLAGS)
GO_ENV_EBPF += CGO_LDFLAGS=$(CUSTOM_CGO_LDFLAGS)

GO_FILES:=$(shell find . -type f -name '*.go' -print)

bin/vrft: $(GO_FILES)
	$(GO_ENV_EBPF) $(CMD_GO) build -a \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="-w \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			"\
		-v -o $@ ./cmd/vrft

deps.get:
	$(CMD_GO) mod tidy

test:
	$(CMD_GO) test -v ./tests/

clean:
	$(CMD_RM) -f bin/vrft
	$(CMD_RM) -rf dist/
	$(CMD_RM) -f bpf/vrftrce
	$(CMD_RM) -f $(OBJS) c_src/libvrft.a
	$(CMD_RM) -f bpf/vrftrace_kprobe.bpf.o
	$(CMD_RM) -f c_src/vrftrace_kprobe.bpf.o.h
