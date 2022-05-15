.ONESHELL:
SHELL = /bin/sh

CMD_CLANG ?= clang
CMD_MKDIR ?= mkdir
CMD_GIT ?= git
CMD_XXD ?= xxd
CMD_GO ?= go
CMD_RM ?= rm
CMD_PKGCONFIG ?= pkg-config
CMD_MD5 ?= md5sum
CMD_TOUCH ?= touch
CMD_CAT ?= cat
CMD_INSTALL ?= install

OUTPUT_DIR = ./dist
BTF_DIR = bpf/btf
BPF_DIR = bpf/

LIB_HEADERS = /usr/include/
LIBBPF_HEADERS = dist/libbpf
LIBBPF_OBJ = dist/libbpf/libbpf.a
LIBVRFT_OBJ = c_src/libvrft.a

.check_%:
#
	@command -v $* >/dev/null
	if [ $$? -ne 0 ]; then
		echo "missing required tool $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to inexistent file
	fi

$(OUTPUT_DIR):
	@$(CMD_MKDIR) -p $@
	@$(CMD_MKDIR) -p $@/libbpf
	@$(CMD_MKDIR) -p $@/libbpf/obj

$(OUTPUT_DIR)/btfhub:
#
	@$(CMD_MKDIR) -p $@
	@$(CMD_TOUCH) $@/.place-holder # needed for embed.FS

.PHONY: all
all: deps.get libbpf.a xxd_bpf libvrft.a bin/vrft

## bundle
.PHONY: $(OUTPUT_DIR)/vrftrace.bpf
$(OUTPUT_DIR)/vrftrace.bpf: \
	.check_$(CMD_INSTALL)
#
	@$(CMD_MKDIR) -p $@
	$(CMD_INSTALL) -m 0640 $(OUTPUT_DIR)/libbpf/bpf/*.h $@
	$(CMD_INSTALL) -m 0640 bpf/vrftrace_kprobe.bpf.c @

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
  -I$(OUTPUT_DIR)/vrftrace.bpf \
  -D__TARGET_ARCH_$(ARCH)

#
# btfhub (expensive: only run if core obj changed)
#

SH_BTFHUB = ./btfhub.sh

.PHONY: btfhub
btfhub: $(OUTPUT_DIR)/vrftrace_kprobe.bpf.o \
	| .check_$(CMD_MD5)
	$(MAKE) $(OUTPUT_DIR)/btfhub
	@new=$($(CMD_MD5) -b $< | cut -d' ' -f1)
	@if [ -f ".$(notdir $<).md5" ]; then
		old=$($(CMD_CAT) .$(notdir $<).md5)
		if [ "$$old" != "$$new" ]; then
			$(SH_BTFHUB) && echo $$new > .$(notdir $<).md5
		fi
	else
		$(SH_BTFHUB) && echo $$new > .$(notdir $<).md5
	fi

.PHONY: xxd_bpf
xxd_bpf: btfhub \
	c_src/vrftrace_kprobe.bpf.o.h \
	c_src/vrouter.bpf.h

$(OUTPUT_DIR)/vrftrace_kprobe.bpf.o: bpf/vrftrace_kprobe.bpf.c
	$(MAKE) $(OUTPUT_DIR)/vrftrace.bpf
	$(CMD_CLANG) $(BPF_CFLAGS) -c $^ -o $@

c_src/vrftrace_kprobe.bpf.o.h: $(OUTPUT_DIR)/vrftrace_kprobe.bpf.o
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
  -I ./bpf/ \
  -I$(OUTPUT_DIR)/vrftrace.bpf

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
	$(GO_ENV_EBPF) $(CMD_GO) build \
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
	$(CMD_RM) -f .vrftrace_kprobe.bpf.o.md5
	$(CMD_RM) -f bpf/vrftrce
	$(CMD_RM) -f $(OBJS) c_src/libvrft.a
	$(CMD_RM) -f bpf/vrftrace_kprobe.bpf.o
	$(CMD_RM) -f c_src/vrftrace_kprobe.bpf.o.h
