KDIR ?= /lib/modules/$(shell uname -r)/source
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

OUTPUT := $(shell pwd)
CFLAGS := -pipe -O2 -Wall -ggdb3
CPPFLAGS := -I $(KDIR)/tools/lib -I $(KDIR)/tools/testing/selftests
LDLIBS := -lelf -lreadline
BIN := xdp_switch.o xdp_dumb_switch
BPFDIR := $(KDIR)/tools/lib/bpf/
BPFOBJ := $(BPFDIR)/libbpf.a
CLANG_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
        | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
CLANG_FLAGS = -nostdinc -I. \
	-isystem /usr/lib/gcc/x86_64-redhat-linux/8/include \
	-I$(KDIR)/arch/$(ARCH)/include \
	-I$(KDIR)/arch/$(ARCH)/include/generated \
	-I$(KDIR)/include \
	-I$(KDIR)/arch/x86/include/uapi \
	-I$(KDIR)/arch/x86/include/generated/uapi \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include/generated/uapi \
	-include $(KDIR)/include/linux/kconfig.h \
	-I$(KDIR)/samples/bpf \
	-I$(KDIR)/tools/testing/selftests/bpf/ \
	-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option  \
	-O2 -emit-llvm

all: $(BIN)

xdp_dumb_switch: xdp_dumb_switch.c $(BPFOBJ)

$(BPFOBJ): force
	$(MAKE) -C $(BPFDIR) OUTPUT=$(OUTPUT)/

xdp_switch.o: xdp_switch.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - |      \
	$(LLC) -march=bpf -mcpu=$(CPU) $(LLC_FLAGS) -filetype=obj -o $@

clean::
	$(RM) $(BIN)

.PHONY: force