#ccflags-m += -I./include/uapi


MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build

obj-m := xt_NATMAP.o

all:	modules

modules:
	make -C ${KERNEL_DIR} KBUILD_MODPOST_WARN=1 M=$$PWD $@ $(MFLAGS)
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	depmod -a;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -rf modules.order
