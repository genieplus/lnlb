obj-m := lnlb.o lnlb_mod_tracking.o
default: module userland
module: lnlb.c lnlb_mod_tracking.c
	make -C /usr/src/linux SUBDIRS=$(PWD) modules
userland: lnlbctl.c
	gcc -o lnlbctl lnlbctl.c -Wall
install_module:
	make -C /usr/src/linux SUBDIRS=$(PWD) modules_install
install_userland:
	cp lnlbctl /usr/sbin
install: module userland install_module install_userland
