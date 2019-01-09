KERNEL_TREE := /home/orangepi/OrangePi/xunlong_github/OrangePi-Kernel/linux-3.4.113/
INSTALL_PATH := /lib/modules/$(shell /bin/uname -r)/kernel/drivers/misc/opi18b20
#CROSS_OPTS := CROSS_COMPILE=/usr/bin/arm-linux-gnueabi- ARCH=arm
CROSS_OPTS :=

.PHONY: all install install_autostart uninstall
all:	opi18b20.ko

opi18b20.ko:	opi18b20.c
	@[ -d ${KERNEL_TREE} ] || { echo "Edit Makefile to set KERNEL_TREE to point at your kernel"; exit 1; }
	@[ -e ${KERNEL_TREE}/Module.symvers ] || { echo "KERNEL_TREE/Module.symvers does not exist, you need to configure and compile your kernel"; exit 1; }
	make -C ${KERNEL_TREE} ${CROSS_OPTS} M=$(PWD) modules

install: opi18b20.ko
	@sudo cp $(PWD)/udev_scripts/opi18b20 /lib/udev
	@sudo cp $(PWD)/udev_scripts/20-opi18b20.rules /etc/udev/rules.d
	@sudo chmod +x /lib/udev/opi18b20
	@echo "OPI18b20 udev rules complete."

reload: opi18b20.ko
	@sudo rmmod opi18b20
	@sudo insmod opi18b20.ko
	@echo "OPI18b20 reload."

load: opi18b20.ko
	@sudo insmod opi18b20.ko
	@echo "OPI18b20 load."

install_autostart: install
	@echo "Enabling OPI18b20 autostart on boot."
	@sudo mkdir -p $(INSTALL_PATH)
	@sudo cp $(PWD)/opi18b20.ko $(INSTALL_PATH)
	@if ! grep opiservo /etc/modules > /dev/null 2>&1; then sudo sed -i '$$a\opi18b20' /etc/modules; fi
	@sudo depmod -a
	@echo "OPI18b20 will now auto start on next boot."
	@echo "The following commands will start and stop the driver:"
	@echo "	modprobe opi18b20"
	@echo "	modprobe -r opi18b20"

uninstall:
	@modprobe -r opi18b20
	@sudo rm -f /lib/udev/opi18b20
	@sudo rm -f /etc/udev/rules.d/20-opi18b20.rules
	@sudo rm -f $(INSTALL_PATH)/opi18b20.ko
	@sudo depmod -a
	
clean:
	make -C ${KERNEL_TREE} ${CROSS_OPTS} M=$(PWD) clean

