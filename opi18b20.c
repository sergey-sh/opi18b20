/*
 * opi18b20.c DS18B20 Driver for the Orange PI one
 * Copyright (c) 2019 Sergey Shkuliov <sergey.sckuliov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * If you want the device node created automatically create these two
 * files, and make /lib/udev/opi18b20 executable (chmod +x):
 *
 * ============= /etc/udev/rules.d/20-opi18b20.rules =============
 * SUBSYSTEM=="module", DEVPATH=="/module/opi18b20", RUN+="/lib/udev/opi18b20"
 * ===================================================================
 *
 * ===================== /lib/udev/opi18b20 ======================
 * #!/bin/bash
 *
 * if [ "$ACTION" = "remove" ]; then
 *         rm -f /dev/opi18b20
 * elif [ "$ACTION" = "add" ]; then
 *          major=$( sed -n 's/ opi18b20//p' /proc/devices )
 *        [ "$major" ] && mknod -m 0666 /dev/opi18b20 c $major 0
 * fi
 *
 * exit 0
 * ===================================================================
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

#define MAX_READ_MESSAGE_SIZE 256
#define MAX_WRITE_MESSAGE_SIZE 1024
#define MAX_BUF_VALUE 21
#define MAX_ERR 3

#define MAX_DEVICES 64
#define NUM_PINS 9*32



// This struct is used to store all temporary data associated with a given
// open() of /dev/opi18b20
struct private_data {
	int rd_query;	
	int rd_len;
	char rd_data[MAX_READ_MESSAGE_SIZE];
	int wr_len;
	char wr_data[MAX_WRITE_MESSAGE_SIZE];
};

static int dev_open(struct inode *, struct file *);
static int dev_close(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static long dev_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations fops = {
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_close,
	.unlocked_ioctl = dev_ioctl,
	.compat_ioctl = dev_ioctl,
};

static dev_t devno;
static struct cdev my_cdev;
static int my_major;
bool terminated = false;

#define OPI18B20_CDEVNAME "opi18b20"
#define NSEC_PER_MSEC   1000000L
#define MS_TO_NS(x) (x * NSEC_PER_MSEC)

// GPIO
static volatile uint32_t *gpio; 

#define SUNXI_PORT_BASE	(0x01C20000)

#define SUNXI_GPIO_OFFSET	(0x0800)
#define	SUNXI_GPIO_LEN	(4*1024)

#define	INPUT	0
#define	OUTPUT	1


#define	LOW	0
#define	HIGH	1


static int BP_PIN_MASK[][32] =  //[BANK]  [INDEX]
{
 { 0, 1, 2, 3,-1,-1, 6, 7, 8, 9,10,11,12,13,14,-1,-1,-1,18,19,20,21,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PA
 {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PB
 { 0, 1, 2, 3, 4,-1,-1, 7,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PC
 {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,14,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PD
 {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PE
 {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PF
 {-1,-1,-1,-1,-1,-1, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PG
 {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PH
 {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,},//PI
};


static uint32_t count_pins=0;
static uint32_t pins[NUM_PINS];
static uint32_t pins_offset_devices[NUM_PINS];
static uint32_t pins_count_devices[NUM_PINS];

static uint32_t count_device=0;
static uint64_t devices[MAX_DEVICES];
static uint32_t data_devices[MAX_DEVICES];

static u8 w1_crc8_table[] = {
	0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
	157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
	35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
	190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
	70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
	219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
	101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
	248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
	140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
	17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
	175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
	50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
	202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
	87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
	233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
	116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53
};

#define CMD_CONVERTTEMP    0x44
#define CMD_RSCRATCHPAD    0xbe
#define CMD_WSCRATCHPAD    0x4e
#define CMD_CPYSCRATCHPAD  0x48
#define CMD_RECEEPROM      0xb8
#define CMD_RPWRSUPPLY     0xb4
#define CMD_SEARCHROM      0xf0
#define CMD_READROM        0x33
#define CMD_MATCHROM       0x55
#define CMD_SKIPROM        0xcc
#define CMD_ALARMSEARCH    0xec

static void w1_delay(unsigned long tm) {
	udelay(tm);
}

static u8 w1_calc_crc8(u8 * data, int len) {
	u8 crc = 0;

	while (len--)
		crc = w1_crc8_table[crc ^ *data++];

	return crc;
}

static uint32_t readlI(uint32_t addr) {
	return *(gpio + (addr >> 2));
}

static void writelI(uint32_t val, uint32_t addr) {
	*(gpio + (addr >> 2)) = val;
}

static void sunxi_set_gpio_mode(int pin,int mode) {
	uint32_t regval = 0;
	int bank = pin >> 5;
	int index = pin - (bank << 5);
	int offset = ((index - ((index >> 3) << 3)) << 2);
	uint32_t phyaddr = SUNXI_GPIO_OFFSET + (bank * 36) + ((index >> 3) << 2);
	if(BP_PIN_MASK[bank][index] != -1) {
		regval = readlI(phyaddr);
		regval &= ~(7 << offset);
		regval |=  ((mode & 7) << offset);
		writelI(regval, phyaddr);
	} else {
		printk("pin number error\n");
	}
}

static void sunxi_digitalWrite(int pin, int value) { 
	uint32_t regval = 0;
	int bank = pin >> 5;
	int index = pin - (bank << 5);
	uint32_t phyaddr = SUNXI_GPIO_OFFSET + (bank * 36) + 0x10; // +0x10 -> data reg
	if(BP_PIN_MASK[bank][index] != -1) {
		regval = readlI(phyaddr);
		if(0 == value) {
			regval &= ~(1 << index);
			writelI(regval, phyaddr);
		} else {
			regval |= (1 << index);
			writelI(regval, phyaddr);
		}
	} else {
		printk("pin number error\n");
	}
}

static int sunxi_digitalRead(int pin) {
	uint32_t regval = 0;
	int bank = pin >> 5;
	int index = pin - (bank << 5);
	uint32_t phyaddr = SUNXI_GPIO_OFFSET + (bank * 36) + 0x10; // +0x10 -> data reg
	if(BP_PIN_MASK[bank][index] != -1) {
		regval = readlI(phyaddr);
		regval = regval >> index;
		regval &= 1;
		return regval;
	} else {
		printk("Sunxi_digitalRead() pin - number error\n");
		return regval;
	}
}

static void init_devices(void) {
	count_pins = 0;
	memset(pins, 0, sizeof(pins));
	memset(pins_offset_devices, 0, sizeof(pins_offset_devices));
	memset(pins_count_devices	, 0, sizeof(pins_count_devices	));

	count_device = 0;
	memset(devices, 0, sizeof(devices));
	memset(data_devices, 0, sizeof(data_devices));
}

static int OneWire_reset(int pin) {
	int response;

	sunxi_set_gpio_mode(pin, OUTPUT);
	sunxi_digitalWrite(pin, LOW);
	w1_delay(480);

	sunxi_set_gpio_mode(pin, INPUT);
	w1_delay(60);

	response = sunxi_digitalRead(pin);
	w1_delay(410);

	return response;
}

static void OneWire_writeBit(int pin, uint8_t bit) {
	if (bit & 1) {
		sunxi_set_gpio_mode(pin, OUTPUT);
		sunxi_digitalWrite(pin, LOW);
		w1_delay(10);
		sunxi_set_gpio_mode(pin, INPUT);
		w1_delay(55);
	} else {
		sunxi_set_gpio_mode(pin, OUTPUT);
		sunxi_digitalWrite(pin, LOW);
		w1_delay(65);
		sunxi_set_gpio_mode(pin, INPUT);
		w1_delay(5);
	}
}

static void OneWire_writeByte(int pin, uint8_t byte) {
	uint8_t i = 8;
	while (i--) {
		OneWire_writeBit(pin, byte & 1);
		byte >>= 1;
	}
}

static uint8_t OneWire_readBit(int pin) {
	uint8_t bit = 0;
	unsigned long flags;

	sunxi_set_gpio_mode(pin, OUTPUT);

	local_irq_save(flags);

	sunxi_digitalWrite(pin, LOW);
	w1_delay(3);

	sunxi_set_gpio_mode(pin, INPUT);
	w1_delay(10);

	bit = sunxi_digitalRead(pin);

	local_irq_restore(flags);

	w1_delay(45);
	return bit;
}

static uint8_t OneWire_readByte(int pin) {
	uint8_t i = 8, byte = 0;
	while (i--) {
		byte >>= 1;
		byte |= (OneWire_readBit(pin) << 7);
	}
	return byte;
}

static uint64_t OneWire_searchNextAddress(int pin, uint64_t lastAddress, int *lastDiscrepancy, int *err) {
	uint64_t newAddress = 0;
	int searchDirection = 0;
	int idBitNumber = 1;
	int lastZero = 0;
	
	*err = 0;

	OneWire_reset(pin);
	OneWire_writeByte(pin, CMD_SEARCHROM);

	while (idBitNumber < 65) {
		int idBit = OneWire_readBit(pin);
		int cmpIdBit = OneWire_readBit(pin);

		// id_bit = cmp_id_bit = 1
		if (idBit == 1 && cmpIdBit == 1) {
			*err = 1;
			return 0;
		} else if (idBit == 0 && cmpIdBit == 0) {
			// id_bit = cmp_id_bit = 0
			if (idBitNumber == *lastDiscrepancy) {
				searchDirection = 1;
			} else if (idBitNumber > *lastDiscrepancy) {
				searchDirection = 0;
			} else {
				if ((uint8_t)(lastAddress >> (idBitNumber - 1)) & 1) {
					searchDirection = 1;
				} else {
					searchDirection = 0;
				}
			}
			if (searchDirection == 0) {
				lastZero = idBitNumber;
			}
		} else {
		  // id_bit != cmp_id_bit
		  searchDirection = idBit;
		}
		newAddress |= ((uint64_t) searchDirection) << (idBitNumber - 1);
		OneWire_writeBit(pin, searchDirection);
		idBitNumber++;
	}
	*lastDiscrepancy = lastZero;
	return newAddress;
}

static u8 OneWire_crcCheck(uint64_t data8x8bit) {
	uint8_t dat[8];
	for (int i = 0; i < 8; i++) {
		dat[i] = (uint8_t)((data8x8bit >> (i * 8)) & 0xFF);
	}
	return w1_calc_crc8(dat,8);
}

static void OneWire_searchRom(int pin) {
	uint64_t lastAddress = 0;
	int lastDiscrepancy = 0;
	int err = 0;
	int last_err;
	u8 crc;
	do {
		do {
			lastAddress = OneWire_searchNextAddress(pin, lastAddress, &lastDiscrepancy, &last_err);
			crc = OneWire_crcCheck(lastAddress);
			if(last_err) {
				err++;
			} else {
				if (crc == 0) {
					data_devices[count_device] = 0;
					devices[count_device++] = lastAddress;
					err = 0;
					printk(KERN_INFO "Pin: %d find 0x%llx\n",pin,lastAddress);
				} else {
					printk(KERN_INFO "Pin: %d error read ROM %d\n",pin,err);
					err++;
				}
			}
		} while (err>0 && err<MAX_ERR);
	} while (lastDiscrepancy != 0 && count_device < MAX_DEVICES && err<MAX_ERR);
}

static void OneWire_setDevice(int pin, uint64_t rom) {
	uint8_t i = 64;
	OneWire_reset(pin);
	OneWire_writeByte(pin,CMD_MATCHROM);
	while (i--) {
		OneWire_writeBit(pin, rom & 1);
		rom >>= 1;
	}
}

static uint32_t OneWire_getTemp(int pin, uint64_t ds18b20s) {
	int err = 0;
	uint8_t data[9];

	do {
		OneWire_setDevice(pin, ds18b20s);
		OneWire_writeByte(pin,CMD_CONVERTTEMP);

		msleep_interruptible(750);

		OneWire_setDevice(pin, ds18b20s);
		OneWire_writeByte(pin, CMD_RSCRATCHPAD);

		for (int i = 0; i < 9; i++) {
			data[i] = OneWire_readByte(pin);
		}
	} while ((w1_calc_crc8(data, 8) != data[8]) && (err<MAX_ERR));
	
	if(err>0) {
		printk(KERN_INFO "Pin: %d device %llx error read temperature %d\n",pin,ds18b20s,err);
	}
	
	if(err>=MAX_ERR) {
		return 0xFFFFFFFF;
	} else {
		return ((data[1] << 8) + data[0]) * 625;
	}
}

static void do_pin_command(uint32_t pin) {
	int i,i_pin;
	i_pin = count_pins;
	for(i=0;i<count_pins;i++) {
		if(pins[i]==pin) {
			i_pin = i;
			break;
		}
	}
	if(i_pin<count_pins) {
		printk(KERN_INFO "Pin: %d already init\n",pin);
		return;
	}
	if(count_pins>=NUM_PINS) {
		printk(KERN_INFO "Use maximum pins: %d\n",NUM_PINS);
		return;
	}
	count_pins++;
	pins[i_pin] = pin;
	pins_offset_devices[i_pin] = count_device;
	pins_count_devices[i_pin] = 0;

	sunxi_set_gpio_mode(pin, INPUT);
	OneWire_searchRom(pin);
	pins_count_devices[i_pin] = count_device-pins_offset_devices[i_pin];
}

static char* charn2str(char *data,int len,char *buf,int buf_len) {
	if(len>=0 && len<buf_len-1) {
		memcpy(buf, data, len);
		buf[len]=0x0;
		return buf;
	}
	return 0;
}

static void update_command(char *data,int len) {
	char buf[MAX_BUF_VALUE];
	uint32_t pin;
	if(charn2str(data,len,buf,sizeof(buf))) {
		if(sscanf(buf, "%d\n", &pin) == 1) {
			if(pin>=0 && pin<NUM_PINS) {
				printk(KERN_INFO "Add ds18b20 on: %d\n",pin);
				do_pin_command(pin);
			} else {
				printk("Bad num pins: %d\n",pin);
			}
		} else if(strcmp(buf,"CLEAR")==0) {
			printk(KERN_INFO "Clear all ds18b20\n");
			init_devices();
		} else {
			printk("Bad query format\n");
		}
	} else {
		printk("Bad query format\n");
	}
}

static void parse_and_update_command(struct private_data* const pdata) {
	int wr_complete = 0;
	char *p = pdata->wr_data, *start = p, *end = p + pdata->wr_len;
	while(p<end) {
		if(*p == 0x0A) {
			update_command(start,p-start);
			wr_complete += (p-start)+1;
			start = p+1;
		}
		p++;
	}
	if(wr_complete>0) {
		memcpy(pdata->wr_data, pdata->wr_data+wr_complete, pdata->wr_len-wr_complete);
		pdata->wr_len-=wr_complete;
	}
}

static void fill_get_result(struct private_data* const pdata) {
	int i,j;
	pdata->rd_len = 0;
	for(i=0;i<count_pins;i++) {
		for(j=pins_offset_devices[i];j<MAX_DEVICES && j<pins_offset_devices[i]+pins_count_devices[i];j++) {
			data_devices[j] = OneWire_getTemp(pins[i],devices[j]);
			pdata->rd_len += snprintf(
				pdata->rd_data+pdata->rd_len,
				sizeof(pdata->rd_data)-pdata->rd_len, 
				"%llx=%d\n", devices[j], data_devices[j]
			);
		}
	}
}

static int __init opi18b20_kernel_init(void) {
	int res;
	
	printk(KERN_INFO "Hello, opi18b20!\n");

	gpio = (uint32_t *)ioremap(SUNXI_PORT_BASE, SUNXI_GPIO_LEN);

	res = alloc_chrdev_region(&devno, 0, 1, OPI18B20_CDEVNAME);
	if (res < 0) {
		printk(KERN_WARNING "OPI18b20: Can't allocated device number\n");
		return res;
	}
	my_major = MAJOR(devno);
	cdev_init(&my_cdev, &fops);
	my_cdev.owner = THIS_MODULE;
	my_cdev.ops = &fops;
	res = cdev_add(&my_cdev, MKDEV(my_major, 0), 1);
	if (res) {
		printk(KERN_WARNING "OPI18b20: Error %d adding device\n", res);
		unregister_chrdev_region(devno, 1);
		return res;
	}
	
	init_devices();
	return 0; 
}

static void __exit opi18b20_kernel_exit(void) {

	cdev_del(&my_cdev);
	unregister_chrdev_region(devno, 1);
	
	iounmap(gpio);
	
	printk(KERN_INFO "Goodbye, opi18b20!\n");
}

// kmalloc the temporary data required for each user:
static int dev_open(struct inode *inod, struct file *fil) {
	fil->private_data = kmalloc(sizeof(struct private_data), GFP_KERNEL);
	if (0 == fil->private_data)
	{
		printk(KERN_WARNING "OPI18b20: Failed to allocate user data\n");
		return -ENOMEM;
	}
	memset(fil->private_data, 0, sizeof(struct private_data));
	return 0;
}

static ssize_t dev_read(struct file *filp, char *buf, size_t count, loff_t *f_pos) {
	ssize_t ret = 0;
	struct private_data* const pdata = filp->private_data;
	// Only proceed if we have private data, else return EOF.
	if (pdata) {
		if (0 == *f_pos) {
			fill_get_result(pdata);
		}
		if (*f_pos < pdata->rd_len) {
			if (count > pdata->rd_len - *f_pos)
				count = pdata->rd_len - *f_pos;
			if (copy_to_user(buf, pdata->rd_data + *f_pos, count))
				return -EFAULT;
			*f_pos += count;
			ret = count;
		}
	}
	return ret;
}

static ssize_t dev_write(struct file *filp,const char *buf,size_t count,loff_t *f_pos) {
	struct private_data* const pdata = filp->private_data;
	if (0 == pdata)
		return -EFAULT;
	if (count+pdata->wr_len > sizeof(pdata->wr_data) - 1)
		count = sizeof(pdata->wr_data) - pdata->wr_len;
	if (copy_from_user(pdata->wr_data+pdata->wr_len, buf, count))
		return -EFAULT;
	pdata->wr_len+= count;

	parse_and_update_command(pdata);

	return count;
}

static int dev_close(struct inode *inod,struct file *fil) {
	struct private_data* const pdata = fil->private_data;
	int ret = 0;
	if (pdata) {
		// Free process data.
		kfree(pdata);
	}

	return ret;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	return -EINVAL;
}

module_init(opi18b20_kernel_init);
module_exit(opi18b20_kernel_exit);

MODULE_DESCRIPTION("OPI18b20, DS18b20 Driver for the Orange Pi one");
MODULE_AUTHOR("Sergey Shkuliov <sergey.sckuliov@gmail.com>");
MODULE_LICENSE("GPL v2");

