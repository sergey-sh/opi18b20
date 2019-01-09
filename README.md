# opi18b20
Kernel module for orange pi one. Read unlimited ds18b20 on unlimited pins.

Tested and developed for SoC Orange PI One. Uses linux 3.4.113+.

It will probably work on all platforms using CPU Allwinner H3.

I tested the use Pin 200.

Example for use from bash: 

```bash
echo "200">/dev/opi18b20
cat /dev/opi18b20

````

Out:
```bash
f10315927a06ff28=173750
eb0117b32f01ff28=172500
b60315926bc3ff28=178750

````


