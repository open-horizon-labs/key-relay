#!/bin/sh
# Configures the Raspberry Pi's USB port as a FIDO HID device (CTAPHID, 64-byte reports).
# Run as root at boot, after 'dtoverlay=dwc2' is in /boot/firmware/config.txt.
# USB IDs: pid.codes 0x1209:0x0001 is a test PID, for testing only (contract decision D3).
set -eu
modprobe libcomposite
G=/sys/kernel/config/usb_gadget/keyrelay
if [ -d "$G" ]; then exit 0; fi
mkdir -p "$G"
cd "$G"
echo 0x1209 > idVendor
echo 0x0001 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB
mkdir -p strings/0x409
echo "KeyRelay" > strings/0x409/manufacturer
echo "KeyRelay receiver (test)" > strings/0x409/product
mkdir -p functions/hid.usb0
echo 0 > functions/hid.usb0/protocol
echo 0 > functions/hid.usb0/subclass
echo 64 > functions/hid.usb0/report_length
# FIDO report descriptor from the CTAP specification: usage page 0xF1D0, usage 0x01,
# 64-byte input report (usage 0x20) and 64-byte output report (usage 0x21).
printf '\006\320\361\011\001\241\001\011\040\025\000\046\377\000\165\010\225\100\201\002\011\041\025\000\046\377\000\165\010\225\100\221\002\300' > functions/hid.usb0/report_desc
mkdir -p configs/c.1/strings/0x409
echo "FIDO" > configs/c.1/strings/0x409/configuration
echo 100 > configs/c.1/MaxPower
ln -s functions/hid.usb0 configs/c.1/
ls /sys/class/udc | head -n 1 > UDC
