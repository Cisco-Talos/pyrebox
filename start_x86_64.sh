#!/bin/bash

#This script is provided as an example of a possible QEMU / Pyrebox configuration
#for a Windows 7 SP 0 64 bit analysis target.

#It assumes that pyrebox.conf.Win7SP0x64 exists, and contains the list
#of scripts to be loaded on startup, as well as the configuration parameter
#that indicates Volatility the profile to apply.

#The QEMU parameters specified will start a VM with:
#   * 512 MiB of RAM
#   * Usb support
#   * A main hard-drive, provided as a qcow2 image as the first parameter for the script
#   * Starts a VNC server on 127.0.0.1 for showing the system display
#   * Redirects the QEMU monitor to stdio (only configuration supported currently)

if [ -z "$2" ]
then
    snapshot=""
else
    snapshot="-loadvm $2"
fi

cp pyrebox.conf.Win7SP0x64 pyrebox.conf
./pyrebox-x86_64 -monitor stdio -m 512 -usb -drive file=$1,index=0,media=disk,format=qcow2,cache=unsafe -vnc 127.0.0.1:0 ${snapshot} 
