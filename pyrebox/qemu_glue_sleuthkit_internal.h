/*-------------------------------------------------------------------------------

   Copyright (C) 2018 Cisco Talos Security Intelligence and Research Group

   PyREBox: Python scriptable Reverse Engineering Sandbox 
   Author: Xabier Ugarte-Pedrero 
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
   MA 02110-1301, USA.
   
-------------------------------------------------------------------------------*/

#ifndef QEMU_GLUE_SLEUTHKIT_INTERNAL_H
#define QEMU_GLUE_SLEUTHKIT_INTERNAL_H

#define MAX_DEVICES 64
/* PyREBox: This code was taken from DECAF: https://github.com/sycurelab/DECAF */
// This struct is used to store info about the disk images opened by qemu
// We use this to open the disk using Sleuthkit and read files from it
typedef struct {
  //BlockDriverState
  void *bs;
  TSK_IMG_INFO *img;
  TSK_VS_INFO* vs;
  const TSK_VS_PART_INFO* pi;
  TSK_FS_INFO *fs;
} disk_info_t;
 

// List of loaded disk images
// This could be more than MAX_DEVICES. We just assume MAX_DEVICES for now
extern disk_info_t disk_info_internal[MAX_DEVICES];

#endif
