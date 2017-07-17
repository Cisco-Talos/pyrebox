/*-------------------------------------------------------------------------------

   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group

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

#ifndef QEMU_CALLBACKS_TARGET_INDEPENDENT_H
#define QEMU_CALLBACKS_TARGET_INDEPENDENT_H

int is_keystroke_callback_needed(void);
int is_nic_rec_callback_needed(void);
int is_nic_send_callback_needed(void);

//In device emulation code
void qemu_keystroke_callback(unsigned int keycode);
//Assume 64 bits for these target independent parameters
void qemu_nic_rec_callback(unsigned char* buf, uint64_t size, uint64_t cur_pos, uint64_t start, uint64_t stop);
void qemu_nic_send_callback(unsigned char* buf, uint64_t size, uint64_t address);

#endif
