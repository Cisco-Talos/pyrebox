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

#ifndef QEMU_CALLBACKS_NEEDED_H
#define QEMU_CALLBACKS_NEEDED_H

//Separated in order to allow including it in translate.c

int is_opcode_range_callback_needed(target_ulong start_opcode, target_ulong pgd);
int is_block_begin_callback_needed(target_ulong address,target_ulong pgd);
int is_insn_begin_callback_needed(target_ulong address,target_ulong pgd);
int is_block_end_callback_needed(target_ulong pgd);
int is_insn_end_callback_needed(target_ulong pgd);
int is_mem_read_callback_needed(target_ulong pgd);
int is_mem_write_callback_needed(target_ulong pgd);

#endif
