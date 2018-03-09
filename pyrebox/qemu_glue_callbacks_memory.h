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

#ifndef QEMU_CALLBACKS_MEMORY_H
#define QEMU_CALLBACKS_MEMORY_H

#include "qemu_glue_callbacks_needed.h"

//In TCG code
void helper_qemu_mem_read_callback(CPUState* cpu, target_ulong vaddr, uintptr_t haddr, target_ulong size);

void helper_qemu_mem_write_callback(CPUState* cpu, target_ulong vaddr, uintptr_t haddr, target_ulong data, target_ulong size);

#endif
