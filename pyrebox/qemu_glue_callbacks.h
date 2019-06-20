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

#ifndef QEMU_GLUE_CALLBACKS_H
#define QEMU_GLUE_CALLBACKS_H

#include "qemu_glue_callbacks_needed.h"
#include "qemu_glue_callbacks_flush.h"
#include "qemu_glue_callbacks_target_independent.h"
#include "qemu_glue_callbacks_memory.h"

// Disables the keystroke callback
// every time we trigger it from the Python API
// to avoid mutual lock.
extern int keystroke_callback_disabled;

void disable_keystroke_callbacks(void);
void enable_keystroke_callbacks(void);

//At translation time
void helper_qemu_block_begin_callback(TranslationBlock* tb);

void helper_qemu_block_end_callback(TranslationBlock* next_tb, target_ulong from, target_ulong to);

void helper_qemu_insn_begin_callback(void);

void helper_qemu_insn_end_callback(void);

void helper_qemu_opcode_range_callback(target_ulong from, target_ulong to, uint32_t opcode, target_ulong insn_size);

void helper_qemu_trigger_cpu_loop_exit_if_needed(void);

//Emulation time
//Always needed
void notify_cpu_executing(CPUState* cpu);
//Always needed
void qemu_tlb_exec_callback(CPUState* cpu,target_ulong vaddr);

#endif
