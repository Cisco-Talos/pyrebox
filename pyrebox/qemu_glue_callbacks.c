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

#include  <Python.h>

//QEMU dependencies
#include "qemu/queue.h"
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/option.h"
#include "migration/vmstate.h"
#include "qapi-types.h"
#include "sysemu/sysemu.h"
#include "monitor/monitor.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "pyrebox.h"
#include "qemu_glue.h"
#include "process_mgr.h"
#include "qemu_glue_callbacks.h"
#include "callbacks.h"

//This file should define the functions called by qemu hooks, 
//and redirect the calls to the corresponding callbacks 
//in callbacks.cpp

//callbacks is c++ code, making difficult to compile QEMU 
//if we include it in qemu headers, so we need 
//this proxy to compile it easily

target_ulong last_pgd = 0;

int flush_needed = 0;
int cpu_loop_exit_needed = 0;

void qemu_tlb_exec_callback(CPUState* cpu, target_ulong vaddr){
    //Transform parameters
    callback_params_t params;
    params.tlb_exec_params.cpu = (qemu_cpu_opaque_t) cpu;
    params.tlb_exec_params.vaddr = (pyrebox_target_ulong) vaddr;
    //Call pyrebox callback
    tlb_exec_callback(params); 
    if (is_cpu_loop_exit_needed()) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

void notify_cpu_executing(CPUState* cpu){
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
    target_ulong cur_pgd = (target_ulong)env->cr[3];
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    //If there was a context change
    if(cur_pgd != last_pgd){
        //Notify context change
        callback_params_t params;
        params.vmi_context_change_params.old_pgd = last_pgd;
        params.vmi_context_change_params.new_pgd = cur_pgd;
        context_change_callback(params);
        last_pgd = cur_pgd;
    }
}

void helper_qemu_block_begin_callback(CPUState* cpu,TranslationBlock* tb){
    callback_params_t params;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
    params.block_begin_params.cpu_index = get_qemu_cpu_index_with_pgd((target_ulong)env->cr[3]);
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    params.block_begin_params.tb = (qemu_tb_opaque_t) tb;
    params.block_begin_params.cpu = (qemu_cpu_opaque_t) cpu;
    block_begin_callback(params);
    if (is_cpu_loop_exit_needed()) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}
void helper_qemu_block_end_callback(CPUState* cpu,TranslationBlock* tb, target_ulong from, target_ulong to){
    callback_params_t params;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
    params.block_end_params.cpu_index = get_qemu_cpu_index_with_pgd((target_ulong)env->cr[3]);
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    params.block_end_params.tb = (qemu_tb_opaque_t) tb;
    params.block_end_params.cpu = (qemu_cpu_opaque_t) cpu;
    params.block_end_params.cur_pc = from;
    params.block_end_params.next_pc = to;
    block_end_callback(params);
    if (is_cpu_loop_exit_needed()) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

void helper_qemu_insn_begin_callback(CPUState* cpu){
    callback_params_t params;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
    params.insn_begin_params.cpu_index = get_qemu_cpu_index_with_pgd((target_ulong)env->cr[3]);
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    params.insn_begin_params.cpu = (qemu_cpu_opaque_t) cpu;
    insn_begin_callback(params);
    if (is_cpu_loop_exit_needed()) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

void helper_qemu_insn_end_callback(CPUState* cpu){
    callback_params_t params;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
    params.insn_end_params.cpu_index = get_qemu_cpu_index_with_pgd((target_ulong)env->cr[3]);
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    params.insn_end_params.cpu = (qemu_cpu_opaque_t) cpu;
    insn_end_callback(params);
    if (is_cpu_loop_exit_needed()) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

void helper_qemu_opcode_range_callback(CPUState* cpu, target_ulong from, target_ulong to, uint32_t opcode){
    callback_params_t params;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
    params.opcode_range_params.cpu_index = get_qemu_cpu_index_with_pgd((target_ulong)env->cr[3]);
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    params.opcode_range_params.cpu = (qemu_cpu_opaque_t) cpu; 
    params.opcode_range_params.cur_pc = from;
    params.opcode_range_params.next_pc = to;
    params.opcode_range_params.opcode = opcode;

    opcode_range_callback(params);
    if (is_cpu_loop_exit_needed()) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

void helper_qemu_mem_read_callback(CPUState* cpu, target_ulong vaddr, uintptr_t haddr, target_ulong size){
    callback_params_t params;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
    params.mem_read_params.cpu_index = get_qemu_cpu_index_with_pgd((target_ulong)env->cr[3]);
    params.mem_read_params.cpu = (qemu_cpu_opaque_t) cpu;
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    params.mem_read_params.vaddr = vaddr;
    params.mem_read_params.haddr = haddr;
    params.mem_read_params.size = size;
    mem_read_callback(params);
    if (is_cpu_loop_exit_needed()) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

void helper_qemu_mem_write_callback(CPUState* cpu, target_ulong vaddr, uintptr_t haddr, target_ulong data, target_ulong size){
    callback_params_t params;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
    params.mem_write_params.cpu_index = get_qemu_cpu_index_with_pgd((target_ulong)env->cr[3]);
    params.mem_write_params.cpu = (qemu_cpu_opaque_t) cpu;
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    params.mem_write_params.vaddr = vaddr;
    params.mem_write_params.haddr = haddr;
    params.mem_write_params.size = size;
    params.mem_write_params.data = data;

    mem_write_callback(params);
    if (is_cpu_loop_exit_needed()) {
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

void qemu_keystroke_callback(unsigned int keycode){
    callback_params_t params;
    params.keystroke_params.keycode = keycode;
    keystroke_callback(params);
    if (is_cpu_loop_exit_needed()) {
        current_cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(current_cpu);
    }
}

void qemu_nic_rec_callback(unsigned char* buf, uint64_t size, uint64_t cur_pos, uint64_t start, uint64_t stop) {
    callback_params_t params;
    params.nic_rec_params.buf = buf;
    params.nic_rec_params.size = size;
    params.nic_rec_params.cur_pos = cur_pos;
    params.nic_rec_params.start = start;
    params.nic_rec_params.stop = stop;
    nic_rec_callback(params);
    if (is_cpu_loop_exit_needed()) {
        current_cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(current_cpu);
    }
}

void qemu_nic_send_callback(unsigned char* buf, uint64_t size, uint64_t address){
    callback_params_t params;
    params.nic_send_params.buf = buf;
    params.nic_send_params.size = size;
    params.nic_send_params.address = address;
    nic_send_callback(params);
    if (is_cpu_loop_exit_needed()) {
        current_cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(current_cpu);
    }
}

int is_opcode_range_callback_needed(target_ulong start_opcode, target_ulong pgd){
    return is_callback_needed(OPCODE_RANGE_CB, start_opcode, pgd);
}

int is_block_begin_callback_needed(target_ulong address,target_ulong pgd){
    return is_callback_needed(BLOCK_BEGIN_CB, address ,pgd);
}
int is_insn_begin_callback_needed(target_ulong address,target_ulong pgd){
    return is_callback_needed(INSN_BEGIN_CB, address ,pgd);
}

int is_block_end_callback_needed(target_ulong pgd){
    return is_callback_needed(BLOCK_END_CB, (pyrebox_target_ulong) INV_ADDR,pgd);
}

int is_insn_end_callback_needed(target_ulong pgd){
    return is_callback_needed(INSN_END_CB, (pyrebox_target_ulong) INV_ADDR,pgd);
}

int is_mem_read_callback_needed(target_ulong pgd){
    return is_callback_needed(MEM_READ_CB, (pyrebox_target_ulong) INV_ADDR,pgd);
}

int is_mem_write_callback_needed(target_ulong pgd){
    return is_callback_needed(MEM_WRITE_CB, (pyrebox_target_ulong) INV_ADDR,pgd);
}

int is_keystroke_callback_needed(void){
    return is_callback_needed(KEYSTROKE_CB, (pyrebox_target_ulong) INV_ADDR, (pyrebox_target_ulong) INV_PGD);
}

int is_nic_rec_callback_needed(void){
    return is_callback_needed(NIC_REC_CB, (pyrebox_target_ulong) INV_ADDR, (pyrebox_target_ulong) INV_PGD);
}

int is_nic_send_callback_needed(void){
    return is_callback_needed(NIC_SEND_CB, (pyrebox_target_ulong) INV_ADDR, (pyrebox_target_ulong) INV_PGD);
}

int is_tb_flush_needed(void){
    if (flush_needed > 0){
        flush_needed = 0;
        return 1;
    }
    return 0; 
}

void pyrebox_flush_tb(void){
    flush_needed = 1;    
}

int is_cpu_loop_exit_needed(void){
    if (cpu_loop_exit_needed) {
        cpu_loop_exit_needed = 0;
        return 1;
    }
    return 0;
}

void pyrebox_cpu_loop_exit(void) {
    cpu_loop_exit_needed = 1;
}
