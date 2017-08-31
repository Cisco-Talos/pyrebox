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

#ifndef QEMU_GLUE_H
#define QEMU_GLUE_H

#include "config-target.h"

#if defined(TARGET_X86_64)
#define TARGET_LONG_BITS 64
#define PYREBOX_CPU_NB_REGS 16 
#define PYTHON_TARGET_ULONG Q
#elif defined(TARGET_I386) && !defined(TARGET_X86_64)
#define TARGET_LONG_BITS 32
#define PYREBOX_CPU_NB_REGS 8
#define PYTHON_TARGET_ULONG I
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif

#ifndef TARGET_LONG_BITS
#error TARGET_LONG_BITS must be defined before including this header
#endif

#define TARGET_LONG_SIZE (TARGET_LONG_BITS / 8)
#if TARGET_LONG_SIZE == 4
typedef int32_t pyrebox_target_long;
typedef uint32_t pyrebox_target_ulong;
#elif TARGET_LONG_SIZE == 8
typedef int64_t pyrebox_target_long;
typedef uint64_t pyrebox_target_ulong;
#else
#error TARGET_LONG_SIZE undefined
#endif


//XXX: THIS HEADER MUST NOT CONTAIN ANY REFERECE TO QEMU HEADERS. FUNCTIONS MUST USE
//     OPAQUES FOR REFERENCING QEMU CPU AND QEMU TB (TRANSLATION BLOCK), SO THAT
//     THE INTERACTION WITH QEMU IS TOTALLY TRANSPARENT TO THE REST OF THE CODE
//     IN PYREBOX, THAT WILL USE THIS HEADER TO INTERFACE WITH QEMU.

//String to store the target platform
extern const char* target_platform;

#if defined(TARGET_I386) || defined(TARGET_X86_64)
typedef enum {
    RT_REGULAR = 0,
    RT_SEGMENT,
} register_type_t;
#endif

//XXX: Update qemu_glue.c and python enumerations whenever you introuce any change to these enumerations
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
typedef enum {
    RN_EAX = 0,
    RN_ECX,
    RN_EDX,
    RN_EBX,
    RN_ESP,
    RN_EBP,
    RN_ESI,
    RN_EDI,
    RN_EIP,
    RN_EFLAGS,
    RN_ES,
    RN_CS, 
    RN_SS,    
    RN_DS,    
    RN_FS,    
    RN_GS,    
    RN_LDT,
    RN_TR,
    RN_GDT,
    RN_IDT,
    RN_CR0,
    RN_CR1,
    RN_CR2,
    RN_CR3,
    RN_CR4,
    RN_CPU_INDEX,
    RN_LAST,
} register_num_t;
#elif defined(TARGET_X86_64)
typedef enum {
    RN_RAX = 0,
    RN_RCX,
    RN_RDX,
    RN_RBX,
    RN_RSP,
    RN_RBP,
    RN_RSI,
    RN_RDI,
    RN_RIP,
    RN_RFLAGS,
    RN_ES,
    RN_CS, 
    RN_SS,    
    RN_DS,    
    RN_FS,    
    RN_GS,    
    RN_LDT,
    RN_TR,
    RN_GDT,
    RN_IDT,
    RN_CR0,
    RN_CR1,
    RN_CR2,
    RN_CR3,
    RN_CR4,
    RN_CPU_INDEX,
    RN_R8,
    RN_R9,
    RN_R10,
    RN_R11,
    RN_R12,
    RN_R13,
    RN_R14,
    RN_R15,
    RN_LAST,
} register_num_t;
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif


#if defined(TARGET_I386) || defined(TARGET_X86_64)
extern register_type_t register_type[RN_LAST];
#endif

//Definition for QEMU structure opaques
typedef void* qemu_cpu_opaque_t;
typedef void* qemu_tb_opaque_t;

/**************************************************** PYTHON FUNCTIONS ************************************************/

//These methods convert some complex QEMU types to python tuples that can be easily used in 
//python callback functions. This NEW objects must be decrefed once we return back from the
//python funtion called with Py_Callobject so that the GC can delete them from memory.
PyObject* get_cpu_state(qemu_cpu_opaque_t cpu_opaque);
PyObject* get_tb(qemu_tb_opaque_t tb_opaque);

/************************************************** MEM/REG RW FUNCTIONS **********************************************/

//Functions for reading registers from QEMU CPU
int read_register_convert(qemu_cpu_opaque_t cpu_opaque, register_num_t reg_num, pyrebox_target_ulong* out_val);
//Functions for writing registers into QEMU CPU
int write_register_convert(qemu_cpu_opaque_t cpu_opaque, register_num_t reg_num,pyrebox_target_ulong val);
#if defined(TARGET_I386) || defined(TARGET_X86_64)
int write_selector_register_convert(qemu_cpu_opaque_t cpu_opaque, register_num_t reg_num, uint32_t selector, pyrebox_target_ulong base, uint32_t limit, uint32_t flags);
#endif

//Memory read/write functions
int qemu_physical_memory_rw(pyrebox_target_ulong addr, uint8_t *buf, pyrebox_target_ulong len, int is_write);
int qemu_virtual_memory_rw(qemu_cpu_opaque_t *cpu_opaque, pyrebox_target_ulong addr,
                        uint8_t *buf, pyrebox_target_ulong len, int is_write);
int qemu_virtual_memory_rw_with_pgd(pyrebox_target_ulong pgd, pyrebox_target_ulong addr,
                        uint8_t *buf, pyrebox_target_ulong len, int is_write);
pyrebox_target_ulong qemu_virtual_to_physical_with_pgd(pyrebox_target_ulong pgd, pyrebox_target_ulong addr);

uint32_t qemu_ioport_read(uint16_t address, uint8_t size);
void qemu_ioport_write(uint16_t address, uint8_t size, uint32_t value);

/******************************************* CPU/TB DATA EXTRAcTION **********************************************/

//Functions for retrieving QEMU CPU OPAQUE
qemu_cpu_opaque_t get_qemu_cpu(int cpu_index);
qemu_cpu_opaque_t get_qemu_cpu_with_pgd(pyrebox_target_ulong pgd);

//Functions to extract useful values from opaques (CPU and TB)
pyrebox_target_ulong get_pgd(qemu_cpu_opaque_t cpu_opaque);
pyrebox_target_ulong get_cpu_addr(qemu_cpu_opaque_t cpu_opaque);
pyrebox_target_ulong get_tb_addr(qemu_tb_opaque_t tb_opaque);
pyrebox_target_ulong get_tb_size(qemu_tb_opaque_t tb_opaque);
pyrebox_target_ulong get_stack_pointer(qemu_tb_opaque_t tb_opaque);
#if defined(TARGET_I386) || defined(TARGET_X86_64)
pyrebox_target_ulong get_gs_base(qemu_cpu_opaque_t cpu_opaque);
pyrebox_target_ulong get_fs_base(qemu_cpu_opaque_t cpu_opaque);
int get_qemu_cpu_protected_mode(qemu_cpu_opaque_t cpu_opaque);
int qemu_is_kernel_running(int cpu_index);
#endif

//CPU Query functions
int get_qemu_cpu_index_with_pgd(pyrebox_target_ulong pgd);
pyrebox_target_ulong get_running_process(int cpu_index);
int get_num_cpus(void);

/************************************************** UTILITY FUNCTIONS **********************************************/

//Save - load VM
void pyrebox_save_vm(char* name);
void pyrebox_load_vm(char* name);

//Interface for volatility
uint64_t connection_write_memory(uint64_t user_paddr, void *buf, uint64_t user_len);
uint64_t connection_read_memory(uint64_t user_paddr, char *buf, uint64_t user_len);
uint64_t get_memory_size(void);

#endif
