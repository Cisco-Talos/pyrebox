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

#include <Python.h>
#include <limits.h>

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
#include "exec/cpu-common.h"
#include "exec/memory.h"
#include "exec/hwaddr.h"
#include "exec/ram_addr.h"
#include "qemu/main-loop.h"
#include "monitor/monitor.h"
#include "qemu/thread.h"
#include "exec/ioport.h"
#include "hmp.h"

#include "qemu_glue.h"
#include "qemu_glue_callbacks_flush.h"

/**************************************************** DEFINITIONS ************************************************/

#if defined(TARGET_X86_64)
const char* target_platform = "x86_64-softmmu";
#elif defined(TARGET_I386) && !defined(TARGET_X86_64)
const char* target_platform = "i386-softmmu";
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
//const char* platform = "aarch64-softmmu";
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
//const char* platform = "arm-softmmu";
#endif

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
register_type_t register_type[RN_LAST] = 
{
    RT_REGULAR,   //RN_EAX = 0,
    RT_REGULAR,   //RN_ECX,
    RT_REGULAR,   //RN_EDX,
    RT_REGULAR,   //RN_EBX,
    RT_REGULAR,   //RN_ESP,
    RT_REGULAR,   //RN_EBP,
    RT_REGULAR,   //RN_ESI,
    RT_REGULAR,   //RN_EDI,
    RT_REGULAR,   //RN_EIP,
    RT_REGULAR,   //RN_EFLAGS,
    RT_SEGMENT,   //RN_ES,
    RT_SEGMENT,   //RN_CS, 
    RT_SEGMENT,   //RN_SS,    
    RT_SEGMENT,   //RN_DS,    
    RT_SEGMENT,   //RN_FS,    
    RT_SEGMENT,   //RN_GS,    
    RT_SEGMENT,   //RN_LDT,
    RT_SEGMENT,   //RN_TR,
    RT_SEGMENT,   //RN_LDT,
    RT_SEGMENT,   //RN_IDT,
    RT_REGULAR,   //RN_CR0,
    RT_REGULAR,   //RN_CR1,
    RT_REGULAR,   //RN_CR2,
    RT_REGULAR,   //RN_CR3,
    RT_REGULAR,   //RN_CR4.
    RT_REGULAR    //RN_CPU_INDEX.
};
#elif defined(TARGET_X86_64)
register_type_t register_type[RN_LAST] = 
{
    RT_REGULAR,   //RN_EAX = 0,
    RT_REGULAR,   //RN_ECX,
    RT_REGULAR,   //RN_EDX,
    RT_REGULAR,   //RN_EBX,
    RT_REGULAR,   //RN_ESP,
    RT_REGULAR,   //RN_EBP,
    RT_REGULAR,   //RN_ESI,
    RT_REGULAR,   //RN_EDI,
    RT_REGULAR,   //RN_EIP,
    RT_REGULAR,   //RN_EFLAGS,
    RT_SEGMENT,   //RN_ES,
    RT_SEGMENT,   //RN_CS, 
    RT_SEGMENT,   //RN_SS,    
    RT_SEGMENT,   //RN_DS,    
    RT_SEGMENT,   //RN_FS,    
    RT_SEGMENT,   //RN_GS,    
    RT_SEGMENT,   //RN_LDT,
    RT_SEGMENT,   //RN_TR,
    RT_SEGMENT,   //RN_LDT,
    RT_SEGMENT,   //RN_IDT,
    RT_REGULAR,   //RN_CR0,
    RT_REGULAR,   //RN_CR1,
    RT_REGULAR,   //RN_CR2,
    RT_REGULAR,   //RN_CR3,
    RT_REGULAR,   //RN_CR4.
    RT_REGULAR,    //RN_CPU_INDEX.
    RT_REGULAR,   //RN_R8,
    RT_REGULAR,   //RN_R9,
    RT_REGULAR,   //RN_R10,
    RT_REGULAR,   //RN_R11,
    RT_REGULAR,   //RN_R12,
    RT_REGULAR,   //RN_R13,
    RT_REGULAR,   //RN_R14,
    RT_REGULAR   //RN_R15,
};

#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif

/**************************************************** PYTHON FUNCTIONS ************************************************/

PyObject* get_cpu_state(qemu_cpu_opaque_t cpu_opaque){
    //N denotes object type. It passes an object untouched, and it doesnt increment its reference count like O, 
    //so that the call to XDECREF of the whole tuple will already trigger the deallocation of all the values.
    PyObject* result = 0;
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    PyObject* args = Py_BuildValue("((I,I,I,I,I,I,I,I, I,I, N,N,N,N,N,N,N,N,N,N, I,I,I,I,I,i))",
                            env->regs[R_EAX],
                            env->regs[R_ECX],
                            env->regs[R_EDX],
                            env->regs[R_EBX],
                            env->regs[R_ESP],
                            env->regs[R_EBP],
                            env->regs[R_ESI],
                            env->regs[R_EDI],
                            env->eip, 
                            env->eflags,
                            Py_BuildValue("(I,I,I,I)", env->segs[R_ES].selector,env->segs[R_ES].base,env->segs[R_ES].limit,env->segs[R_ES].flags),
                            Py_BuildValue("(I,I,I,I)", env->segs[R_CS].selector,env->segs[R_CS].base,env->segs[R_CS].limit,env->segs[R_CS].flags),
                            Py_BuildValue("(I,I,I,I)", env->segs[R_SS].selector,env->segs[R_SS].base,env->segs[R_SS].limit,env->segs[R_SS].flags),
                            Py_BuildValue("(I,I,I,I)", env->segs[R_DS].selector,env->segs[R_DS].base,env->segs[R_DS].limit,env->segs[R_DS].flags),
                            Py_BuildValue("(I,I,I,I)", env->segs[R_FS].selector,env->segs[R_FS].base,env->segs[R_FS].limit,env->segs[R_FS].flags),
                            Py_BuildValue("(I,I,I,I)", env->segs[R_GS].selector,env->segs[R_GS].base,env->segs[R_GS].limit,env->segs[R_GS].flags),
                            Py_BuildValue("(I,I,I,I)", env->ldt.selector,env->ldt.base,env->ldt.limit,env->ldt.flags),
                            Py_BuildValue("(I,I,I,I)", env->tr.selector,env->tr.base,env->tr.limit,env->tr.flags),
                            Py_BuildValue("(I,I,I,I)", env->gdt.selector,env->gdt.base,env->gdt.limit,env->gdt.flags),
                            Py_BuildValue("(I,I,I,I)", env->idt.selector,env->idt.base,env->idt.limit,env->idt.flags),
                            env->cr[0],
                            env->cr[1],
                            env->cr[2],
                            env->cr[3],
                            env->cr[4],
                            get_qemu_cpu_index_with_pgd(env->cr[3]));

    PyObject* py_module_name = PyString_FromString("api_internal");
    PyObject* py_module = PyImport_Import(py_module_name);
    Py_DECREF(py_module_name);
    if(py_module != NULL){
        PyObject* py_convert_cpu= PyObject_GetAttrString(py_module,"convert_x86_cpu");
        if (py_convert_cpu){
            if (PyCallable_Check(py_convert_cpu)){
                 result =  PyObject_CallObject(py_convert_cpu,args);
                 Py_DECREF(args);
            }
        }
    }
#elif defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    PyObject* args = Py_BuildValue("((K,K,K,K,K,K,K,K, K,K, N,N,N,N,N,N,N,N,N,N, K,K,K,K,K,i,K,K,K,K,K,K,K,K))",
                            env->regs[R_EAX],
                            env->regs[R_ECX],
                            env->regs[R_EDX],
                            env->regs[R_EBX],
                            env->regs[R_ESP],
                            env->regs[R_EBP],
                            env->regs[R_ESI],
                            env->regs[R_EDI],
                            env->eip, 
                            env->eflags,
                            Py_BuildValue("(I,K,I,I)", env->segs[R_ES].selector,env->segs[R_ES].base,env->segs[R_ES].limit,env->segs[R_ES].flags),
                            Py_BuildValue("(I,K,I,I)", env->segs[R_CS].selector,env->segs[R_CS].base,env->segs[R_CS].limit,env->segs[R_CS].flags),
                            Py_BuildValue("(I,K,I,I)", env->segs[R_SS].selector,env->segs[R_SS].base,env->segs[R_SS].limit,env->segs[R_SS].flags),
                            Py_BuildValue("(I,K,I,I)", env->segs[R_DS].selector,env->segs[R_DS].base,env->segs[R_DS].limit,env->segs[R_DS].flags),
                            Py_BuildValue("(I,K,I,I)", env->segs[R_FS].selector,env->segs[R_FS].base,env->segs[R_FS].limit,env->segs[R_FS].flags),
                            Py_BuildValue("(I,K,I,I)", env->segs[R_GS].selector,env->segs[R_GS].base,env->segs[R_GS].limit,env->segs[R_GS].flags),
                            Py_BuildValue("(I,K,I,I)", env->ldt.selector,env->ldt.base,env->ldt.limit,env->ldt.flags),
                            Py_BuildValue("(I,K,I,I)", env->tr.selector,env->tr.base,env->tr.limit,env->tr.flags),
                            Py_BuildValue("(I,K,I,I)", env->gdt.selector,env->gdt.base,env->gdt.limit,env->gdt.flags),
                            Py_BuildValue("(I,K,I,I)", env->idt.selector,env->idt.base,env->idt.limit,env->idt.flags),
                            env->cr[0],
                            env->cr[1],
                            env->cr[2],
                            env->cr[3],
                            env->cr[4],
                            get_qemu_cpu_index_with_pgd(env->cr[3]),
                            env->regs[8],
                            env->regs[9],
                            env->regs[10],
                            env->regs[11],
                            env->regs[12],
                            env->regs[13],
                            env->regs[14],
                            env->regs[15]);

    PyObject* py_module_name = PyString_FromString("api_internal");
    PyObject* py_module = PyImport_Import(py_module_name);
    Py_DECREF(py_module_name);
    if(py_module != NULL){
        PyObject* py_convert_cpu= PyObject_GetAttrString(py_module,"convert_x64_cpu");
        if (py_convert_cpu){
            if (PyCallable_Check(py_convert_cpu)){
                 result =  PyObject_CallObject(py_convert_cpu,args);
                 Py_DECREF(args);
            }
        }
    }

#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    return result;
}

PyObject* get_tb(qemu_tb_opaque_t tb_opaque){
#if TARGET_LONG_SIZE == 4
    TranslationBlock* tb = (TranslationBlock*)tb_opaque;
    return Py_BuildValue("(I,I,I)", tb->pc, tb->size, tb->icount);
#elif TARGET_LONG_SIZE == 8
    TranslationBlock* tb = (TranslationBlock*)tb_opaque;
    return Py_BuildValue("(K,I,I)", tb->pc, tb->size, tb->icount);
#else
#error TARGET_LONG_SIZE undefined
#endif
}

/************************************************** MEM/REG RW FUNCTIONS **********************************************/

//Wrap call to qemu function
int qemu_physical_memory_rw(target_ulong addr, uint8_t *buf, pyrebox_target_ulong len, int is_write){
    //Detect int overflow in length
    assert(len <= INT_MAX);
    cpu_physical_memory_rw(addr,buf,len,is_write);
    return 0;
}
//Read virtual memory address given a cpu_opaque with its PGD
int qemu_virtual_memory_rw(qemu_cpu_opaque_t *cpu_opaque, pyrebox_target_ulong addr,
                        uint8_t *buf, pyrebox_target_ulong len, int is_write){

    CPUState* cpu = (CPUState*)cpu_opaque;
    return cpu_memory_rw_debug(cpu,addr,buf,len,is_write);
}

int qemu_virtual_memory_rw_with_pgd(pyrebox_target_ulong pgd, pyrebox_target_ulong addr,
                        uint8_t *buf, pyrebox_target_ulong len, int is_write){
    int result = 0;
    //First try to do it using the running CPU with the corresponding pgd
    qemu_cpu_opaque_t running_cpu = get_qemu_cpu_with_pgd(pgd);
    if (running_cpu != NULL){
        result = qemu_virtual_memory_rw(running_cpu,addr,buf,len,is_write);
    }
    else{//If it didnt work, we force the pgd 
        CPUState* cpu = first_cpu;
        assert(first_cpu != NULL);
#if defined(TARGET_I386) || defined(TARGET_X86_64)
        CPUX86State* env = &(X86_CPU(cpu)->env);
        pyrebox_target_ulong old_pgd = env->cr[3];
        env->cr[3] = pgd;
        result = qemu_virtual_memory_rw((qemu_cpu_opaque_t)cpu,addr,buf,len,is_write);
        env->cr[3] = old_pgd;
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    }
    return result;
}
pyrebox_target_ulong qemu_virtual_to_physical_with_pgd(pyrebox_target_ulong pgd, pyrebox_target_ulong addr){
    qemu_cpu_opaque_t running_cpu = get_qemu_cpu_with_pgd(pgd);
    pyrebox_target_ulong page,phys_addr;
    MemTxAttrs attrs;
    if (running_cpu != NULL){
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_attrs_debug(running_cpu, page, &attrs);
        /* if no physical page mapped, return an error */
        if (phys_addr == -1)
          return -1;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        return (pyrebox_target_ulong)phys_addr; 
    }
    else{//If it didnt work, we force the cr[3]
        CPUState* cpu = first_cpu;
        assert(first_cpu != NULL);
#if defined(TARGET_I386) || defined(TARGET_X86_64)
        CPUX86State* env = &(X86_CPU(cpu)->env);
        pyrebox_target_ulong old_pgd = env->cr[3];
        env->cr[3] = pgd;
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, page, &attrs);
        env->cr[3] = old_pgd;
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
        /* if no physical page mapped, return an error */
        if (phys_addr == -1)
          return -1;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        return (pyrebox_target_ulong)phys_addr; 
    }
}

uint32_t qemu_ioport_read(uint16_t address, uint8_t size){
    //If the size parameter is incorrect, force it to be 1.
    if (size != 1 && size != 2 && size != 4){
        size = 1;
    }
    uint32_t val = 0;
    
    switch(size) {
    default:
    case 1:
        val = cpu_inb(address);
        break;
    case 2:
        val = cpu_inw(address);
        break;
    case 4:
        val = cpu_inl(address);
        break;
    }
    return val;
}

void qemu_ioport_write(uint16_t address, uint8_t size, uint32_t value){

    //If the size parameter is incorrect, force it to be 1.
    if (size != 1 && size != 2 && size != 4){
        size = 1;
    }

    switch (size) {
    default:
    case 1:
        cpu_outb(address, value);
        break;
    case 2:
        cpu_outw(address, value);
        break;
    case 4:
        cpu_outl(address, value);
        break;
    }
}

int read_register_convert(qemu_cpu_opaque_t cpu_opaque, register_num_t reg_num, pyrebox_target_ulong* out_val){
    assert(out_val != 0);
    *out_val = 0;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    if (reg_num < RN_LAST && register_type[reg_num] == RT_REGULAR)
    {
       switch(reg_num){
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
           case RN_EAX:
                *out_val = env->regs[R_EAX];
                break;
           case RN_ECX:
                *out_val = env->regs[R_ECX];
                break;
           case RN_EDX:
                *out_val = env->regs[R_EDX];
                break;
           case RN_EBX:
                *out_val = env->regs[R_EBX];
                break;
           case RN_ESP:
                *out_val = env->regs[R_ESP];
                break;
           case RN_EBP:
                *out_val = env->regs[R_EBP];
                break;
           case RN_ESI:
                *out_val = env->regs[R_ESI];
                break;
           case RN_EDI:
                *out_val = env->regs[R_EDI];
                break;
           case RN_EIP:
                *out_val = env->eip;
                break;
           case RN_EFLAGS:
                *out_val = env->eflags;
                break;
#elif defined(TARGET_X86_64)
           case RN_RAX:
                *out_val = env->regs[R_EAX];
                break;
           case RN_RCX:
                *out_val = env->regs[R_ECX];
                break;
           case RN_RDX:
                *out_val = env->regs[R_EDX];
                break;
           case RN_RBX:
                *out_val = env->regs[R_EBX];
                break;
           case RN_RSP:
                *out_val = env->regs[R_ESP];
                break;
           case RN_RBP:
                *out_val = env->regs[R_EBP];
                break;
           case RN_RSI:
                *out_val = env->regs[R_ESI];
                break;
           case RN_RDI:
                *out_val = env->regs[R_EDI];
                break;
           case RN_RIP:
                *out_val = env->eip;
                break;
           case RN_RFLAGS:
                *out_val = env->eflags;
                break;

#endif
#if defined(TARGET_I386) || defined(TARGET_X86_64)

           case RN_CR0:
                *out_val = env->cr[0];
                break;
           case RN_CR1:
                *out_val = env->cr[1];
                break;
           case RN_CR2:
                *out_val = env->cr[2];
                break;
           case RN_CR3:
                *out_val = env->cr[3];
                break;
           case RN_CR4:
                *out_val = env->cr[4];
                break;
#endif
#if defined(TARGET_X86_64)
           case RN_R8:
                *out_val = env->regs[8];
                break;
           case RN_R9:
                *out_val = env->regs[9];
                break;
           case RN_R10:
                *out_val = env->regs[10];
                break;
           case RN_R11:
                *out_val = env->regs[11];
                break;
           case RN_R12:
                *out_val = env->regs[12];
                break;
           case RN_R13:
                *out_val = env->regs[13];
                break;
           case RN_R14:
                *out_val = env->regs[14];
                break;
           case RN_R15:
                *out_val = env->regs[15];
                break;
#endif
           default:
                return 0;
                break;
       }
       return 0;
    }
    return 1;
}

int write_register_convert(qemu_cpu_opaque_t cpu_opaque, register_num_t reg_num,pyrebox_target_ulong val){
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    int changed = 0;
    if (reg_num < RN_LAST && register_type[reg_num] == RT_REGULAR)
    {
       switch(reg_num){
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
           case RN_EAX:
                env->regs[R_EAX] = val;
                break;
           case RN_ECX:
                env->regs[R_ECX] = val;
                break;
           case RN_EDX:
                env->regs[R_EDX] = val;
                break;
           case RN_EBX:
                env->regs[R_EBX] = val;
                break;
           case RN_ESP:
                env->regs[R_ESP] = val;
                break;
           case RN_EBP:
                env->regs[R_EBP] = val;
                break;
           case RN_ESI:
                env->regs[R_ESI] = val;
                break;
           case RN_EDI:
                env->regs[R_EDI] = val;
                break;
           case RN_EIP:
                changed = ((env->eip) != val);
                env->eip = val;
                if (changed) {
                    pyrebox_cpu_loop_exit();
                }
                break;
           case RN_EFLAGS:
                env->eflags = val;
                break;
#elif defined(TARGET_X86_64)
           case RN_RAX:
                env->regs[R_EAX] = val;
                break;
           case RN_RCX:
                env->regs[R_ECX] = val;
                break;
           case RN_RDX:
                env->regs[R_EDX] = val;
                break;
           case RN_RBX:
                env->regs[R_EBX] = val;
                break;
           case RN_RSP:
                env->regs[R_ESP] = val;
                break;
           case RN_RBP:
                env->regs[R_EBP] = val;
                break;
           case RN_RSI:
                env->regs[R_ESI] = val;
                break;
           case RN_RDI:
                env->regs[R_EDI] = val;
                break;
           case RN_RIP:
                changed = ((env->eip) != val);
                env->eip = val;
                if (changed) {
                    pyrebox_cpu_loop_exit();
                }
                break;
           case RN_RFLAGS:
                env->eflags = val;
                break;

#endif
#if defined(TARGET_I386) || defined(TARGET_X86_64)

           case RN_CR0:
                env->cr[0] = val;
                break;
           case RN_CR1:
                env->cr[1] = val;
                break;
           case RN_CR2:
                env->cr[2] = val;
                break;
           case RN_CR3:
                env->cr[3] = val;
                break;
           case RN_CR4:
                env->cr[4] = val;
                break;
#endif
#if defined(TARGET_X86_64)
           case RN_R8:
                env->regs[8] = val;
                break;
           case RN_R9:
                env->regs[9] = val;
                break;
           case RN_R10:
                env->regs[10] = val;
                break;
           case RN_R11:
                env->regs[11] = val;
                break;
           case RN_R12:
                env->regs[12] = val;
                break;
           case RN_R13:
                env->regs[13] = val;
                break;
           case RN_R14:
                env->regs[14] = val;
                break;
           case RN_R15:
                env->regs[15] = val;
                break;
#endif
           default:
                return 1;
                break;
       }
       return 0;
    }
    return 1;
}

#if defined(TARGET_I386) || defined(TARGET_X86_64)
//selector, limit and flags are always 32 bits. base depends on 32/64 bits
int write_selector_register_convert(qemu_cpu_opaque_t cpu_opaque, register_num_t reg_num, uint32_t selector, pyrebox_target_ulong base, uint32_t limit, uint32_t flags){
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    if (reg_num <= RN_LAST && register_type[reg_num] == RT_SEGMENT)
    {
       switch(reg_num){
         case RN_ES:
            env->segs[R_ES].selector = selector;
            env->segs[R_ES].base = base;
            env->segs[R_ES].limit = limit;
            env->segs[R_ES].flags = base;
            break;
         case RN_CS: 
            env->segs[R_CS].selector = selector;
            env->segs[R_CS].base = base;
            env->segs[R_CS].limit = limit;
            env->segs[R_CS].flags = base;
            break;
         case RN_SS:    
            env->segs[R_SS].selector = selector;
            env->segs[R_SS].base = base;
            env->segs[R_SS].limit = limit;
            env->segs[R_SS].flags = base;
            break;
         case RN_DS:    
            env->segs[R_DS].selector = selector;
            env->segs[R_DS].base = base;
            env->segs[R_DS].limit = limit;
            env->segs[R_DS].flags = base;
            break;
         case RN_FS:    
            env->segs[R_FS].selector = selector;
            env->segs[R_FS].base = base;
            env->segs[R_FS].limit = limit;
            env->segs[R_FS].flags = base;
            break;
         case RN_GS:    
            env->segs[R_GS].selector = selector;
            env->segs[R_GS].base = base;
            env->segs[R_GS].limit = limit;
            env->segs[R_GS].flags = base;
            break;
         case RN_LDT:
            env->ldt.selector = selector;
            env->ldt.base = base;
            env->ldt.limit = limit;
            env->ldt.flags = base;
            break;
         case RN_TR:
            env->tr.selector = selector;
            env->tr.base = base;
            env->tr.limit = limit;
            env->tr.flags = base;
            break;
         case RN_GDT:
            env->gdt.selector = selector;
            env->gdt.base = base;
            env->gdt.limit = limit;
            env->gdt.flags = base;
            break;
         case RN_IDT:
            env->idt.selector = selector;
            env->idt.base = base;
            env->idt.limit = limit;
            env->idt.flags = base;
            break;
         default:
            return 1;
            break;
     }
     return 0;
   }
   return 1;
}
#endif

/******************************************* CPU/TB DATA EXTRAcTION **********************************************/

pyrebox_target_ulong get_pgd(qemu_cpu_opaque_t cpu_opaque){
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    return (pyrebox_target_ulong) env->cr[3];
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
}

pyrebox_target_ulong get_stack_pointer(qemu_cpu_opaque_t cpu_opaque){
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    return (pyrebox_target_ulong) env->regs[R_ESP];
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
}

#if defined(TARGET_I386) || defined(TARGET_X86_64)
pyrebox_target_ulong get_fs_base(qemu_cpu_opaque_t cpu_opaque){
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    return (pyrebox_target_ulong) env->segs[R_FS].base;
};
pyrebox_target_ulong get_gs_base(qemu_cpu_opaque_t cpu_opaque){
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    return (pyrebox_target_ulong) env->segs[R_GS].base;
};
int get_qemu_cpu_protected_mode(qemu_cpu_opaque_t cpu_opaque){
    //Protected mode for X86: The lowest bit of CR0 is set.
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    return (env->cr[0] & 0x1);
};

//Returns 0 if not running in kernel mode, 1 if running in kernel mode,
//-1 if the cpu index is incorrect
int qemu_is_kernel_running(int cpu_index){
    qemu_cpu_opaque_t cpu = get_qemu_cpu(cpu_index);
    if(cpu != NULL){
        CPUX86State* env = &(X86_CPU((CPUState*)cpu)->env);
        return((env->hflags & HF_CPL_MASK) == 0);
    } else {
        return -1;
    }
}
#endif

pyrebox_target_ulong get_tb_addr(qemu_tb_opaque_t tb_opaque){
    TranslationBlock* tb = (TranslationBlock*)tb_opaque;
    return (pyrebox_target_ulong) tb->pc;
}
pyrebox_target_ulong get_tb_size(qemu_tb_opaque_t tb_opaque){
    TranslationBlock* tb = (TranslationBlock*)tb_opaque;
    return (pyrebox_target_ulong) tb->size;
}
pyrebox_target_ulong get_cpu_addr(qemu_cpu_opaque_t cpu_opaque){
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State* env = &(X86_CPU((CPUState*)cpu_opaque)->env);
    return (pyrebox_target_ulong) env->eip;
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif

}

qemu_cpu_opaque_t get_qemu_cpu(int cpu_index){
    int ind = 0;
    CPUState* next_cpu = first_cpu;
    while (ind < cpu_index && next_cpu != NULL)
    {
        ++ind;
        next_cpu = CPU_NEXT(next_cpu);
    }
    return (qemu_cpu_opaque_t) next_cpu;
}


qemu_cpu_opaque_t get_qemu_cpu_with_pgd(pyrebox_target_ulong pgd){
    CPUState* next_cpu = first_cpu;
    while (next_cpu != NULL)
    {
#if defined(TARGET_I386) || defined(TARGET_X86_64)
        CPUX86State* env = &(X86_CPU(next_cpu)->env);
        if (env->cr[3] == pgd)
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
        {   
            return (qemu_cpu_opaque_t) next_cpu;
        }
        next_cpu = CPU_NEXT(next_cpu);
    }
    return NULL;
}

int get_qemu_cpu_index_with_pgd(pyrebox_target_ulong pgd){
    CPUState* next_cpu = first_cpu;
    int ind = 0;
    while (next_cpu != NULL)
    {
#if defined(TARGET_I386) || defined(TARGET_X86_64)
        CPUX86State* env = &(X86_CPU(next_cpu)->env);
        if (env->cr[3] == pgd)
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
        {
            return ind;
        }
        next_cpu = CPU_NEXT(next_cpu);
        ++ind;
    }
    return -1;
}

pyrebox_target_ulong get_running_process(int cpu_index){
    int ind = 0;
    CPUState* next_cpu = first_cpu;
    while (ind < cpu_index && next_cpu != NULL)
    {
        ++ind;
        next_cpu = CPU_NEXT(next_cpu);
    }
    if (next_cpu != NULL){
#if defined(TARGET_I386) || defined(TARGET_X86_64)
        CPUX86State* env = &(X86_CPU(next_cpu)->env);
        return ((pyrebox_target_ulong)env->cr[3]);
#elif defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
#error "Architecture not supported yet"
#endif
    }
    else{
        return 0;
    }
}


int get_num_cpus(void){
    int ind = 0;
    CPUState* next_cpu = first_cpu;
    while (next_cpu != NULL)
    {
        ++ind;
        next_cpu = CPU_NEXT(next_cpu);
    }
    return ind;
}

/************************************************** UTILITY FUNCTIONS **********************************************/

void pyrebox_save_vm(char* name)
{
    QDict* qdict = qdict_new();
    qdict_put_obj(qdict, "name", QOBJECT(qstring_from_str(name)));
    hmp_savevm(cur_mon,qdict);
}
void pyrebox_load_vm(char* name)
{
    QDict* qdict = qdict_new();
    qdict_put_obj(qdict, "name", QOBJECT(qstring_from_str(name)));
    hmp_loadvm(cur_mon,qdict);
}

/* Extracted from Panda: memory-access.c. See third_party/panda/ */
uint64_t
connection_read_memory (uint64_t user_paddr, char *buf, uint64_t user_len)
{
    hwaddr paddr = (hwaddr) user_paddr;
    hwaddr len = (hwaddr) user_len;

    hwaddr size = len;
    uint8_t buf2[1024];
    uint32_t l;
    while (size != 0) {
        l = sizeof(buf2);
        if (l > size)
            l = size;
        cpu_physical_memory_read(paddr, buf2, l);
        memcpy(buf, buf2, l);
        buf+=l;
        paddr += l;
        size -= l;
    }
    return len;
}

uint64_t
connection_write_memory (uint64_t user_paddr, void *buf, uint64_t user_len)
{
    hwaddr paddr = (hwaddr) user_paddr;
    hwaddr len = (hwaddr) user_len;
    void *guestmem = cpu_physical_memory_map(paddr, &len, 1);
    if (!guestmem){
        return 0;
    }
    memcpy(guestmem, buf, len);
    cpu_physical_memory_unmap(guestmem, len, 0, len);

    return len;
}

//Added support to retrieve memory size
uint64_t get_memory_size(void)
{
    RAMBlock *block;
    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (strstr(block->idstr,"ram") != 0){
            return block->used_length;
        }
    }
    return 0;
}
/* End of - Extracted from Panda: memory-access.c. See third_party/panda/ */
