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

#include <inttypes.h>
#include <Python.h>
#include <set>
#include <pthread.h>

extern "C"{
#include "qemu_glue.h"
#include "utils.h"
#include "pyrebox.h"
}
#include "vmi.h"
#include "windows_vmi.h"

using namespace std;

pyrebox_target_ulong kdbg_address = 0;
static unsigned long long tlb_counter = 0;
pyrebox_target_ulong ps_active_process_list;

//Offset list taken from volatility overlays
unsigned int eprocess_offsets[LimitWindows][LastOffset] = { {0xe8,0xe0,0x1f0,0x238,0x28,0xd0}, // VistaSP0x64
    {0xa0,0x9c,0x124,0x14c,0x18,0x90}, //VistaSP0x86,
    {0xe8,0xe0,0x1f0,0x238,0x28,0xd0}, //VistaSP1x64,
    {0xa0,0x9c,0x124,0x14c,0x18,0x90}, //VistaSP1x86,
    {0xe8,0xe0,0x1f0,0x238,0x28,0xd0}, //VistaSP2x64,
    {0xa0,0x9c,0x124,0x14c,0x18,0x90}, //VistaSP2x86,
    {0x2f0,0x2e8,0x3e0,0x448,0x28,0x670}, //Win10x64,
    {0xb8,0xb4,0x138,0x170,0x18,0x2c0}, //Win10x86,
    {0x88,0x84,0x128,0x154,0x18,0x78}, //Win2003SP0x86,
    {0xe0,0xd8,0x218,0x268,0x28,0xc8}, //Win2003SP1x64,
    {0x98,0x94,0x138,0x164,0x18,0x88}, //Win2003SP1x86,
    {0xe0,0xd8,0x218,0x268,0x28,0xc8}, //Win2003SP2x64,
    {0x98,0x94,0x138,0x164,0x18,0x88}, //Win2003SP2x86,
    {0x188,0x180,0x290,0x2e0,0x28,0x170}, //Win2008R2SP0x64,
    {0x188,0x180,0x290,0x2e0,0x28,0x170}, //Win2008R2SP1x64,
    {0x188,0x180,0x290,0x2e0,0x28,0xd0}, //Win2008SP1x64,
    {0xa0,0x9c,0x124,0x14c,0x18,0x90}, //Win2008SP1x86,
    {0x188,0x180,0x290,0x2e0,0x28,0xd0}, //Win2008SP2x64,
    {0xa0,0x9c,0x124,0x14c,0x18,0x90}, //Win2008SP2x86,
    {0x2e8,0x2e0,0x3d0,0x438,0x28,0x640}, //Win2012R2x64,
    {0x2e8,0x2e0,0x3d0,0x438,0x28,0x610}, //Win2012x64,
    {0x188,0x180,0x290,0x2e0,0x28,0x170}, //Win7SP0x64,
    {0xb8,0xb4,0x140,0x16c,0x18,0xa8}, //Win7SP0x86,
    {0x188,0x180,0x290,0x2e0,0x28,0x170}, //Win7SP1x64,
    {0xb8,0xb4,0x140,0x16c,0x18,0xa8}, //Win7SP1x86,
    {0x2e8,0x2e0,0x3d0,0x438,0x28,0x610}, //Win8SP0x64,
    {0xb8,0xb4,0x134,0x170,0x18,0x2b8}, //Win8SP0x86,
    {0x2e8,0x2e0,0x3d0,0x438,0x28,0x640}, //Win8SP1x64,
    {0xb8,0xb4,0x134,0x170,0x18,0x2b0}, //Win8SP1x86,
    {0xe0,0xd8,0x218,0x268,0x28,0xc8}, //WinXPSP1x64,
    {0xe0,0xd8,0x218,0x268,0x28,0xc8}, //WinXPSP2x64,
    {0x88,0x84,0x14c,0x174,0x180,0x78}, //WinXPSP2x86,
    {0x88,0x84,0x14c,0x174,0x18,0x78}}; //WinXPSP3x86,

pyrebox_target_ulong scan_kdbg(pyrebox_target_ulong pgd){
   //Good reference: http://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kpcr.htm
   //Good reference: Volatility overlays

   PyObject* py_module_name = PyString_FromString("windows_vmi");
   PyObject* py_vmi_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);

   pyrebox_target_ulong kdbg = 0;

   if(py_vmi_module != NULL){
       PyObject* py_kdbgscan = PyObject_GetAttrString(py_vmi_module,"windows_kdbgscan_fast");
       if (py_kdbgscan){
           if (PyCallable_Check(py_kdbgscan)){
                PyObject* py_args = PyTuple_New(1);
                if (arch_bits[os_index] == 32){
                    PyTuple_SetItem(py_args, 0, PyLong_FromUnsignedLong(pgd)); // The reference to the object in the tuple is stolen
                }
                else{
                    PyTuple_SetItem(py_args, 0, PyLong_FromUnsignedLongLong(pgd)); // The reference to the object in the tuple is stolen
                }
                PyObject* addr = PyObject_CallObject(py_kdbgscan,py_args);
                Py_DECREF(py_args);
                if (addr){
                    if (arch_bits[os_index] == 32){
                        kdbg = PyLong_AsUnsignedLong(addr);
                    }
                    else{
                        kdbg = PyLong_AsUnsignedLongLong(addr);
                    }
                    Py_DECREF(addr);
                }
           }
           Py_XDECREF(py_kdbgscan);
       }
       Py_DECREF(py_vmi_module);
   }


   return canonical_address(kdbg); 
}

void windows_vmi_init(os_index_t os_index){
   utils_print_debug("[*] Searching for KDBG...\n");

   //Update the OS family in the Python VMI module
   PyObject* py_module_name = PyString_FromString("vmi");
   PyObject* py_vmi_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);

   if(py_vmi_module != NULL){
       PyObject* py_setosfamily = PyObject_GetAttrString(py_vmi_module,"set_os_family_win");
       if (py_setosfamily){
           if (PyCallable_Check(py_setosfamily)){
                PyObject* py_args = PyTuple_New(0);
                PyObject* ret = PyObject_CallObject(py_setosfamily,py_args);
                Py_DECREF(py_args);
                if (ret){
                    Py_DECREF(ret);
                }
           }
           Py_XDECREF(py_setosfamily);
       }
       Py_DECREF(py_vmi_module);
   }
}

void windows_vmi_context_change_callback(pyrebox_target_ulong old_pgd,pyrebox_target_ulong new_pgd, os_index_t os_index){
    //Check if any process has an exit time > 0, if so, remove it    
    //XXX: For every process in the list of procs, read the exit time
    set<pyrebox_target_ulong> to_remove;
    for (set<Process>::iterator it = processes.begin();it != processes.end();++it){
        uint64_t exittime = 0;
        qemu_virtual_memory_rw_with_pgd(new_pgd,it->get_exittime_offset(),(uint8_t*)&exittime,EXIT_TIME_SIZE,0);
        if (exittime > 0){
            to_remove.insert(it->get_pid());
        }
    }
    for (set<pyrebox_target_ulong>::iterator it = to_remove.begin();it != to_remove.end(); ++it){
        vmi_remove_process(*it);
    }
}

void windows_vmi_tlb_callback(pyrebox_target_ulong pgd, os_index_t os_index){
    //First, try to resolve the kdbg_address, if we have not yet done it.
    int kdbg_found = 0;
    if (kdbg_address == 0){
        tlb_counter += 1;
        //Wait until we have a valid kpcr, and then search for kdbg. Hopefully it is already in memory.
        if (tlb_counter % 1000 == 0){
            pyrebox_target_ulong kpcr = 0;
            pyrebox_target_ulong selfpcr = (pyrebox_target_ulong) -1;
            //First, try to see if gs or fs point to a valid kpcr
            if(arch_bits[os_index] == 32){
               //In 32 bits, we get the KPCR from the FS register
               qemu_cpu_opaque_t cpu = get_qemu_cpu_with_pgd(pgd);
               kpcr = get_fs_base(cpu);
               /* GETTING KDBG FROM KPCR DOES NOT WORK
                *
                * On 32 bits, only the KPCR for the first processor points to the KDBG.
                * On 64 bits, in many cases all KPCRs have the kdbg pointing to null, so we cannot have direct
                * access to KDBG and have to scan for it (see win32/tasks.py and kpcr_vtypes.py in
                * volatility).
                *
                * Wait until we have a valid kpcr, and then search for kdbg. Hopefully it is already in memory.
                *
               */
               qemu_virtual_memory_rw_with_pgd(pgd,kpcr + SELFPCR_OFFSET_32,(uint8_t*)&selfpcr,sizeof(pyrebox_target_ulong),0);
            }
            else if (arch_bits[os_index] == 64){
                qemu_cpu_opaque_t cpu = get_qemu_cpu_with_pgd(pgd);
                kpcr = get_gs_base(cpu);
                qemu_virtual_memory_rw_with_pgd(pgd,kpcr + SELFPCR_OFFSET_64,(uint8_t*)&selfpcr,sizeof(pyrebox_target_ulong),0);
            }
            //Now that KPCR seems to be valid, we scan the kdbg
            if (kpcr && kpcr == selfpcr){
                kdbg_address = scan_kdbg(pgd);
                if (kdbg_address != 0){
#if TARGET_LONG_SIZE == 4
                        utils_print_debug("[*] KPCR found at %x!!\n", kpcr);
                        utils_print_debug("[*] KDBG found at %x!!\n", kdbg_address);
#elif TARGET_LONG_SIZE == 8
                        utils_print_debug("[*] KPCR found at %lx!!\n", kpcr);
                        utils_print_debug("[*] KDBG found at %lx!!\n", kdbg_address);
#else
#error TARGET_LONG_SIZE undefined
#endif
                        //Update the variable to indicate that we found the kdbg
                        kdbg_found = 1;
                }
            }
        }
    }
    //If the pgd is not in the list of processes, then we insert it.
    if (is_process_pgd_in_list(pgd) < PROC_PRESENT){
        //Once kdbg is resolved, we can then start scanning processes
        if (kdbg_address != 0){
            qemu_virtual_memory_rw_with_pgd(pgd,kdbg_address + PS_ACTIVE_PROCESS_HEAD_OFFSET,(uint8_t*)&ps_active_process_list,sizeof(pyrebox_target_ulong),0);
            if (ps_active_process_list != 0){
               //ps_active_process_list points to a _LIST_ENTRY structure, 
               //whose first member (flink), points to the first process's _LIST_ENTRY
               pyrebox_target_ulong cur_proc = 0;
               qemu_virtual_memory_rw_with_pgd(pgd,ps_active_process_list,(uint8_t*)&cur_proc,sizeof(pyrebox_target_ulong),0);
               //Traverse the list, find the process, and add it to the process list 
               while (cur_proc != 0 && cur_proc != ps_active_process_list){
                   pyrebox_target_ulong cur_proc_base = cur_proc - eprocess_offsets[os_index][PS_ACTIVE_LIST];
                   //Read pgd 
                   pyrebox_target_ulong proc_pgd = 0;
                   qemu_virtual_memory_rw_with_pgd(pgd,cur_proc_base + eprocess_offsets[os_index][PGD],(uint8_t*)&proc_pgd,sizeof(pyrebox_target_ulong),0);

                   int is_in_list = is_process_pgd_in_list(proc_pgd);
                   //This is the process we are looking for, or we need to initially populate the list
                   if (pgd == proc_pgd || (kdbg_found == 1 && is_in_list == PROC_NOT_PRESENT)) {
                       //Read Pid, ppid, name
                       pyrebox_target_ulong pid = 0;
                       pyrebox_target_ulong ppid = 0;
                       char proc_name[MAX_PROCNAME_LEN];
                       //Set string to 0
                       memset(proc_name,0,MAX_PROCNAME_LEN);
                       assert(MAX_PROCNAME_LEN >= PROCESS_NAME_SIZE);
                       uint64_t exittime;
                       qemu_virtual_memory_rw_with_pgd(pgd,cur_proc_base + eprocess_offsets[os_index][PID],(uint8_t*)&pid,sizeof(pyrebox_target_ulong),0);
                       qemu_virtual_memory_rw_with_pgd(pgd,cur_proc_base + eprocess_offsets[os_index][PPID],(uint8_t*)&ppid,sizeof(pyrebox_target_ulong),0);
                       qemu_virtual_memory_rw_with_pgd(pgd,cur_proc_base + eprocess_offsets[os_index][NAME],(uint8_t*)&proc_name,PROCESS_NAME_SIZE,0);
                       qemu_virtual_memory_rw_with_pgd(pgd,cur_proc_base + eprocess_offsets[os_index][EXIT_TIME],(uint8_t*)&exittime,EXIT_TIME_SIZE,0);
                       //Add the process, only if has not already exited but the EPROCESS structure remains there
                       if (exittime == 0){
                           if (is_in_list == PROC_NOT_PRESENT){
                               vmi_add_process(proc_pgd, pid, ppid, cur_proc_base, cur_proc_base + eprocess_offsets[os_index][EXIT_TIME],(char*) proc_name);
                           }                       
                       }
                       //Force loop exit, only if we are not populating the list for the first time
                       if (kdbg_found == 0){
                           cur_proc = 0;
                       }
                   }
                   if (cur_proc != 0){
                       //Advance to next process, cur_proc points to the _LIST_ENTRY of the process
                       qemu_virtual_memory_rw_with_pgd(pgd,cur_proc,(uint8_t*)&cur_proc,sizeof(pyrebox_target_ulong),0);
                   }
               }
            }
        }
    }
}
