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
#include <limits.h>
#include <list>
#include <set>

extern "C" {
#include <pthread.h>
#include "qemu_glue.h"    
#include "utils.h"
#include "pyrebox.h"
}

#include "vmi.h"
#include "windows_vmi.h"
#include "linux_vmi.h"
#include "callbacks.h"

using namespace std;

set<Process> processes;
set<pyrebox_target_ulong> pgds_in_list;
set<pyrebox_target_ulong> present_pids;

extern "C" {

int arch_bits[LastIndex] = {64,32,64,32,64,32, //Vista
                            64,32, //Win10
                            32,64,32,64,32, //2003
                            64,64,64,32,64,32, //2008
                            64,64, //2012
                            64,32,64,32, // Win7
                            64,32,64,32, //Win8
                            64,64,32,32, //Xp
                            0,32,64,32,64};

char vol_profile[MAX_PROFILE_LEN];
os_index_t os_index;

void vmi_context_change(pyrebox_target_ulong old_pgd,pyrebox_target_ulong new_pgd){
    if (os_index < LimitWindows){
        windows_vmi_context_change_callback(old_pgd,new_pgd,os_index);
    }
    else if (os_index == Linuxx86 || os_index == Linuxx64){
        linux_vmi_context_change_callback(old_pgd,new_pgd,os_index);
    }
    else {
        utils_print_error("[!] Unsupported guest image");
        exit(1);
    }
}

void update_modules(pyrebox_target_ulong pgd){

   //Lock the python mutex
   pthread_mutex_lock(&pyrebox_mutex);
   fflush(stdout);
   fflush(stderr);

   //Call python for module scanning
   PyObject* py_module_name = PyString_FromString("vmi");
   PyObject* py_vmi_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);

   if(py_vmi_module != NULL){
       PyObject* py_update_modules = PyObject_GetAttrString(py_vmi_module, "update_modules");
       if (py_update_modules){
           if (PyCallable_Check(py_update_modules)){
                PyObject* py_args = PyTuple_New(1);
                if (arch_bits[os_index] == 32){
                    PyTuple_SetItem(py_args, 0, PyLong_FromUnsignedLong(pgd)); // The reference to the object in the tuple is stolen
                }
                else{
                    PyTuple_SetItem(py_args, 0, PyLong_FromUnsignedLongLong(pgd)); // The reference to the object in the tuple is stolen
                }
                PyObject* ret = PyObject_CallObject(py_update_modules, py_args);
                Py_DECREF(py_args);
                if (ret){
                    Py_DECREF(ret);
                }
           }
           Py_XDECREF(py_update_modules);
       }
       Py_DECREF(py_vmi_module);
   }

   //Unlock the python mutex
   fflush(stdout);
   fflush(stderr);
   pthread_mutex_unlock(&pyrebox_mutex);
}


void vmi_tlb_callback(pyrebox_target_ulong new_pgd, pyrebox_target_ulong vaddr){
    if (os_index < LimitWindows){
        windows_vmi_tlb_callback(new_pgd,os_index);
    }
    else if (os_index == Linuxx86 || os_index == Linuxx64){
        linux_vmi_tlb_callback(new_pgd,os_index);
    }
    else {
        utils_print_error("[!] Unsupported guest image");
        exit(1);
    }
}

void vmi_init(const char* prof){
    strncpy(vol_profile,prof,MAX_PROFILE_LEN);
    if (strncmp(vol_profile,"'VistaSP0x64'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP0x64;
    }
    else if(strncmp(vol_profile,"'VistaSP0x86'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP0x86;
    }
    else if(strncmp(vol_profile,"'VistaSP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP1x64;
    }
    else if(strncmp(vol_profile,"'VistaSP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP1x86;
    }
    else if(strncmp(vol_profile,"'VistaSP2x64'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP2x64;
    }
    else if(strncmp(vol_profile,"'VistaSP2x86'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP2x86;
    }
    else if(strncmp(vol_profile,"'Win10x64'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP2x64;
    }
    else if(strncmp(vol_profile,"'Win10x86'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP2x86;
    }
    else if(strncmp(vol_profile,"'Win2003SP0x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP0x86;
    }
    else if(strncmp(vol_profile,"'Win2003SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP1x64;
    }
    else if(strncmp(vol_profile,"'Win2003SP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP1x86;
    }
    else if(strncmp(vol_profile,"'Win2003SP2x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP2x64;
    }
    else if(strncmp(vol_profile,"'Win2003SP2x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP2x86;
    }
    else if(strncmp(vol_profile,"'Win2008R2SP0x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008R2SP0x64;
    }
    else if(strncmp(vol_profile,"'Win2008R2SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008R2SP1x64;
    }
    else if(strncmp(vol_profile,"'Win2008SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008SP1x64;
    }
    else if(strncmp(vol_profile,"'Win2008SP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008SP1x86;
    }
    else if(strncmp(vol_profile,"'Win2008SP2x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008SP2x64;
    }
    else if(strncmp(vol_profile,"'Win2008SP2x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008SP2x86;
    }
    else if(strncmp(vol_profile,"'Win2012R2x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2012R2x64;
    }
    else if(strncmp(vol_profile,"'Win2012x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2012x64;
    }
    else if(strncmp(vol_profile,"'Win7SP0x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win7SP0x64;
    }
    else if(strncmp(vol_profile,"'Win7SP0x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win7SP0x86;
    }
    else if(strncmp(vol_profile,"'Win7SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win7SP1x64;
    }
    else if(strncmp(vol_profile,"'Win7SP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win7SP1x86;
    }
    else if(strncmp(vol_profile,"'Win8SP0x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win8SP0x64;
    }
    else if(strncmp(vol_profile,"'Win8SP0x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win8SP0x86;
    }
    else if(strncmp(vol_profile,"'Win8SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win8SP1x64;
    }
    else if(strncmp(vol_profile,"'Win8SP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win8SP1x86;
    }
    else if(strncmp(vol_profile,"'WinXPSP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = WinXPSP1x64;
    }
    else if(strncmp(vol_profile,"'WinXPSP2x64'",MAX_PROFILE_LEN) == 0){
        os_index = WinXPSP2x64;
    }
    else if(strncmp(vol_profile,"'WinXPSP2x86'",MAX_PROFILE_LEN) == 0){
        os_index = WinXPSP2x86;
    }
    else if(strncmp(vol_profile,"'WinXPSP3x86'",MAX_PROFILE_LEN) == 0){
        os_index = WinXPSP3x86;
    }
    else if(strncmp(vol_profile,"'Linux",6) == 0){
        if (strstr(vol_profile,"x86'")){
            os_index = Linuxx86;
        } else if (strstr(vol_profile,"x64'")){
            os_index = Linuxx64;
        } else {
            utils_print_error("[!] Linux architecture not supported: (Supported archs: x86 - x64)");
            exit(1);
        }
    }
    //Call to the corresponding initialization routine
    if (os_index < LimitWindows){
        windows_vmi_init(os_index);
    }
    else if (os_index == Linuxx86 || os_index == Linuxx64){
        linux_vmi_init(os_index);
    }
    else {
        utils_print_error("[!] Unsupported guest image");
        exit(1);
    }
}

void vmi_add_process(pyrebox_target_ulong pgd, pyrebox_target_ulong pid, pyrebox_target_ulong ppid, pyrebox_target_ulong kernel_addr, pyrebox_target_ulong exittime_offset, char* name){
    Process p;
    p.set(pgd,pid,ppid,kernel_addr,exittime_offset,name);
    processes.insert(p);

    //Update pgds_in_list too
    if (is_process_pgd_in_list(pgd) == PROC_NOT_PRESENT){
        pgds_in_list.insert(pgd);
    }

    //Call the corresponding callback
    callback_params_t params;
    params.vmi_create_proc_params.pid = pid;
    params.vmi_create_proc_params.pgd = pgd;
    params.vmi_create_proc_params.name = name;
    create_proc_callback(params);

}

void vmi_remove_process(pyrebox_target_ulong pid){
    Process p;
    p.set_pid(pid);
    set<Process>::iterator it = processes.find(p);
    if (it != processes.end()){
        //Call the corresponding callback
        callback_params_t params;
        params.vmi_remove_proc_params.pid = it->get_pid();
        params.vmi_remove_proc_params.pgd = it->get_pgd();
        params.vmi_remove_proc_params.name = (char*) it->get_name();
        remove_proc_callback(params);
        processes.erase(it);
        //Update pgds_in_list if there are no more processes with the same pgd
        int is_pgd_in_list = 0;
        it = processes.begin();
        while (!is_pgd_in_list && it != processes.end()){
            is_pgd_in_list = (it->get_pgd() == params.vmi_remove_proc_params.pgd);
            ++it;
        }
        if (!is_pgd_in_list){
            pgds_in_list.erase(params.vmi_remove_proc_params.pgd);
        }
    }
}

int is_process_pid_in_list(pyrebox_target_ulong pid){
    Process p;
    p.set_pid(pid);
    set<Process>::iterator it = processes.find(p);
    if (it!=processes.end()){
        return PROC_PRESENT;
    } else {
        return PROC_NOT_PRESENT; 
    }
}

int is_process_pgd_in_list(pyrebox_target_ulong pgd){
    set<pyrebox_target_ulong>::iterator it = pgds_in_list.find(pgd);
    if (it != pgds_in_list.end()){
        return PROC_PRESENT;
    } else {
        return PROC_NOT_PRESENT;
    }
}

void vmi_set_process_pid_present(pyrebox_target_ulong pid){
    present_pids.insert(pid);
}

void vmi_reset_process_present(){
    present_pids.clear();
}

void vmi_remove_not_present_processes(){
    set<pyrebox_target_ulong> pids_to_remove;
    for(set<Process>::iterator it = processes.begin(); it != processes.end(); ++it){
        if (present_pids.find(it->get_pid()) == present_pids.end()){
            pids_to_remove.insert(it->get_pid());
        }
    }
    for(set<pyrebox_target_ulong>::iterator it = pids_to_remove.begin(); it != pids_to_remove.end(); ++it){
        vmi_remove_process(*it);
    }
}

};// extern "C"
