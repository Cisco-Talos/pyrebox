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
#include "qemu_glue.h"    
#include "utils.h"

}

#include "vmi.h"
#include "windows_vmi.h"
#include "callbacks.h"

using namespace std;

set<Process> processes;

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
    else {
        utils_print_error("[!] Unsupported guest image");
        exit(1);
    }
}

void vmi_tlb_callback(pyrebox_target_ulong new_pgd){
    if (os_index < LimitWindows){
        windows_vmi_tlb_callback(new_pgd,os_index);
    }
    else {
        utils_print_error("[!] Unsupported guest image");
        exit(1);
    }
}

void vmi_init(const char* prof){
    strncpy(vol_profile,prof,MAX_PROFILE_LEN);
    if (strncmp(prof,"'VistaSP0x64'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP0x64;
    }
    else if(strncmp(prof,"'VistaSP0x86'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP0x86;
    }
    else if(strncmp(prof,"'VistaSP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP1x64;
    }
    else if(strncmp(prof,"'VistaSP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP1x86;
    }
    else if(strncmp(prof,"'VistaSP2x64'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP2x64;
    }
    else if(strncmp(prof,"'VistaSP2x86'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP2x86;
    }
    else if(strncmp(prof,"'Win10x64'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP2x64;
    }
    else if(strncmp(prof,"'Win10x86'",MAX_PROFILE_LEN) == 0){
        os_index = VistaSP2x86;
    }
    else if(strncmp(prof,"'Win2003SP0x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP0x86;
    }
    else if(strncmp(prof,"'Win2003SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP1x64;
    }
    else if(strncmp(prof,"'Win2003SP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP1x86;
    }
    else if(strncmp(prof,"'Win2003SP2x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP2x64;
    }
    else if(strncmp(prof,"'Win2003SP2x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2003SP2x86;
    }
    else if(strncmp(prof,"'Win2008R2SP0x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008R2SP0x64;
    }
    else if(strncmp(prof,"'Win2008R2SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008R2SP1x64;
    }
    else if(strncmp(prof,"'Win2008SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008SP1x64;
    }
    else if(strncmp(prof,"'Win2008SP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008SP1x86;
    }
    else if(strncmp(prof,"'Win2008SP2x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008SP2x64;
    }
    else if(strncmp(prof,"'Win2008SP2x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win2008SP2x86;
    }
    else if(strncmp(prof,"'Win2012R2x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2012R2x64;
    }
    else if(strncmp(prof,"'Win2012x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win2012x64;
    }
    else if(strncmp(prof,"'Win7SP0x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win7SP0x64;
    }
    else if(strncmp(prof,"'Win7SP0x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win7SP0x86;
    }
    else if(strncmp(prof,"'Win7SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win7SP1x64;
    }
    else if(strncmp(prof,"'Win7SP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win7SP1x86;
    }
    else if(strncmp(prof,"'Win8SP0x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win8SP0x64;
    }
    else if(strncmp(prof,"'Win8SP0x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win8SP0x86;
    }
    else if(strncmp(prof,"'Win8SP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = Win8SP1x64;
    }
    else if(strncmp(prof,"'Win8SP1x86'",MAX_PROFILE_LEN) == 0){
        os_index = Win8SP1x86;
    }
    else if(strncmp(prof,"'WinXPSP1x64'",MAX_PROFILE_LEN) == 0){
        os_index = WinXPSP1x64;
    }
    else if(strncmp(prof,"'WinXPSP2x64'",MAX_PROFILE_LEN) == 0){
        os_index = WinXPSP2x64;
    }
    else if(strncmp(prof,"'WinXPSP2x86'",MAX_PROFILE_LEN) == 0){
        os_index = WinXPSP2x86;
    }
    else if(strncmp(prof,"'WinXPSP3x86'",MAX_PROFILE_LEN) == 0){
        os_index = WinXPSP3x86;
    }

    //Call to the corresponding initialization routine
    if (os_index < LimitWindows){
        windows_vmi_init(os_index);
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

    //Call the corresponding callback
    callback_params_t params;
    params.vmi_create_proc_params.pid = pid;
    params.vmi_create_proc_params.pgd = pgd;
    params.vmi_create_proc_params.name = name;
    create_proc_callback(params);
}

void vmi_remove_process(pyrebox_target_ulong pgd){
    Process p;
    pyrebox_target_ulong pid = 0;
    p.set_pgd(pgd);
    set<Process>::iterator it = processes.find(p);
    if (it != processes.end()){
        //Call the corresponding callback
        callback_params_t params;
        params.vmi_remove_proc_params.pid = pid;
        params.vmi_remove_proc_params.pgd = pgd;
        params.vmi_remove_proc_params.name = (char*) it->get_name();
        remove_proc_callback(params);
        pid = it->get_pid();
        processes.erase(it);
    }
}
int is_process_in_list(pyrebox_target_ulong pgd)
{
    Process p;
    p.set_pgd(pgd);
    set<Process>::iterator it = processes.find(p);
    if (it!=processes.end()){
        if (it->get_pid() == 0){
            return PROC_UNDEFINED;
        } else {
            return PROC_PRESENT;
        }
    } else {
        return PROC_NOT_PRESENT; 
    }
}

};// extern "C"
