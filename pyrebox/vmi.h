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

#ifndef VMI_H
#define VMI_H

#define MAX_PROFILE_LEN 64
#define MAX_PROCNAME_LEN 512

//PROC_PRESENT must be the last option, so < PROC_PRESENT means we must not skip it
#define PROC_NOT_PRESENT 0
#define PROC_PRESENT 1

#ifdef __cplusplus

class Process{
   private:
       pyrebox_target_ulong pgd;
       pyrebox_target_ulong pid;
       pyrebox_target_ulong ppid;
       //Address for the kernel structure representing the process
       pyrebox_target_ulong kernel_addr;
       pyrebox_target_ulong exittime_offset;
       char name[MAX_PROCNAME_LEN];
   public:

       Process() {}
       Process(pyrebox_target_ulong pgd, pyrebox_target_ulong pid, pyrebox_target_ulong ppid, pyrebox_target_ulong kernel_addr, pyrebox_target_ulong exittime_offset, char* name){
           this->pgd = pgd;
           this->pid = pid;
           this->ppid = ppid;
           this->kernel_addr = kernel_addr;
           this->exittime_offset = exittime_offset;
           strncpy(this->name,name,MAX_PROCNAME_LEN);
       }
       void set(pyrebox_target_ulong pgd, pyrebox_target_ulong pid, pyrebox_target_ulong ppid, pyrebox_target_ulong kernel_addr, pyrebox_target_ulong exittime_offset, char* name){
           this->pgd = pgd;
           this->pid = pid;
           this->ppid = ppid;
           this->kernel_addr = kernel_addr;
           this->exittime_offset = exittime_offset;
           strncpy(this->name,name,MAX_PROCNAME_LEN);
       }

       void set_pgd(pyrebox_target_ulong pgd) {this->pgd = pgd;}
       void set_pid(pyrebox_target_ulong pid) {this->pid = pid;}
       pyrebox_target_ulong get_pgd() const {return this->pgd;}
       pyrebox_target_ulong get_pid() const {return this->pid;}
       pyrebox_target_ulong get_ppid() const {return this->ppid;}
       pyrebox_target_ulong get_kernel_addr() const {return this->kernel_addr;}
       pyrebox_target_ulong get_exittime_offset() const {return this->exittime_offset;}
       char* get_name() const {return (char*) this->name;}
       //Order and uniqueness based on PID, because there can be several processes
       //with the same address space (case for kernel threads in linux)
       bool operator< (const Process& rhs) const {return (this->pid < rhs.pid);}
};

extern std::set<Process> processes;
extern std::set<pyrebox_target_ulong> pgds_in_list;

#endif//__cplusplus


#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

typedef enum os_index{
    VistaSP0x64 = 0,
    VistaSP0x86,
    VistaSP1x64,
    VistaSP1x86,
    VistaSP2x64,
    VistaSP2x86,
    Win10x64,
    Win10x86,
    Win2003SP0x86,
    Win2003SP1x64,
    Win2003SP1x86,
    Win2003SP2x64,
    Win2003SP2x86,
    Win2008R2SP0x64,
    Win2008R2SP1x64,
    Win2008SP1x64,
    Win2008SP1x86,
    Win2008SP2x64,
    Win2008SP2x86,
    Win2012R2x64,
    Win2012x64,
    Win7SP0x64,
    Win7SP0x86,
    Win7SP1x64,
    Win7SP1x86,
    Win8SP0x64,
    Win8SP0x86,
    Win8SP1x64,
    Win8SP1x86,
    WinXPSP1x64,
    WinXPSP2x64,
    WinXPSP2x86,
    WinXPSP3x86,
    LimitWindows,
    Linuxx86,
    Linuxx64,
    OsX32,
    OsX64,
    LastIndex
} os_index_t;

extern int arch_bits[LastIndex];

extern os_index_t os_index;
extern char vol_profile[MAX_PROFILE_LEN];
void vmi_tlb_callback(pyrebox_target_ulong new_pgd, pyrebox_target_ulong vaddr);
void vmi_context_change(pyrebox_target_ulong old_pgd,pyrebox_target_ulong new_pgd);
void vmi_init(const char* prof);
void vmi_add_process(pyrebox_target_ulong pgd, pyrebox_target_ulong pid, pyrebox_target_ulong ppid, pyrebox_target_ulong kernel_addr, pyrebox_target_ulong exittime_offset, char* name);
void vmi_remove_process(pyrebox_target_ulong pid);
int is_process_pgd_in_list(pyrebox_target_ulong pgd);
int is_process_pid_in_list(pyrebox_target_ulong pid);
void vmi_set_process_pid_present(pyrebox_target_ulong pid);
void vmi_reset_process_present(void);
void vmi_remove_not_present_processes(void);

#ifdef __cplusplus
};
#endif//__cplusplus

#endif
