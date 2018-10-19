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

#include <stdio.h>
#include <map>
#include <unordered_set>
#include <set>
#include <list>
#include <string>
#include <Python.h>
extern "C"{
    #include "qemu_glue.h"
}
#include "callbacks.h"
#include "trigger_helpers.h"

extern "C"{
    std::map<callback_handle_t, std::unordered_set<pyrebox_target_ulong> > page_status;
    std::map<callback_handle_t, int> function_declared;
    std::map<callback_handle_t, pyrebox_target_ulong*> begin;
    std::map<callback_handle_t, pyrebox_target_ulong*> end;
    std::map<callback_handle_t, pyrebox_target_ulong*> pgd;

    void erase_vars(callback_handle_t handle){
        begin[handle] = (pyrebox_target_ulong*) get_var(handle,"begin");
        end[handle] = (pyrebox_target_ulong*) get_var(handle,"end");
        pgd[handle] = (pyrebox_target_ulong*) get_var(handle,"pgd");
        page_status[handle].clear();
    }

    //Define trigger type. This type is checked when trigger is loaded
    callback_type_t get_type(){
        return MEM_WRITE_CB;
    }

    //Trigger, return 1 if event should be passed to python callback 
    int trigger(callback_handle_t handle, callback_params_t params){
        if (function_declared.find(handle) == function_declared.end() || function_declared[handle] == 0){
            begin[handle] = (pyrebox_target_ulong*) get_var(handle,"begin");
            end[handle] = (pyrebox_target_ulong*) get_var(handle,"end");
            pgd[handle] = (pyrebox_target_ulong*) get_var(handle,"pgd");
            page_status[handle] = std::unordered_set<pyrebox_target_ulong>();

            declare_function(handle, "erase_vars", erase_vars);
            function_declared[handle] = 1;
        }

        int status = 0;

        pyrebox_target_ulong vaddr = params.mem_write_params.vaddr;
        pyrebox_target_ulong page_mask = (((pyrebox_target_ulong) -1) - 0xFFF);

        if ((*(pgd[handle]) == (pyrebox_target_ulong) -1 || *(pgd[handle]) == get_running_process(params.mem_write_params.cpu_index)) &&  vaddr >= *(begin[handle]) && vaddr < *(end[handle])){
            pyrebox_target_ulong page = vaddr & page_mask;
            std::unordered_set<pyrebox_target_ulong>::iterator it = page_status[handle].find(page);
            if (it == page_status[handle].end()){
                page_status[handle].insert(page);
                status = 1;
            }
        }
        return status;
    }
    void clean(callback_handle_t handle)
    {
        //This call will iterate all the variables created, and for those pointing
        //to some memory, it will free the memory. It will erase completely the list
        //of variables.
        erase_trigger_vars(handle); 
    }
}
