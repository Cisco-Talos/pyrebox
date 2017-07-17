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
    //Define trigger type. This type is checked when trigger is loaded
    callback_type_t get_type(){
        return OPCODE_RANGE_CB;
    }
    //Trigger, return 1 if event should be passed to python callback 
    int trigger(callback_handle_t handle, callback_params_t params){
        pyrebox_target_ulong* pgd = (pyrebox_target_ulong*) get_var(handle,"cr3");
#if TARGET_LONG_SIZE == 4
        pyrebox_target_ulong system_space_limit = 0x80000000;
#elif TARGET_LONG_SIZE == 8
        pyrebox_target_ulong system_space_limit = 0xFFFF080000000000;
#else
#error TARGET_LONG_SIZE undefined
#endif
        //Only user-space -> user-space transitions
        if (get_pgd(params.opcode_range_params.cpu) == *pgd && params.opcode_range_params.cur_pc < system_space_limit && params.opcode_range_params.next_pc < system_space_limit){
            return 1;
        }
        return 0;
    }
    void clean(callback_handle_t handle)
    {
        //This call will iterate all the variables created, and for those pointing
        //to some memory, it will free the memory. It will erase completely the list
        //of variables.
        erase_trigger_vars(handle); 
    }
}
