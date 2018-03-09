/*-------------------------------------------------------------------------------

   Copyright (C) 2018 Cisco Talos Security Intelligence and Research Group

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

#define MAX_CALLBACKS 65536

pyrebox_target_ulong vars[MAX_CALLBACKS][2];

static void init() __attribute__((constructor));

void init() {
    for (unsigned int i = 0; i < MAX_CALLBACKS; i++){
        //begin
        vars[i][0] = 0;
        //end
        vars[i][1] = 0;
    }
}

extern "C"{
    //Define trigger type. This type is checked when trigger is loaded
    callback_type_t get_type(){
        return MEM_READ_CB;
    }
    //Trigger, return 1 if event should be passed to python callback 
    int trigger(callback_handle_t handle, callback_params_t params){
        if (handle >= MAX_CALLBACKS){
            printf("Error in trigger_bprh_memrange callback, MAX number of callbacks reached\n");
            return 0;
        }

        // Check if var is initialized by comparing to 0. While begin can be 0, end will
        // never be set to 0.
        if (vars[handle][1] == 0){
            vars[handle][0] = *((pyrebox_target_ulong*) get_var(handle,"begin"));
            vars[handle][1] = *((pyrebox_target_ulong*) get_var(handle,"end"));
        }

        //We don't care about the PGD, just monitor the physical address
        pyrebox_target_ulong addr = params.mem_read_params.haddr;
        if (addr >= vars[handle][0] && addr < vars[handle][1]){
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
