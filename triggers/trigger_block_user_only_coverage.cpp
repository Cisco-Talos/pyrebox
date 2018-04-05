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
extern "C"{
    #include "trigger_helpers.h"
}
#include "utils.h"

extern "C"{
    FILE* f_out = 0;
    std::map<callback_handle_t,FILE*> file_descs;
    std::map<callback_handle_t, std::unordered_set <pyrebox_target_ulong>* > visited_pages;
    //Define trigger type. This type is checked when trigger is loaded
    callback_type_t get_type(){
        return BLOCK_BEGIN_CB;
    }
    //Trigger, return 1 if event should be passed to python callback 
    int trigger(callback_handle_t handle, callback_params_t params){
        //Never return 1, so that we will never execute the python code on every block.
        //Skip any other process
        pyrebox_target_ulong* pgd = (pyrebox_target_ulong*) get_var(handle,"cr3");
        if (get_running_process(params.block_begin_params.cpu_index) != *pgd)
            return 0;

        pyrebox_target_ulong pc = get_tb_addr(params.block_begin_params.tb);
        pyrebox_target_ulong size = get_tb_size(params.block_begin_params.tb);
        pyrebox_target_ulong page_mask = (((pyrebox_target_ulong) -1) - 0xFFF);
#if TARGET_LONG_SIZE == 4
        pyrebox_target_ulong system_space_limit = 0x80000000;
#elif TARGET_LONG_SIZE == 8
        pyrebox_target_ulong system_space_limit = 0xFFFF080000000000;
#else
#error TARGET_LONG_SIZE undefined
#endif
        if (pc <= system_space_limit){

            std::map<callback_handle_t,FILE*>::iterator f_it;
            f_it = file_descs.find(handle);
            FILE* f_out;
            if(f_it != file_descs.end())
            {
                f_out = f_it->second;
            }
            else
            {
                char* log_name = (char*) get_var(handle,"log_name");
                f_out = fopen(log_name,"w");
                file_descs[handle] = f_out;
            }

            fwrite(&(pc),   (size_t)TARGET_LONG_SIZE,1,f_out);
            fwrite(&(size), (size_t)TARGET_LONG_SIZE,1,f_out);

            std::map<callback_handle_t, std::unordered_set <pyrebox_target_ulong>* >::iterator vp_it;
            vp_it = visited_pages.find(handle);
            std::unordered_set <pyrebox_target_ulong> *vp;
            if(vp_it == visited_pages.end())
            {
                vp = new std::unordered_set <pyrebox_target_ulong>();
                visited_pages[handle] = vp;
            }
            else
            {
                vp = vp_it->second;
            }
            pyrebox_target_ulong page = pc & page_mask;

            if (vp->find(page) == vp->end())
            {
                //If we had not visited the page before, fire an event so that
                //the plugin can update the VADs.
                vp->insert(page);
                return 1;
            }
            else{
                return 0;
            }
        }
        return 0;
    }
    void clean(callback_handle_t handle)
    {
        //This call will iterate all the variables created, and for those pointing
        //to some memory, it will free the memory. It will erase completely the list
        //of variables.
        for(std::map<callback_handle_t,FILE*>::iterator f_it = file_descs.begin(); f_it!=file_descs.end(); f_it++)
        {
            if ((f_it->second) != 0)
            {
                fclose(f_it->second);
            }
        }
        file_descs.clear();
        for(std::map<callback_handle_t, std::unordered_set <pyrebox_target_ulong>* >::iterator vp_it = visited_pages.begin(); vp_it!=visited_pages.end();vp_it++)
        {
            std::unordered_set <pyrebox_target_ulong> *vp = vp_it->second;
            if(vp != 0)
            {
                delete vp;
            }
        }
        visited_pages.clear();
        erase_trigger_vars(handle); 
    }
}
