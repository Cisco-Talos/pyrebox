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

#include <map>
#include <Python.h>
#include <list>
#include <string>
#include <set>
extern "C"{
    #include "qemu_glue.h"
}
#include "callbacks.h"
#include "trigger_helpers.h"

using namespace std;

map<callback_handle_t,map<string,void*> > trigger_vars;

extern "C"{

void erase_trigger_vars(callback_handle_t handle){
    map<callback_handle_t,map<string,void*> >::iterator it1 = trigger_vars.find(handle); 
    if (it1 != trigger_vars.end())
    {
        map<string,void*>::iterator it2;
        for(it2 = it1->second.begin();it2!=it1->second.end();++it2)
        {
            if(it2->second != 0)
            {
                free(it2->second);
            }
        }
        it1->second.clear();
    }
}

void* get_var(callback_handle_t handle, const char* key_str){
    map<callback_handle_t,map<string,void*> >::iterator it1 = trigger_vars.find(handle); 
    if (it1 != trigger_vars.end())
    {
        string key(key_str);
        if (it1->second.find(key) != it1->second.end())
        {
            return it1->second[key];
        }
    }
    return 0;
}

void set_var(callback_handle_t handle, const char* key_str,void* val){
    map<callback_handle_t,map<string,void*> >::iterator it1 = trigger_vars.find(handle); 
    if (it1 == trigger_vars.end())
    {
        trigger_vars[handle] = map<string,void*>();
    }
    string key(key_str);
    if (trigger_vars[handle].find(key) != trigger_vars[handle].end())
    {
        if(trigger_vars[handle][key] != 0)
        {
            free(trigger_vars[handle][key]);
        }
        trigger_vars[handle].erase(key);
    }
    trigger_vars[handle][key] = val;
}

void delete_var(callback_handle_t handle, const char* key_str, int bool_free){
    map<callback_handle_t,map<string,void*> >::iterator it1 = trigger_vars.find(handle); 
    if (it1 == trigger_vars.end())
    {
        return;
    }
    string key(key_str);
    if (trigger_vars[handle].find(key) != trigger_vars[handle].end())
    {
        if(trigger_vars[handle][key] != 0 && bool_free)
        {
            free(trigger_vars[handle][key]);
        }
        trigger_vars[handle].erase(key);
    }
}

};
