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

#ifndef TRIGGER_HELPERS_H
#define TRIGGER_HELPERS_H

#ifdef __cplusplus
extern std::map<callback_handle_t,std::map<std::string,void*> > trigger_vars;
extern "C" {
#endif

// Type for a function name that can be called from Python
typedef void (*function_t)(callback_handle_t);

void erase_trigger_vars(callback_handle_t handle);
void* get_var(callback_handle_t handle, const char* key_str);
void set_var(callback_handle_t handle, const char* key_str,void* val);
void delete_var(callback_handle_t handle, const char* key_str,int bool_free);

// Declare a function name that can be triggered from Python
void declare_function(callback_handle_t handle, const char* function_name, function_t function);
void call_function(callback_handle_t handle, const char* function_name);

#ifdef __cplusplus
};
#endif

#endif //TRIGGER_HELPERS_H
