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
    #include "utils.h"
}
#include "callbacks.h"
#include "trigger_helpers.h"

extern "C"{
    //Define trigger type. This type is checked when trigger is loaded
    callback_type_t get_type(){
        return CREATEPROC_CB;
    }
    int trigger(callback_handle_t handle, callback_params_t params){

        pyrebox_target_ulong* var1 = (pyrebox_target_ulong*) get_var(handle,"var1");
        pyrebox_target_ulong* var2 = (pyrebox_target_ulong*) get_var(handle,"var2");
        char* var3 = (char*) get_var(handle,"var3");

        if (var1 == 0 || var2 == 0 || var3 == 0)
        {
            utils_print("[!] Some variables not correctly set"); 
        }
        else{
            //Create a python object. This objects reference count is automatically set to 1.
            PyObject* new_var = PyList_New(10);
            pyrebox_target_ulong i;
            for (i = 0; i < 10;i++)
            {
                //PyList_SetItem is adviced over PyList_Append because the latter will increment
                //the reference count of the built value, and therefore it will leak memory
                PyList_SetItem(new_var,i,Py_BuildValue("(i,i)",*var1+(i*2),*var1+(i*2+1)));
            }

            //If this python object is going to be retrieved, or referenced inside the python
            //callback, then its reference count will be automatically decremented. Since at
            //this point the reference count is 1, this object will be garbage collected!
            
            //Therefore, python objects created inside a trigger should be a single-use object that 
            //will be disposed after the first time it is referenced in the python callback.
            //
            //NOTE: USE PYTHON OBJECTS AS A WAY TO PASS PRECOMPUTED INFORMATION TO THE PYTHON
            //CALLBACK THAT IS ABOUT TO BE CALLED, BUT NOT AS A WAY TO STORE INFORMATION
            //BETWEEN CALLS TO THE trigger, BECAUSE THESE PYTHON OBJECTS WILL BE FREED 
            //AUTOMATICALLY ONCE THEY ARE USED INSIDE THE CALLED PYTHON METHOD.

            //Delete the var without freeing its content. 
            //If we call directly to set_var, this function will internally try to free the
            //memory pointed by the PyObject, resulting into potential crashes / undefined behaviour.
            //It is assumed that the variable was referenced in a python function called before,
            //and therefore its reference count was decreased (and potentially garbage collected).
            //Therefore, we don't need to decrement its reference count.
            PyObject* old_var = (PyObject*)get_var(handle,"list0");
            if (old_var != 0)
            {
                //Delete the variable without freeing its memory.
                delete_var(handle,"list0",0);
            }
            //Now, we can set the var
            set_var(handle,"list0",new_var);

            utils_print("Trigger called: var1: %x var2: %x var3: %s\n",*var1,*var2,var3);
        }
        return 1;
    }

    void clean(callback_handle_t handle)
    {
        //In this function we must first decrement reference count and null out 
        //those variables pointing to python objects.
        //Get PyObject*
        PyObject* old_var = (PyObject*)get_var(handle,"list0");
        if (old_var != 0)
        {
            //Delete the var without freeing its content. 
            //If we call directly to set_var, this function will internally try to free the
            //memory pointed by the PyObject, resulting into potential crashes / undefined behaviour.
            //It is assumed that the variable was referenced in a python function called before,
            //and therefore its reference count was decreased (and potentially garbage collected).
            //Therefore, we don't need to decrement its reference count.
            delete_var(handle,"list0",0);
        }
        //This call will iterate all the variables created, and for those pointing
        //to some memory, it will free the memory. It will erase completely the list
        //of variables.
        erase_trigger_vars(handle); 
    }
}
