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

#include <Python.h>
#include <pthread.h>

//QEMU dependencies
#include "qemu/queue.h"
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/option.h"
#include "migration/vmstate.h"
#include "sysemu/sysemu.h"
#include "monitor/monitor.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "qemu_glue.h"
#include "callbacks.h"
#include "qemu_commands.h"
#include "pyrebox.h"
#include "qemu_glue_gdbstub.h"

void import_module(Monitor* mon, const QDict* qdict)
{
  if ((qdict != NULL) && (qdict_haskey(qdict, "modulename")))
  {
   PyObject* py_module_name = PyUnicode_FromString("init");
   PyObject* py_init_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);
   PyObject *module_path = PyUnicode_FromString(qdict_get_str(qdict, "modulename"));

   if(py_init_module != NULL){
       PyObject* py_func = PyObject_GetAttrString(py_init_module, "import_module");
       if (py_func){
           if (PyCallable_Check(py_func)){
                PyObject* py_args = PyTuple_New(1);
                PyTuple_SetItem(py_args, 0, module_path); 
                PyObject* ret = PyObject_CallObject(py_func, py_args);
                Py_DECREF(py_args);
                if (ret){
                    Py_DECREF(ret);
                }
           }
           Py_XDECREF(py_func);
       }
       Py_DECREF(py_init_module);
   }
  }
}

void unload_module(Monitor* mon, const QDict* qdict)
{

  if ((qdict != NULL) && (qdict_haskey(qdict, "modulehandle")))
  {
   PyObject* py_module_name = PyUnicode_FromString("init");
   PyObject* py_init_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);
   PyObject *module_hdl = PyLong_FromLong(qdict_get_int(qdict, "modulehandle"));

   if(py_init_module != NULL){
       PyObject* py_func = PyObject_GetAttrString(py_init_module, "unload_module");
       if (py_func){
           if (PyCallable_Check(py_func)){
                PyObject* py_args = PyTuple_New(1);
                PyTuple_SetItem(py_args, 0, module_hdl); 
                PyObject* ret = PyObject_CallObject(py_func, py_args);
                Py_DECREF(py_args);
                if (ret){
                    Py_DECREF(ret);
                }
           }
           Py_XDECREF(py_func);
       }
       Py_DECREF(py_init_module);
   }
   commit_deferred_callback_removes();
  }
}

void reload_module(Monitor* mon, const QDict* qdict)
{
  if ((qdict != NULL) && (qdict_haskey(qdict, "modulehandle")))
  {
   PyObject* py_module_name = PyUnicode_FromString("init");
   PyObject* py_init_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);
   PyObject *module_hdl = PyLong_FromLong(qdict_get_int(qdict, "modulehandle"));

   if(py_init_module != NULL){
       PyObject* py_func = PyObject_GetAttrString(py_init_module, "reload_module");
       if (py_func){
           if (PyCallable_Check(py_func)){
                PyObject* py_args = PyTuple_New(1);
                PyTuple_SetItem(py_args, 0, module_hdl); 
                PyObject* ret = PyObject_CallObject(py_func, py_args);
                Py_DECREF(py_args);
                if (ret){
                    Py_DECREF(ret);
                }
           }
           Py_XDECREF(py_func);
       }
       Py_DECREF(py_init_module);
   }
   commit_deferred_callback_removes();
  }
}

void list_modules(Monitor* mon, const QDict* qdict)
{
   PyObject* py_module_name = PyUnicode_FromString("init");
   PyObject* py_init_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);

   if(py_init_module != NULL){
       PyObject* py_func = PyObject_GetAttrString(py_init_module, "list_modules");
       if (py_func){
           if (PyCallable_Check(py_func)){
                PyObject* py_args = PyTuple_New(0);
                PyObject* ret = PyObject_CallObject(py_func, py_args);
                Py_DECREF(py_args);
                if (ret){
                    Py_DECREF(ret);
                }
           }
           Py_XDECREF(py_func);
       }
       Py_DECREF(py_init_module);
   }
}

void pyrebox_shell(Monitor* mon, const QDict* qdict)
{
   PyObject* py_module_name = PyUnicode_FromString("init");
   PyObject* py_init_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);

   if(py_init_module != NULL){
       PyObject* py_shell = PyObject_GetAttrString(py_init_module, "pyrebox_ipython_shell");
       if (py_shell){
           if (PyCallable_Check(py_shell)){
                PyObject* py_args = PyTuple_New(0);
                PyObject* ret = PyObject_CallObject(py_shell, py_args);
                Py_DECREF(py_args);
                if (ret){
                    Py_DECREF(ret);
                }
           }
           Py_XDECREF(py_shell);
       }
       Py_DECREF(py_init_module);
   }
}

void pyrebox_gdbserver(Monitor* mon, const QDict* qdict){
    if ((qdict != NULL) && (qdict_haskey(qdict, "port")))
    {
        pyrebox_gdbserver_start(qdict_get_int(qdict, "port"));
    }
}

void signal_breakpoint(Monitor* mon, const QDict* qdict){
    if ((qdict != NULL) && (qdict_haskey(qdict, "thread")))
    {
        gdb_signal_breakpoint(qdict_get_int(qdict, "thread"));
    }

}
