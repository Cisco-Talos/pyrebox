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
#include "qapi-types.h"
#include "sysemu/sysemu.h"
#include "monitor/monitor.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "qemu_glue.h"
#include "callbacks.h"
#include "qemu_commands.h"
#include "pyrebox.h"

void import_module(Monitor* mon, const QDict* qdict)
{

  if ((qdict != NULL) && (qdict_haskey(qdict, "modulename")))
  {
    PyObject* py_main_module, *py_global_dict;
    PyObject* py_import,*py_args_tuple;
    PyObject *module_path = PyString_FromString(qdict_get_str(qdict, "modulename"));
    // Get a reference to the main module and global dictionary
    py_main_module = PyImport_AddModule("__main__");
    py_global_dict = PyModule_GetDict(py_main_module);
    //Call the module import function
    py_import = PyDict_GetItemString(py_global_dict, "import_module");
    py_args_tuple = PyTuple_New(1);
    PyTuple_SetItem(py_args_tuple, 0, module_path); 
    PyObject* ret = PyObject_CallObject(py_import,py_args_tuple);
    Py_XDECREF(ret);
    Py_DECREF(py_args_tuple);
  }

}

void unload_module(Monitor* mon, const QDict* qdict)
{

  if ((qdict != NULL) && (qdict_haskey(qdict, "modulehandle")))
  {
    PyObject* py_main_module, *py_global_dict;
    PyObject* py_import,*py_args_tuple;
    PyObject *module_hdl = PyInt_FromLong(qdict_get_int(qdict, "modulehandle"));
    // Get a reference to the main module and global dictionary
    py_main_module = PyImport_AddModule("__main__");
    py_global_dict = PyModule_GetDict(py_main_module);
    //Call the module import function
    py_import = PyDict_GetItemString(py_global_dict, "unload_module");
    py_args_tuple = PyTuple_New(1);
    PyTuple_SetItem(py_args_tuple, 0, module_hdl); 
    PyObject* ret = PyObject_CallObject(py_import,py_args_tuple);
    Py_XDECREF(ret);
    Py_DECREF(py_args_tuple);
    commit_deferred_callback_removes();
  }

}

void reload_module(Monitor* mon, const QDict* qdict)
{
  if ((qdict != NULL) && (qdict_haskey(qdict, "modulehandle")))
  {
    PyObject* py_main_module, *py_global_dict;
    PyObject* py_import,*py_args_tuple;
    PyObject *module_hdl = PyInt_FromLong(qdict_get_int(qdict, "modulehandle"));
    // Get a reference to the main module and global dictionary
    py_main_module = PyImport_AddModule("__main__");
    py_global_dict = PyModule_GetDict(py_main_module);
    //Call the module import function
    py_import = PyDict_GetItemString(py_global_dict, "reload_module");
    py_args_tuple = PyTuple_New(1);
    PyTuple_SetItem(py_args_tuple, 0, module_hdl); 
    PyObject* ret = PyObject_CallObject(py_import,py_args_tuple);
    Py_XDECREF(ret);
    Py_DECREF(py_args_tuple);
    commit_deferred_callback_removes();
  }
}

void list_modules(Monitor* mon, const QDict* qdict)
{

    PyObject* py_main_module, *py_global_dict;
    PyObject* py_import;//,*py_args_tuple;
    // Get a reference to the main module and global dictionary
    py_main_module = PyImport_AddModule("__main__");
    py_global_dict = PyModule_GetDict(py_main_module);
    //Call the module import function
    py_import = PyDict_GetItemString(py_global_dict, "list_modules");
    PyObject* ret = PyObject_CallObject(py_import,0);
    Py_XDECREF(ret);

}

void pyrebox_shell(Monitor* mon, const QDict* qdict)
{
    PyObject* py_main_module, *py_global_dict;
    PyObject* py_import;//,*py_args_tuple;
    // Get a reference to the main module and global dictionary
    py_main_module = PyImport_AddModule("__main__");
    py_global_dict = PyModule_GetDict(py_main_module);
    //Call the module import function
    py_import = PyDict_GetItemString(py_global_dict, "pyrebox_ipython_shell");
    PyObject* ret = PyObject_CallObject(py_import,0);
    Py_XDECREF(ret);
}
