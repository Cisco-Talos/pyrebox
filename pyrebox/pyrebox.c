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

//System includes
#include <sys/time.h>
#include <Python.h>
#include <dlfcn.h>
#include <pthread.h>

//QEMU includes
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

//Includes
#include "qemu_glue.h"
#include "api.h"
#include "process_mgr.h"
#include "config.h"
#include "callbacks.h"
#include "pyrebox.h"
#include "vmi.h"

pthread_mutex_t pyrebox_mutex;

void clear_targets(void){
  clear_monitored_processes();
}

int pyrebox_init(const char *pyrebox_conf_str){

  //Initialize mutex to call python code, which may sometime be thread unsafe
  if (pthread_mutex_init(&pyrebox_mutex, NULL) != 0){      
          perror("Python mutex could not be initialized\n");
          return 1;
  }

  //Initialize callback manager
  InitCallbacks();

  /*Python interface initialization*/
  /*-------------------------------*/
  //Python references
  PyObject* py_main_module, *py_global_dict;
  PyObject* py_init = 0;
  PyObject* py_init_plugins = 0;

  //XXX: Needed as a workaround to a python bug: 
  //https://mail.python.org/pipermail/new-bugs-announce/2008-November/003322.html
  dlopen("libpython2.7.so", RTLD_LAZY | RTLD_GLOBAL);

  Py_Initialize();
  PyObject *sysPath = PySys_GetObject((char*)"path");
  PyObject *path = PyString_FromString(PYREBOX_PATH);
  PyList_Insert(sysPath, 0, path);

  //Register all the interface function for python
  Py_InitModule("c_api", api_methods);
  Py_InitModule("utils_print", utils_methods_print);

  unsigned int length = strlen(PYREBOX_PATH) + strlen("init.py") + 2;
  //More than 4k path should be unreasonable
  assert(length < 4096);
  char* init_fname = (char*)malloc(length);
  if (init_fname == (char*)0){
      printf("Could not allocate space for init path\n");
      return 1;
  }
  snprintf(init_fname,length,"%s/%s",PYREBOX_PATH,"init.py");
  FILE* py_file;
  //Open and execute the Python file
  py_file = fopen(init_fname, "r");
  if (py_file == NULL) {
    if (init_fname){
        free(init_fname);
    }
    perror("Opening init.py failed");
    return 1;
  }
  PyRun_SimpleFile(py_file, init_fname);
  if (init_fname){
      free(init_fname);
  }

  clear_targets();

  // Get a reference to the main module and global dictionary
  py_main_module = PyImport_AddModule("__main__");
  py_global_dict = PyModule_GetDict(py_main_module);

  //Call the initialization function
  PyObject *py_args_tuple;
  PyObject *platform_str = PyString_FromString(target_platform);
  PyObject *root_path_str = PyString_FromString(ROOT_PATH);
  PyObject *volatility_path_str = PyString_FromString(VOLATILITY_PATH);
  PyObject *conf_name_str = PyString_FromString(pyrebox_conf_str);

  py_args_tuple = PyTuple_New(4);
  PyTuple_SetItem(py_args_tuple, 0, platform_str); 
  PyTuple_SetItem(py_args_tuple, 1, root_path_str); 
  PyTuple_SetItem(py_args_tuple, 2, volatility_path_str); 
  PyTuple_SetItem(py_args_tuple, 3, conf_name_str);

  py_init = PyDict_GetItemString(py_global_dict, "init");
  PyObject* vol_profile = PyObject_CallObject(py_init,py_args_tuple);
  if (vol_profile == 0 || vol_profile == Py_None){
      return 1;
  }
  Py_DECREF(py_args_tuple);

  PyObject* vol_prof_repr = PyObject_Repr(vol_profile);
  const char* s = PyString_AsString(vol_prof_repr);
  //Set the vol profile in vmi.cpp
  vmi_init(s);

  // Now, we can decref vol_profile
  Py_XDECREF(vol_profile);

  py_args_tuple = PyTuple_New(0);
  //Now that we initialized the VMI, init the plugins
  py_init_plugins = PyDict_GetItemString(py_global_dict, "init_plugins");
  PyObject* result = PyObject_CallObject(py_init_plugins, py_args_tuple);
  if (result == 0 || result == Py_None){
      return 1;
  }
  // We can decref the args tuple
  Py_DECREF(py_args_tuple);
  // We can decref the result
  Py_XDECREF(result);

  return 0;
};

int pyrebox_finalize(void){
  vm_stop(RUN_STATE_PAUSED);

  clear_targets();

  //Remove all callbacks and clean everything

  FinalizeCallbacks();

  Py_Finalize();

  vm_start();

  return 0;    
}
