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
#include <map>
#include <list>
#include <string>
#include <set>
#include <vector>

extern "C" {
    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>
    #include <sys/types.h>
    #include <sys/un.h>
    #include <unistd.h>
    #include <signal.h>
    #include <stdint.h>

    #include "qemu_glue.h"
    #include "utils.h"
    #include "qemu_glue_sleuthkit.h"
    #include "qemu_glue_ui.h"
    #include "qemu_glue_gdbstub.h"
}

#include "callbacks.h"
#include "process_mgr.h"
#include "utils.h"
#include "api.h"
#include "vmi.h"

using namespace std;

vector<QEMU_GLUE_TSK_PATH_INFO*> guest_path_handles;

extern "C" {

PyObject* register_callback(PyObject *dummy, PyObject *args){
    PyObject *result = 0;
    PyObject *py_callback;
    unsigned int callback_type = 0xFFFFFFFF;
    pyrebox_target_ulong first_param = (pyrebox_target_ulong) INV_ADDR;
    pyrebox_target_ulong second_param = (pyrebox_target_ulong) INV_PGD;
    module_handle_t module_handle;

    //Parameters: module handle, callback type, callback function, optional address start, optional pgd 
    int parse_tuple_result = 0; 
#if TARGET_LONG_SIZE == 4
    parse_tuple_result = PyArg_ParseTuple(args, "IIO|II", &module_handle, &callback_type, &py_callback,&first_param,&second_param);
#elif TARGET_LONG_SIZE == 8
    parse_tuple_result = PyArg_ParseTuple(args, "IIO|KK", &module_handle, &callback_type, &py_callback,&first_param,&second_param);
#else
#error TARGET_LONG_SIZE undefined
#endif
    if (parse_tuple_result){
        if (!PyCallable_Check(py_callback)) {
            PyErr_SetString(PyExc_TypeError, "[!] Parameter must be callable");
            return 0;
        }
        //First valid callback should always be 0, last callback should be lower than LAST_CB
        if (callback_type >= LAST_CB)
        {
            PyErr_SetString(PyExc_TypeError, "[!] Invalid callback type");
            return 0;
        }
        //Should not reach this point if we have and invalid callback
        callback_type_t casted_callback_type = (callback_type_t) callback_type;
       
        callback_handle_t hdl; 
        if (casted_callback_type == OPCODE_RANGE_CB)
        {
            //First parameter(address) is the start_opcode
            //Second parameter(pgd) is the end_opcode
            
            //Translate extended opcodes to what QEMU understands in the translation switch (see target/i386/translate.c
            //: "reswitch")
            if ((first_param & 0xFF00) == 0x0F00){
                first_param = 0x0100 | (0x00FF & first_param);
            } else {
                first_param &= 0xFFFF;
            }
            if ((second_param & 0xFF00) == 0x0F00){
                second_param = 0x0100 | (0x00FF & second_param);
            } else {
                second_param &= 0xFFFF;
            }

            hdl = add_callback_at(casted_callback_type,module_handle,py_callback,first_param,second_param);
        }
        //Rewrite callback type appropriately
        else if (casted_callback_type == BLOCK_BEGIN_CB || casted_callback_type == INSN_BEGIN_CB){
            if (first_param == (pyrebox_target_ulong) INV_ADDR && second_param == (pyrebox_target_ulong) INV_PGD){
                hdl = add_callback(casted_callback_type,module_handle,py_callback);
            }else{
                if (casted_callback_type == BLOCK_BEGIN_CB){
                    hdl = add_callback_at(OP_BLOCK_BEGIN_CB,module_handle,py_callback,first_param,second_param);
                }
                else if(casted_callback_type == INSN_BEGIN_CB){
                    hdl = add_callback_at(OP_INSN_BEGIN_CB,module_handle,py_callback,first_param,second_param);
                }
                else{
                    //This condition should never be reached
                    PyErr_SetString(PyExc_TypeError, "[!] Invalid callback type");
                    return 0;
                }
            }
        }
        else{
            hdl = add_callback(casted_callback_type,module_handle,py_callback);
        }
        result = Py_BuildValue("I",hdl);
    }
    else{
        PyErr_SetString(PyExc_TypeError, "[!] Could not parse parameters");

    }
    return result;
}

PyObject* unregister_callback(PyObject *dummy, PyObject *args){
    PyObject *result = 0;
    callback_handle_t hdl; 
    if (PyArg_ParseTuple(args, "I", &hdl)){
        remove_callback_deferred(hdl);
        Py_INCREF(Py_None);
        result = Py_None;
    }
    return result;
}

//Read physical memory
PyObject* r_pa(PyObject *dummy, PyObject *args){
    PyObject *result = 0;
    pyrebox_target_ulong addr;
    unsigned int len;
    uint8_t* buffer;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "II", &addr, &len)){
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "KI", &addr, &len)){
#else
#error TARGET_LONG_SIZE undefined
#endif

        //Limit memory size to read to 8k
        if (len > 0x2000)
        {
            PyErr_SetString(PyExc_ValueError, "Incorrect size, it must be between 0 and 0x2000 bytes");
            return 0;
        }
        if (addr + len > get_memory_size()){
            PyErr_SetString(PyExc_ValueError, "Address and size are greater than the memory limit");
            return 0;
        }
        buffer = (uint8_t*) malloc(len * sizeof(uint8_t));
        if (buffer)
        {
            qemu_physical_memory_rw(addr,buffer,len,0);
            result = Py_BuildValue("y#",buffer,len);
            free(buffer);
        }
        else
        {
            PyErr_SetString(PyExc_ValueError, "Could not allocate buffer to read memory");
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: addr,length");
    }
    return result;
}

//Read virtual memory
PyObject* r_va(PyObject *dummy, PyObject *args)
{
    PyObject *result = 0;
    pyrebox_target_ulong addr;
    unsigned int len;
    uint8_t* buffer;
    pyrebox_target_ulong pgd;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "III",&pgd, &addr, &len)){
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "KKI",&pgd, &addr, &len)){
#else
#error TARGET_LONG_SIZE undefined
#endif
        //Limit memory size to read to 8k
        if (len > 0x2000) {
            PyErr_SetString(PyExc_ValueError, "Incorrect size, it must be between 0 and 0x2000 bytes");
        } else{
            buffer = (uint8_t*) malloc(len * sizeof(uint8_t));
            if (buffer) {
                if (qemu_virtual_memory_rw_with_pgd(pgd,addr,buffer,len,0) == 0) {
                    result = Py_BuildValue("y#",buffer,len);
                } else
                {
                    PyErr_SetString(PyExc_RuntimeError, "Could not read memory");
                }
                free(buffer);
            } else
            {
                PyErr_SetString(PyExc_ValueError, "Could not allocate buffer to read memory");
            }
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: pgd,addr,length");
    }
    return result;
}

//Write physical memory
PyObject* w_pa(PyObject *dummy, PyObject *args)
{
    PyObject *result = 0;
    pyrebox_target_ulong addr;
    unsigned int len;
    uint8_t* buffer;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "Iy#", &addr, &buffer,&len)){
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "Ky#", &addr, &buffer,&len)){
#else
#error TARGET_LONG_SIZE undefined
#endif
        //Limit memory size to read to 0x2000
        if (len > 0x2000){
            PyErr_SetString(PyExc_ValueError, "Incorrect size, it must be between 0 and 0x2000 bytes");
            return 0;
        }
        if (addr + len > get_memory_size()){
            PyErr_SetString(PyExc_ValueError, "Address and size are greater than the memory limit");
            return 0;
        }
        if (buffer){
            qemu_physical_memory_rw(addr,buffer,len,1);
            Py_INCREF(Py_None);
            result = Py_None;
        }
        else{
            PyErr_SetString(PyExc_ValueError, "Could not allocate buffer to read memory");
        }
    }
    else{
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: addr,buffer");
    }
    return result;
}

//Write virtual memory
PyObject* w_va(PyObject *dummy, PyObject *args) {
    PyObject *result = 0;
    pyrebox_target_ulong addr;
    unsigned int len;
    uint8_t* buffer;
    pyrebox_target_ulong pgd;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "IIy#",&pgd,&addr, &buffer,&len)){

#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "KKy#",&pgd,&addr, &buffer,&len)){
#else
#error TARGET_LONG_SIZE undefined
#endif
        //Limit memory size to read to 4k
        if (len > 0x2000)
        {
            PyErr_SetString(PyExc_ValueError, "Incorrect size, it must be between 0 and 0x2000 bytes");
        }else{
            if (buffer)
            {
                qemu_virtual_memory_rw_with_pgd(pgd,addr,buffer,len,1);
                Py_INCREF(Py_None);
                result = Py_None;
            }
            else
            {
                PyErr_SetString(PyExc_ValueError, "Could not allocate buffer to read memory");
            }
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: pgd,addr,buffer");
    }
    return result;
}

//Read cpu
PyObject* r_cpu(PyObject *dummy, PyObject *args)
{
    PyObject *result = 0;
    int index;
    if (PyArg_ParseTuple(args, "i",&index)){
        qemu_cpu_opaque_t cpu = get_qemu_cpu(index);
        if (cpu == NULL){
            PyErr_SetString(PyExc_ValueError, "Incorrect cpu index specified");
        }
        else{
            result = get_cpu_state(cpu);
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: cpu_index");
    }
    return result;
}

PyObject* r_ioport(PyObject *dummy, PyObject* args){
    PyObject *result = 0;
    uint16_t port;
    uint8_t size;
    if (PyArg_ParseTuple(args, "HB",&port,&size)){
        if(size != 1 && size != 2 && size != 4) {
            PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: size must be 1, 2 or 4");
        } else {
            uint32_t val = qemu_ioport_read(port,size);
            result = Py_BuildValue("I",val);
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: port,size");
    }
    return result;
}
PyObject* w_ioport(PyObject *dummy, PyObject* args){
    PyObject *result = 0;
    uint16_t port;
    uint8_t size;
    uint32_t val;
    if (PyArg_ParseTuple(args, "HBI",&port,&size,&val)){
        if(size != 1 && size != 2 && size != 4) {
            PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: size must be 1, 2 or 4");
        } else {
            qemu_ioport_write(port,size,val);
            Py_INCREF(Py_None);
            result = Py_None;
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: port,size,val");
    }
    return result;
}

//Write register
PyObject* w_r(PyObject *dummy, PyObject *args)
{
    PyObject *result = 0;
    register_num_t reg_num;
    pyrebox_target_ulong val;
    int index;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "iII",&index,&reg_num,&val)){
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "iIK",&index,&reg_num,&val)){
#else
#error TARGET_LONG_SIZE undefined
#endif
        qemu_cpu_opaque_t cpu = get_qemu_cpu(index);
        if (cpu == NULL){
            PyErr_SetString(PyExc_ValueError, "Incorrect cpu index specified");
        }
        else{
            if (!write_register_convert(cpu,reg_num,val))
            {
                Py_INCREF(Py_None);
                result = Py_None;
            }
            else{
                PyErr_SetString(PyExc_ValueError, "Error writing register");
            }
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: cpu_index, register number, value");
    }
    return result;
}

//Write segment register
PyObject* w_sr(PyObject *dummy, PyObject *args)
{
    PyObject *result = 0;
    register_num_t reg_num;
    uint32_t selector;
    pyrebox_target_ulong base;
    uint32_t limit;
    uint32_t flags;
    int index;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "iIIIII",&index,&reg_num,&selector,&base,&limit,&flags)){
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "iIIKII",&index,&reg_num,&selector,&base,&limit,&flags)){
#else
#error TARGET_LONG_SIZE undefined
#endif
        qemu_cpu_opaque_t cpu = get_qemu_cpu(index);
        if (cpu == NULL){
            PyErr_SetString(PyExc_ValueError, "Incorrect cpu index specified");
        }
        else{
            if (!write_selector_register_convert(cpu,reg_num,selector,base,limit,flags)){
                Py_INCREF(Py_None);
                result = Py_None;
            }
            else{
                PyErr_SetString(PyExc_ValueError, "Error writing register");
            }
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: cpu index, register number, selector, base, limit, flags");
    }
    return result;
}

//Virtual address to physical address
PyObject* va_to_pa(PyObject *dummy, PyObject *args)
{
    PyObject *result = 0;
    pyrebox_target_ulong addr;
    pyrebox_target_ulong pgd;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "II",&pgd, &addr)){
        result = Py_BuildValue("I",qemu_virtual_to_physical_with_pgd(pgd,addr));
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "KK",&pgd, &addr)){
        result = Py_BuildValue("K",qemu_virtual_to_physical_with_pgd(pgd,addr));
#else
#error TARGET_LONG_SIZE undefined
#endif
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: pgd,addr");
    }
    return result;
}
PyObject* start_monitoring_process(PyObject *dummy, PyObject *args){
    PyObject *result = 0;
    pyrebox_target_ulong pgd;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "I",&pgd)){
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "K",&pgd)){
#else
#error TARGET_LONG_SIZE undefined
#endif
        add_monitored_process(pgd);
        Py_INCREF(Py_None);
        result = Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: pgd");
    }
    return result;
}
PyObject* stop_monitoring_process(PyObject *dummy, PyObject *args){
    PyObject *result = 0;
    pyrebox_target_ulong pgd;
    int force = 0;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "Ii",&pgd,&force)){
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "Ki",&pgd,&force)){
#else
#error TARGET_LONG_SIZE undefined
#endif
        remove_monitored_process(pgd,force);
        Py_INCREF(Py_None);
        result = Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: pgd");
    }
    return result;
}
PyObject* py_get_running_process(PyObject *dummy, PyObject *args){
    PyObject *result = 0;
    int cpu_index;
    if (PyArg_ParseTuple(args, "i",&cpu_index)){
#if TARGET_LONG_SIZE == 4
        result = Py_BuildValue("I",get_running_process(cpu_index));
#elif TARGET_LONG_SIZE == 8
        result = Py_BuildValue("K",get_running_process(cpu_index));
#else
#error TARGET_LONG_SIZE undefined
#endif
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: cpu_index");
    }
    return result;
}

PyObject* py_get_num_cpus(PyObject *dummy, PyObject *args){
    PyObject *result = 0;
    result = Py_BuildValue("I",get_num_cpus());
    return result;
}

PyObject* is_kernel_running(PyObject *dummy, PyObject *args){
    int cpu_index;
    if (PyArg_ParseTuple(args, "i", &cpu_index)){
        int result = qemu_is_kernel_running(cpu_index);
        switch(result){
            case 0:
                Py_INCREF(Py_False);
                return Py_False;
            case 1:
                Py_INCREF(Py_True);
                return Py_True;
            case -1:
                PyErr_SetString(PyExc_ValueError, "Incorrect cpu index specified");
                return 0;
        }
    } else {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: cpu_index");
    }
    return 0;
}

PyObject* py_is_monitored_process(PyObject *dummy, PyObject *args){
    pyrebox_target_ulong pgd;
#if TARGET_LONG_SIZE == 4
    if (PyArg_ParseTuple(args, "I",&pgd)){
#elif TARGET_LONG_SIZE == 8
    if (PyArg_ParseTuple(args, "K",&pgd)){
#else
#error TARGET_LONG_SIZE undefined
#endif
        if (is_monitored_process(pgd)){
            Py_INCREF(Py_True);
            return Py_True;
        } else{
            Py_INCREF(Py_False);
            return Py_False;
        }
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameters: cr3");
        return 0;
    }
}

PyObject* save_vm(PyObject *dummy, PyObject *args){
    char* name;
    int length;
    if (PyArg_ParseTuple(args, "s#",&name,&length)){
        pyrebox_save_vm(name);
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect snapshot name");
        return 0;
    }
}
PyObject* load_vm(PyObject *dummy, PyObject *args){
    char* name;
    int length;
    if (PyArg_ParseTuple(args, "s#",&name,&length)){
        pyrebox_load_vm(name);
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect snapshot name");
        return 0;
    }
}
PyObject* py_add_trigger(PyObject *dummy, PyObject *args){
    int handle;
    char* path;
    int length;
    if (PyArg_ParseTuple(args, "Is#",&handle,&path,&length)){
        add_trigger(handle,path);
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect parameters passed to add_trigger");
        return 0;
    }
}
PyObject* py_remove_trigger(PyObject *dummy, PyObject *args){
    int handle;
    if (PyArg_ParseTuple(args, "I",&handle)){
        remove_trigger(handle);
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect parameters passed to remove_trigger");
        return 0;
    }
}

PyObject* set_trigger_uint32(PyObject *dummy, PyObject *args){
    int handle;
    char* str;
    int length;
    uint32_t val;
    if (PyArg_ParseTuple(args, "Is#I",&handle,&str,&length,&val)){
        uint32_t* new_val = (uint32_t*) malloc(sizeof(uint32_t));
        *new_val = (uint32_t)val;
        set_trigger_var(handle,str,new_val);
        Py_INCREF(Py_None);
        return Py_None;
    }
    else{
        PyErr_SetString(PyExc_ValueError, "Incorrect parameters passed to set_trigger_uint32");
        return 0;
    }
}

PyObject* set_trigger_uint64(PyObject *dummy, PyObject *args){
    int handle;
    char* str;
    int length;
    uint64_t val;
    if (PyArg_ParseTuple(args, "Is#K",&handle,&str,&length,&val)){
        uint64_t* new_val = (uint64_t*) malloc(sizeof(uint64_t));
        *new_val = (uint64_t)val;
        set_trigger_var(handle,str,new_val);
        Py_INCREF(Py_None);
        return Py_None;
    }
    else{
        PyErr_SetString(PyExc_ValueError, "Incorrect parameters passed to set_trigger_uint64");
        return 0;
    }
}


PyObject* set_trigger_str(PyObject *dummy, PyObject *args){
    int handle;
    char* str_key;
    int length_key;
    char* str_val;
    int length_val;
    if (PyArg_ParseTuple(args, "Is#s#",&handle,&str_key,&length_key,&str_val,&length_val)){
        char* str_val_copy = (char*) malloc(length_val + 1);
        memset(str_val_copy,0,length_val+1);
        strncpy(str_val_copy,str_val,length_val);
        set_trigger_var(handle,str_key,str_val_copy);
        Py_INCREF(Py_None);
        return Py_None;
    }
    else{
        PyErr_SetString(PyExc_ValueError, "Incorrect parameters passed to set_trigger_str");
        return 0;
    }
}

PyObject* py_get_trigger_var(PyObject *dummy, PyObject *args){
    int handle;
    char* str;
    int length;
    if (PyArg_ParseTuple(args, "Is#",&handle,&str,&length)){
        return (PyObject*) get_trigger_var(handle,str);
    }
    else{
        PyErr_SetString(PyExc_ValueError, "Incorrect parameters passed to get_trigger_var");
        return 0;
    }
}

PyObject* py_call_trigger_function(PyObject *dummy, PyObject *args){
    int handle;
    char* str;
    int length;
    if (PyArg_ParseTuple(args, "Is#",&handle,&str,&length)){
        call_trigger_function(handle,str);
        Py_INCREF(Py_None);
        return Py_None;
    }
    else{
        PyErr_SetString(PyExc_ValueError, "Incorrect parameters passed to call_trigger_function");
        return 0;
    }
}

PyObject* py_vol_get_memory_size(PyObject *dummy, PyObject *args){
    uint64_t size = get_memory_size();
    PyObject *result = Py_BuildValue("K",size);
    return result;
}
PyObject* py_vol_read_memory(PyObject *dummy, PyObject *args){
    uint64_t length;
    uint64_t address;
    uint64_t nbytes;
    PyObject *result = 0;

    if (PyArg_ParseTuple(args, "KK", &address,&length)){
        char *buf = (char*)malloc(length + 1);
        if (buf){
            nbytes = connection_read_memory(address, buf, length);
            if (nbytes != length){
                Py_INCREF(Py_None);
                result = Py_None;
            }
            else{
                result = Py_BuildValue("y#",buf,length);
            }
            free(buf);
        } else{
            PyErr_SetString(PyExc_ValueError, "Could not allocate sufficient memory to perform memory read on py_vol_read_memory");
            return 0;
        }
    }
    return result;
}


PyObject* py_vol_write_memory(PyObject *dummy, PyObject *args){
    uint64_t length;
    uint64_t address;
    uint64_t nbytes;
    PyObject *result = 0;
    unsigned int len;
    char* buffer;
    if (PyArg_ParseTuple(args, "KKy#", &address,&length,&buffer,&len)){
        if (len != length){
            Py_INCREF(Py_None);
            result = Py_None;
        }
        else{
            nbytes = connection_write_memory(address, buffer, length);
            if (nbytes == length){
                Py_INCREF(Py_True);
                return Py_True;
            }
            else{
                Py_INCREF(Py_None);
                result = Py_None;
            }
        }
    }
    return result;
}



//Obtain a list of processes (pid,pgd,name,kernel_addr)
PyObject* get_process_list(PyObject *dummy, PyObject *args)
{
    PyObject *result = 0;
    result = PyList_New(processes.size());
    unsigned int i = 0;
    for(set<Process>::iterator it = processes.begin(); it != processes.end(); ++it)
    {
#if TARGET_LONG_SIZE == 4
        PyList_SetItem(result,i,Py_BuildValue("{sIsIsssI}","pid",it->get_pid(),"pgd",it->get_pgd(),"name",it->get_name(),"kaddr",it->get_kernel_addr()));
#elif TARGET_LONG_SIZE == 8
        PyList_SetItem(result,i,Py_BuildValue("{sKsKsssK}","pid",it->get_pid(),"pgd",it->get_pgd(),"name",it->get_name(),"kaddr",it->get_kernel_addr()));
#else
#error TARGET_LONG_SIZE undefined
#endif
        ++i;
    }
    return result;
}

PyObject* py_print(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    char* str;
    int size;
    if (args_size == 1){
       if (PyArg_ParseTuple(args, "s#", &str,&size)){
           utils_print(str);
           Py_INCREF(Py_None);
           return Py_None;
       }
       else{
           PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
           return 0;
       }
    }
    else{
        PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
        return 0;
    }
    return 0;
}
PyObject* py_print_debug(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    char* str;
    int size;
    if (args_size == 1){
       if (PyArg_ParseTuple(args, "s#", &str,&size)){
           utils_print_debug(str);
           Py_INCREF(Py_None);
           return Py_None;
       }
       else{
           PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
           return 0;
       }
    }
    else{
        PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
        return 0;
    }
    return 0;

}
PyObject* py_print_warning(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    char* str;
    int size;
    if (args_size == 1){
       if (PyArg_ParseTuple(args, "s#", &str,&size)){
           utils_print_warning(str);
           Py_INCREF(Py_None);
           return Py_None;
       }
       else{
           PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
           return 0;
       }
    }
    else{
        PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
        return 0;
    }
    return 0;

}
PyObject* py_print_error(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    char* str;
    int size;
    if (args_size == 1){
       if (PyArg_ParseTuple(args, "s#", &str,&size)){
           utils_print_error(str);
           Py_INCREF(Py_None);
           return Py_None;
       }
       else{
           PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
           return 0;
       }
    }
    else{
        PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
        return 0;
    }
    return 0;

}
PyObject* py_print_plugin(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    char* str;
    int size;
    if (args_size == 1){
       if (PyArg_ParseTuple(args, "s#", &str,&size)){
           utils_print_plugin(str);
           Py_INCREF(Py_None);
           return Py_None;
       }
       else{
           PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
           return 0;
       }
    }
    else{
        PyErr_SetString(PyExc_ValueError, "This internal function only accepts one string argument");
        return 0;
    }
    return 0;
}
PyObject* py_get_os_bits(PyObject *dummy, PyObject *args){
    PyObject* result = 0;
    result = Py_BuildValue("I",arch_bits[os_index]);
    return result;
}

PyObject* py_get_os_kind(PyObject *dummy, PyObject *args){
    PyObject* result = 0;
    if (os_index < LimitWindows)
        result = Py_BuildValue("s","Windows");
    else
        result = Py_BuildValue("s","Linux");
    return result;
}

PyObject* py_import_module(PyObject *dummy, PyObject *args){
    char* name;
    int length;
    if (PyArg_ParseTuple(args, "s#",&name,&length)){

        PyObject* py_main_module, *py_global_dict;
        PyObject* py_import,*py_args_tuple;
        PyObject *module_path = PyUnicode_FromString(name);
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
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameter: module name");
        return 0;
    }
}

PyObject* py_unload_module(PyObject *dummy, PyObject *args){
    unsigned int module_id;
    if (PyArg_ParseTuple(args, "I",&module_id)){
        PyObject* py_main_module, *py_global_dict;
        PyObject* py_import,*py_args_tuple;
        PyObject *module_hdl = PyLong_FromLong(module_id);
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
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameter: module_id");
    }
    return 0;
}

PyObject* py_reload_module(PyObject *dummy, PyObject *args){
    unsigned int module_id;
    if (PyArg_ParseTuple(args, "I",&module_id)){
        PyObject* py_main_module, *py_global_dict;
        PyObject* py_import,*py_args_tuple;
        PyObject *module_hdl = PyLong_FromLong(module_id);
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
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
    {
        PyErr_SetString(PyExc_ValueError, "Incorrect function parameter: module_id");
    }
    return 0;
}

PyObject* py_get_loaded_modules(PyObject *dummy, PyObject *args){
    PyObject* py_main_module, *py_global_dict;
    PyObject* py_import,*py_args_tuple;
    // Get a reference to the main module and global dictionary
    py_main_module = PyImport_AddModule("__main__");
    py_global_dict = PyModule_GetDict(py_main_module);
    //Call the module import function
    py_import = PyDict_GetItemString(py_global_dict, "get_loaded_modules");
    py_args_tuple = PyTuple_New(0);
    PyObject* ret = PyObject_CallObject(py_import,py_args_tuple);
    //Dec ref the argument list
    Py_DECREF(py_args_tuple);
    //Dont decrement the reference for the return, cause we pass
    //it as result
    if (ret){
        return ret;
    } else {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

PyObject* py_get_file_systems(PyObject *dummy, PyObject *args){
    // No input arguments
    PyObject *result = 0;
    int number_of_fs = qemu_glue_tsk_get_number_filesystems();
    result = PyList_New(number_of_fs);
    for(int i = 0; i < number_of_fs; ++i)
    {
        QEMU_GLUE_TSK_FILESYSTEM* fs = qemu_glue_tsk_get_filesystem(i);
        if (fs != NULL){
            PyList_SetItem(result,i,Py_BuildValue("{sIsssK}","index",i,"type",fs->fs_type,"size",fs->size));
            qemu_glue_tsk_free_filesystem(fs);
        } else {
            Py_DECREF(result);
            Py_INCREF(Py_None);
            return Py_None;
        }
    }
    return result;
}
PyObject* py_open_guest_path(PyObject *dummy, PyObject *args){
    int number_of_fs = qemu_glue_tsk_get_number_filesystems();
    Py_ssize_t args_size = PyTuple_Size(args);
    unsigned int fs_number;
    char* str;
    int size;
    if (args_size == 2){
       if (PyArg_ParseTuple(args, "Is#", &fs_number, &str, &size)){
           if (fs_number >= (unsigned int) number_of_fs){
               PyErr_SetString(PyExc_ValueError, "The file system number specified does not refer to a valid file system");
               return 0;
           } else {
               QEMU_GLUE_TSK_PATH_INFO* pi = qemu_glue_tsk_ls(fs_number, str);
               if (pi != NULL){
                   if(pi->type == QEMU_GLUE_TSK_DIR){
                       // It is a directory
                       PyObject* result = PyList_New(pi->info.dir_info.number_of_filenames);
                       for (unsigned int i = 0; i < pi->info.dir_info.number_of_filenames; ++i){
                           PyList_SetItem(result,i,Py_BuildValue("s",pi->info.dir_info.filenames[i]));
                       }
                       //Free the structure
                       qemu_glue_tsk_free_path_info(pi);
                       return result;
                   } else if (pi->type == QEMU_GLUE_TSK_FILE){
                       // Save the path info, and return a handle
                       // Find an empty space on the vector
                       int space_found = 0;
                       unsigned int handle;
                       for(handle = 0; handle < guest_path_handles.size() && space_found == 0; ++handle){
                           if (guest_path_handles[handle] == NULL){
                               space_found = 1;
                           }
                       }
                       if (space_found == 0){
                            handle = guest_path_handles.size(); 
                            guest_path_handles.push_back(pi);
                       } else {
                            guest_path_handles[handle] = pi;
                       }
                       
                       PyObject* result = Py_BuildValue("{sIsKss}", "handle", handle, "size", pi->info.file_info.size, "filename", pi->info.file_info.filename);
                       return result;
                   } else {
                       PyErr_SetString(PyExc_ValueError, "Unsupported PATH_INFO type");
                       return 0;
                   }
               } else {
                   PyErr_SetString(PyExc_ValueError, "The file or directory specified may not exist");
                   return 0;
               }
           }
       }
       else{
           PyErr_SetString(PyExc_ValueError, "This internal function accepts one int and one string argument");
           return 0;
       }
    }
    else{
        PyErr_SetString(PyExc_ValueError, "This internal function accepts one int and one string argument");
        return 0;
    }
    return 0;
}
PyObject* py_read_guest_file(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    unsigned int handle;
    uint64_t offset;
    uint32_t size;
    if (args_size == 3){
       if (PyArg_ParseTuple(args, "IKI", &handle, &offset, &size)){
           if (handle >= guest_path_handles.size() || guest_path_handles[handle] == NULL){
               PyErr_SetString(PyExc_ValueError, "The path handle specified is either closed or invalid");
               return 0;
           } else {
               char* buffer = (char*)malloc(size);
               if (buffer != NULL){
                   uint32_t bytes_read = qemu_glue_tsk_read_file(guest_path_handles[handle], offset, size, buffer);
                   if (bytes_read == 0 || bytes_read > size){
                       free(buffer);
                       PyErr_SetString(PyExc_ValueError, "Error while reading data, could not read any bytes.");
                       return 0;
                   } else {
                        return Py_BuildValue("y#", buffer, bytes_read);
                   }
               } else {
                   PyErr_SetString(PyExc_ValueError, "Could not allocate buffer for reading data");
                   return 0;
               }
           }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts a handle, an offset, and a size.");
           return 0;
     }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts a handle, an offset, and a size.");
           return 0;
     }
}

PyObject* py_close_guest_path(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    unsigned int handle;
    if (args_size == 1){
       if (PyArg_ParseTuple(args, "I", &handle)){
           if (handle >= guest_path_handles.size() || guest_path_handles[handle] == NULL){
               PyErr_SetString(PyExc_ValueError, "The path handle specified is either closed or invalid");
               return 0;
           } else {
               qemu_glue_tsk_free_path_info(guest_path_handles[handle]);
               guest_path_handles[handle] = NULL;
               Py_INCREF(Py_None);
               return Py_None;
           }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts one int argument");
           return 0;
     }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts one int argument");
           return 0;
     }
}


PyObject* py_x86_get_pte(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    pyrebox_target_ulong pgd;
    pyrebox_target_ulong addr;
    if (args_size == 2){
#if TARGET_LONG_SIZE == 4
        if (PyArg_ParseTuple(args, "II",&pgd, &addr)){
#elif TARGET_LONG_SIZE == 8
        if (PyArg_ParseTuple(args, "KK",&pgd, &addr)){
#else
#error TARGET_LONG_SIZE undefined
#endif
           pyrebox_target_ulong pte = x86_get_pte(pgd, addr);
           if (pte == (pyrebox_target_ulong)-1){
               Py_INCREF(Py_None);
               return Py_None;
           } else {
#if TARGET_LONG_SIZE == 4
               return Py_BuildValue("I", pte);
#elif TARGET_LONG_SIZE == 8
               return Py_BuildValue("K", pte);
#else
#error TARGET_LONG_SIZE undefined
#endif
           }
         } else {
               PyErr_SetString(PyExc_ValueError, "This internal function accepts 2 arguments: pgd and address");
               return 0;
         }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts 2 arguments: pgd and address");
           return 0;
     }
}

PyObject* py_x86_is_pae(PyObject *dummy, PyObject *args){
   int is_pae = x86_is_pae();
   if (is_pae){
        Py_INCREF(Py_True);
        return Py_True;
   } else {
        Py_INCREF(Py_False);
        return Py_False;
   }
}

PyObject* py_mouse_move(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    int dx;
    int dy;
    int dz;
    if (args_size == 3){
        if (PyArg_ParseTuple(args, "iii", &dx, &dy, &dz)){
           pyrebox_mouse_move(dx, dy, dz);
           Py_INCREF(Py_True);
           return Py_True;
         } else {
               PyErr_SetString(PyExc_ValueError, "This internal function accepts 3 arguments: dx, dy, dz");
               return 0;
         }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts 3 arguments: dx, dy, dz");
           return 0;
     }
}

PyObject* py_mouse_button(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    //1=L, 2=M, 4=R
    int button_state;
    if (args_size == 1){
        if (PyArg_ParseTuple(args, "i", &button_state)){
           if (button_state == 1 || button_state == 2 || button_state == 4){
               pyrebox_mouse_button(button_state);
               Py_INCREF(Py_True);
               return Py_True;
           }
           else {
               PyErr_SetString(PyExc_ValueError, "This internal function accepts 1 argument: button_state (1, 2, 4)");
               return 0;
           }
         } else {
               PyErr_SetString(PyExc_ValueError, "This internal function accepts 1 argument: button_state (1, 2, 4)");
               return 0;
         }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts 1 argument: button_state (1, 2, 4)");
           return 0;
     }
}

PyObject* py_send_key(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    char* keys;
    unsigned int length = 0;
    int hold_time;
    if (args_size == 2){
        if (PyArg_ParseTuple(args, "s#i", &keys, &length, &hold_time)){
           pyrebox_sendkeys(keys, hold_time);
           Py_INCREF(Py_True);
           return Py_True;
         } else {
               PyErr_SetString(PyExc_ValueError, "This internal function accepts 2 arguments: keys, hold_time");
               return 0;
         }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts 2 arguments: keys, hold_time");
           return 0;
     }
}

PyObject* py_screendump(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    char* filename;
    unsigned int length;
    if (args_size == 1){
        if (PyArg_ParseTuple(args, "s#", &filename, &length)){
           pyrebox_screendump(filename);
           Py_INCREF(Py_True);
           return Py_True;
         } else {
               PyErr_SetString(PyExc_ValueError, "This internal function accepts 1 argument: filename");
               return 0;
         }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts 1 argument: filename");
           return 0;
     }
}

PyObject* py_gdb_signal_breakpoint(PyObject *dummy, PyObject *args){
    Py_ssize_t args_size = PyTuple_Size(args);
    unsigned long long thread;
    if (args_size == 1){
        if (PyArg_ParseTuple(args, "K", &thread)){
           gdb_signal_breakpoint(thread);
           Py_INCREF(Py_True);
           return Py_True;
         } else {
               PyErr_SetString(PyExc_ValueError, "This internal function accepts 1 argument: thread");
               return 0;
         }
     } else {
           PyErr_SetString(PyExc_ValueError, "This internal function accepts 1 argument: thread");
           return 0;
     }
}

PyMethodDef api_methods[] = {
      {"register_callback", register_callback, METH_VARARGS, "register_callback"}, 
      {"unregister_callback", unregister_callback, METH_VARARGS, "unregister_callback"},
      {"r_pa",r_pa, METH_VARARGS, "r_pa"},
      {"r_va",r_va, METH_VARARGS, "r_va"},
      {"r_cpu",r_cpu, METH_VARARGS, "r_cpu"},
      {"w_pa",w_pa, METH_VARARGS, "w_pa"},
      {"w_va",w_va, METH_VARARGS, "w_va"},
      {"w_r",w_r, METH_VARARGS, "w_r"},
      {"w_sr",w_sr, METH_VARARGS, "w_sr"},
      {"r_ioport",r_ioport,METH_VARARGS,"r_ioport"},
      {"w_ioport",w_ioport,METH_VARARGS,"w_ioport"},
      {"va_to_pa",va_to_pa, METH_VARARGS, "va_to_pa"},
      {"start_monitoring_process",start_monitoring_process, METH_VARARGS, "start_monitoring_process"},
      {"is_monitored_process",py_is_monitored_process, METH_VARARGS, "is_monitored_process"},
      {"stop_monitoring_process",stop_monitoring_process, METH_VARARGS, "stop_monitoring_process"},
      {"get_running_process",py_get_running_process, METH_VARARGS, "get_running_process"},
      {"is_kernel_running",is_kernel_running, METH_VARARGS, "is_kernel_running"},
      {"save_vm",save_vm, METH_VARARGS, "save_vm"},
      {"load_vm",load_vm, METH_VARARGS, "load_vm"},
      {"add_trigger",py_add_trigger, METH_VARARGS, "add_trigger"},
      {"remove_trigger",py_remove_trigger, METH_VARARGS, "remove_trigger"},
      {"set_trigger_uint32",set_trigger_uint32, METH_VARARGS, "set_trigger_uint32"},
      {"set_trigger_uint64",set_trigger_uint64, METH_VARARGS, "set_trigger_uint64"},
      {"set_trigger_str",set_trigger_str, METH_VARARGS, "set_trigger_str"},
      {"get_trigger_var",py_get_trigger_var, METH_VARARGS, "get_trigger_var"},
      {"call_trigger_function",py_call_trigger_function, METH_VARARGS, "call_trigger_function"},
      {"vol_get_memory_size",py_vol_get_memory_size, METH_VARARGS, "vol_get_memory_size"},
      {"vol_read_memory",py_vol_read_memory, METH_VARARGS, "vol_read_memory"},
      {"vol_write_memory",py_vol_write_memory, METH_VARARGS, "vol_write_memory"},
      {"get_process_list",get_process_list, METH_VARARGS, "get_process_list"},
      {"get_num_cpus",py_get_num_cpus, METH_VARARGS, "get_num_cpus"},
      {"plugin_print_internal",py_print_plugin, METH_VARARGS, "plugin_print_internal"},
      {"get_os_bits",py_get_os_bits,METH_VARARGS,"get_os_bits"},
      {"get_os_kind",py_get_os_kind,METH_VARARGS,"get_os_kind"},
      {"import_module",py_import_module,METH_VARARGS,"import_module"},
      {"unload_module",py_unload_module,METH_VARARGS,"unload_module"},
      {"reload_module",py_reload_module,METH_VARARGS,"reload_module"},
      {"get_loaded_modules",py_get_loaded_modules, METH_VARARGS, "get_loaded_modules"},
      {"get_file_systems", py_get_file_systems, METH_VARARGS, "get_file_systems"},
      {"open_guest_path", py_open_guest_path, METH_VARARGS, "open_guest_path"},
      {"read_guest_file", py_read_guest_file, METH_VARARGS, "read_guest_file"},
      {"close_guest_path", py_close_guest_path, METH_VARARGS, "close_guest_path"},
      {"x86_get_pte", py_x86_get_pte, METH_VARARGS, "x86_get_pte"},
      {"x86_is_pae", py_x86_is_pae, METH_VARARGS, "x86_is_pae"},
      {"mouse_move", py_mouse_move, METH_VARARGS, "mouse_move"},
      {"mouse_button", py_mouse_button, METH_VARARGS, "mouse_button"},
      {"send_key", py_send_key, METH_VARARGS, "send_key"},
      {"screendump", py_screendump, METH_VARARGS, "screendump"},
      {"gdb_signal_breakpoint", py_gdb_signal_breakpoint, METH_VARARGS, "gdb_signal_breakpoint"},
      { NULL, NULL, 0, NULL }
    };

PyMethodDef utils_methods_print[] = {
      {"prnt",py_print, METH_VARARGS, "prnt"},
      {"debug",py_print_debug, METH_VARARGS, "debug"},
      {"warning",py_print_warning, METH_VARARGS, "warning"},
      {"error",py_print_error, METH_VARARGS, "error"},
      { NULL, NULL, 0, NULL }
    };
};
