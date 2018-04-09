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
#include <list>
#include <set>
#include <dlfcn.h>
#include <pthread.h>

extern "C" {
#include "qemu_glue.h"
#include "pyrebox.h"
#include "utils.h"
#include "qemu_glue_callbacks_flush.h"
#include "pyrebox.h"
}
#include "process_mgr.h"
#include "callbacks.h"
#include "vmi.h"

using namespace std;

extern "C" {

//Handle counter. Starts at 1. 0 is the invalid handle
callback_handle_t callback_handle_counter = 1;

//Array of internal callbacks
internal_callbacks_t internal_callbacks[MAX_INTERNAL_CALLBACKS];
internal_callback_handle_t current_internal_callback_handle = 0;

//CallbackManager class initialization 

//Reference to callback manager
CallbackManager* cb_manager = 0;

void InitCallbacks(){
    cb_manager = new CallbackManager();
    for (int i = 0; i < MAX_INTERNAL_CALLBACKS; ++i){
        internal_callbacks[i] = {.pgd = 0,
                                 .pc = 0,
                                 .callback_function = 0};
    }
}

void FinalizeCallbacks(){
    if (cb_manager != 0)
    {
        delete cb_manager;
        cb_manager = 0;
    }
}

//----------------------------------------------------------------------------------------------
//                           C interface for callback manager
//----------------------------------------------------------------------------------------------

void remove_callback(callback_handle_t handle){
    if (cb_manager != 0) {
        cb_manager->remove_callback(handle); 
    }
    return;
}
void add_trigger(callback_handle_t callback_handle,char* trigger_path){
    if (cb_manager != 0) {
        cb_manager->add_trigger(callback_handle,trigger_path);
    }
    return;
}
void remove_trigger(callback_handle_t callback_handle){
    if (cb_manager != 0) {
        cb_manager->remove_trigger(callback_handle);
    }
    return;
}
void set_trigger_var(callback_handle_t callback_handle,const char* var,void* val){
    if (cb_manager != 0) {
        cb_manager->set_trigger_var(callback_handle,var,val); 
    }
    return;
}
void* get_trigger_var(callback_handle_t callback_handle,const char* var){
    if (cb_manager != 0) {
        return cb_manager->get_trigger_var(callback_handle,var); 
    }
    return 0;
}

void remove_callback_deferred(callback_handle_t handle){
    if (cb_manager != 0) {
        cb_manager->remove_callback_deferred(handle);
    }
    return;
}
void commit_deferred_callback_removes(){
    if (cb_manager != 0) {
        cb_manager->commit_deferred_callback_removes();
    }
    return;
}

callback_handle_t add_callback_at(callback_type_t type, module_handle_t module_handle, PyObject* callback_function, pyrebox_target_ulong address, pyrebox_target_ulong pgd){
    if (cb_manager != 0) {
        return cb_manager->add_callback(type,module_handle,callback_function,address,pgd); 
    }
    else{
        return 0;
    }
}
callback_handle_t add_callback(callback_type_t type, module_handle_t module_handle, PyObject* callback_function){
    if (cb_manager != 0) {
        return cb_manager->add_callback(type,module_handle,callback_function,0);
    }
    else{
        return 0;
    }
}

//----------------------------------------------------------------------------------
// Internal callback management functions
//----------------------------------------------------------------------------------

internal_callback_handle_t add_internal_callback(pyrebox_target_ulong pgd, pyrebox_target_ulong pc, callback_t callback_function){
    //We already reached the maximum number of internal callbacks
    if (current_internal_callback_handle < MAX_INTERNAL_CALLBACKS){
        internal_callbacks[current_internal_callback_handle++] = {.pgd = pgd,
                                                                .pc = pc,
                                                                .callback_function = callback_function};
        return (current_internal_callback_handle-1);
    }
    return (internal_callback_handle_t) -1;
}

//----------------------------------------------------------------------------------
//Callback functions, that are delivered to their corresponding python callbacks
//----------------------------------------------------------------------------------

void block_begin_callback(callback_params_t params)
{
   if (cb_manager != 0) {
    cb_manager->deliver_callback(BLOCK_BEGIN_CB,params);
   }
}

void block_end_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(BLOCK_END_CB,params);
   }
}

void insn_begin_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(INSN_BEGIN_CB,params);
   }
}

void insn_end_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(INSN_END_CB,params);
   }
}

void mem_read_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(MEM_READ_CB, params);
   }
}

void mem_write_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(MEM_WRITE_CB, params);
   }
}

void keystroke_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(KEYSTROKE_CB,params);
   }
}

void nic_rec_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(NIC_REC_CB,params);
   }
}

void nic_send_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(NIC_SEND_CB,params);
   }
}

void opcode_range_callback(callback_params_t params)
{
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(OPCODE_RANGE_CB,params);
   }
}

void tlb_exec_callback(callback_params_t params)
{
   qemu_cpu_opaque_t cpu_opaque = params.tlb_exec_params.cpu;
   pyrebox_target_ulong cr3 = get_pgd(cpu_opaque);
   //VMI related actions
   vmi_tlb_callback(cr3, params.tlb_exec_params.vaddr);
   
   //Deliver the python callbacks
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(TLB_EXEC_CB,params);
   }
}

void create_proc_callback(callback_params_t params)
{
   //Deliver the python callbacks
   if (cb_manager != 0)
   {
    cb_manager->deliver_callback(CREATEPROC_CB, params);
   }
}

void remove_proc_callback(callback_params_t params)
{
    //Update monitored processes
    pyrebox_target_ulong pgd = params.vmi_remove_proc_params.pgd;
    remove_monitored_process(pgd,1);
    //Deliver callback
    if (cb_manager != 0)
    {
        cb_manager->deliver_callback(REMOVEPROC_CB, params);
    }
}
void context_change_callback(callback_params_t params)
{
    //Trigger the necessary vmi updates on context change
    pyrebox_target_ulong pgd = params.vmi_context_change_params.new_pgd;
    vmi_context_change(params.vmi_context_change_params.old_pgd,pgd);
    //Deliver callback
    if (cb_manager != 0)
    {
        cb_manager->deliver_callback(CONTEXTCHANGE_CB, params);
    }
}


//Determine if a callback is needed for a given callback type and position
int is_callback_needed(callback_type_t callback_type, pyrebox_target_ulong address, pyrebox_target_ulong pgd){
    return (cb_manager->is_callback_needed(callback_type,address,pgd));
}

}; // extern "C" 


callback_handle_t CallbackManager::add_callback(callback_type_t type, module_handle_t module_handle, PyObject* callback_function, pyrebox_target_ulong address){
    return this->add_callback(type,module_handle,callback_function,address,0);
}

void CallbackManager::set_trigger_var(callback_handle_t callback_handle,const char* var,void*val){
    multiset<Callback*,CompareCallbackP>::iterator it;
    int i;
    int found = 0;
    for (i = 0; found == 0 && i<LAST_CB;i++)
    {
        for (it = this->callbacks[i].begin();it!=this->callbacks[i].end();++it)
        {
            if ((*it)->get_handle() == callback_handle)
            {
                found = 1;
                break;
            }
        }
        if (found == 1){
            //Break to avoid incrementing i
            break;
        }
    }
    if (found == 0)
    {
        utils_print_error("[!] Could not set trigger var on unregistered callback handle %x\n",callback_handle);
        return;
    }
    //iterator points to the callback.
    //We first fetch the set_var method from the plugin.
    if ((*it)->get_dll_handle() == 0)
    {
        utils_print_error("[!] Cannot update variable on unloaded trigger\n");
        return;
    }
    set_var_t func = (set_var_t)dlsym((*it)->get_dll_handle(),"set_var");
    if (func == 0)
    {
        utils_print_error("[!] Could not fetch set_var function from plugin\n");
        return;
    }
    //Call the function
    func(callback_handle,var,val);
}
void* CallbackManager::get_trigger_var(callback_handle_t callback_handle,const char* var){
    multiset<Callback*,CompareCallbackP>::iterator it;
    int i;
    int found = 0;
    for (i = 0; found == 0 && i<LAST_CB;i++)
    {
        for (it = this->callbacks[i].begin();it!=this->callbacks[i].end();++it)
        {
            if ((*it)->get_handle() == callback_handle)
            {
                found = 1;
                break;
            }
        }
        if (found == 1){
            //Break to avoid incrementing i
            break;
        }
    }
    if (found == 0)
    {
        utils_print_error("[!] Could not get trigger on unregistered callback handle %x\n",callback_handle);
        return 0;
    }
    //iterator points to the callback.
    //We first fetch the set_var method from the plugin.
    if ((*it)->get_dll_handle() == 0)
    {
        utils_print_error("[!] Cannot update variable on unloaded trigger\n");
        return 0;
    }
    get_var_t func = (get_var_t)dlsym((*it)->get_dll_handle(),"get_var");
    if (func == 0)
    {
        utils_print_error("[!] Could not fetch get_var function from plugin\n");
        return 0;
    }
    //Call the function
    return func(callback_handle,var);
}

void CallbackManager::add_trigger(callback_handle_t callback_handle,char* trigger_path){
    //Locate callback entry
    multiset<Callback*,CompareCallbackP>::iterator it;
    int i;
    int found = 0;
    for (i = 0; found == 0 && i<LAST_CB;i++)
    {
        for (it = this->callbacks[i].begin();it!=this->callbacks[i].end();++it)
        {
            if ((*it)->get_handle() == callback_handle)
            {
                found = 1;
                break;
            }
        }
        if (found == 1){
            //Break to avoid incrementing i
            break;
        }
    }
    if (found == 0)
    {
        utils_print_error("[!] Could not set trigger on unregistered callback handle %x\n",callback_handle);
        return;
    }
    //iterator (it) points to the callback structure
    if((*it)->get_trigger() != (trigger_t)0)
    {
        utils_print_debug("[!] Removing existing trigger %llx on callback...\n",(*it)->get_trigger());
        this->remove_trigger(callback_handle);
    }
    //Load dll
    void* dll_handle = dlopen(trigger_path,RTLD_NOW|RTLD_LOCAL);
    if (!dll_handle)
    {
        utils_print_error("[!] Error while loading %s\n",trigger_path);
        utils_print_error("%s\n", dlerror());
        return;
    }
    trigger_get_type_t get_func_type = (trigger_get_type_t) dlsym(dll_handle,"get_type");
    if (get_func_type != 0 && get_func_type() == i)
    {
        //Load symbol
        void* func = dlsym(dll_handle,"trigger");
        if (!func)
        {
            utils_print_error("[!] Could not find function trigger in %s\n",trigger_path);
            return;
        }
        //Update trigger
        (*it)->set_trigger((trigger_t)func);
        (*it)->set_dll_handle(dll_handle);
    }
    else{
        utils_print_error("[!] The trigger cannot be used for this callback type %s\n",trigger_path);
    }
}
void CallbackManager::remove_trigger(callback_handle_t callback_handle){
    //Locate callback entry
    multiset<Callback*,CompareCallbackP>::iterator it;
    int i;
    int found = 0;
    for (i = 0; found == 0 && i<LAST_CB;i++)
    {
        for (it = this->callbacks[i].begin();it!=this->callbacks[i].end();++it)
        {
            if ((*it)->get_handle() == callback_handle)
            {
                found = 1;
                break;
            }
        }
        if (found == 1){
            //Break to avoid incrementing i
            break;
        }
    }
    if (found == 0)
    {
        utils_print_error("[!] Could not set trigger on unregistered callback handle %x\n",callback_handle);
        return;
    }
    //iterator (it) points to the callback structure
    if((*it)->get_trigger() == (trigger_t)0 || (*it)->get_dll_handle() == (void*)0)
    {
        utils_print_error("[!] Cannot remove non existent trigger\n");
        return;
    }
    //Load symbol
    trigger_clean_t clean = (trigger_clean_t)dlsym((*it)->get_dll_handle(),"clean");
    if (!clean)
    {
        utils_print_error("[!] Could not find function clean\n");
        return;
    }
    //First, remove reference to trigger
    (*it)->set_trigger((trigger_t)0);
    //Second, call the clean function
    clean((*it)->get_handle());
    //Third, unload dll
    if(dlclose((*it)->get_dll_handle()))
    {
        utils_print_error("[!] Error while decrementing reference count for library\n");
        return;
    }
    utils_print_debug("[*] Successfully removed trigger\n");
    (*it)->set_dll_handle(0);
}

callback_handle_t CallbackManager::add_callback(callback_type_t type, module_handle_t module_handle, PyObject* callback_function, pyrebox_target_ulong address, pyrebox_target_ulong pgd) {
    //First, check if the python function is correct 
    if (!PyCallable_Check(callback_function)){
        return 0;
    }
    //Now, create the callback and insert it
    Callback* cb;
    switch(type)
    {
        case OP_BLOCK_BEGIN_CB:
            //Unless we are isntrumenting all block begins, flush TB 
            if (callbacks[BLOCK_BEGIN_CB].size() == 0){
                pyrebox_flush_tb();
            }
            cb = (Callback*) new OptimizedBlockBeginCallback();
            memory_address_t addr_block;
            addr_block.address = address;
            addr_block.pgd = pgd;
            ((OptimizedBlockBeginCallback*)cb)->set_target_address(addr_block);
            break;
        case OP_INSN_BEGIN_CB:
            //Unless we are isntrumenting all insn begins, flush TB 
            if (callbacks[INSN_BEGIN_CB].size() == 0){
                pyrebox_flush_tb();
            }
            cb = (Callback*) new OptimizedInsBeginCallback(); 
            memory_address_t addr;
            addr.address = address;
            addr.pgd = pgd;
            ((OptimizedInsBeginCallback*)cb)->set_target_address(addr);
            break;
        case OPCODE_RANGE_CB:
            //Always flush tb when new opcode range callback is inserted
            pyrebox_flush_tb();
            cb = (Callback*) new OptimizedOpcodeRangeCallback();
            opcode_range_t opcode_range;
            opcode_range.start_opcode = address & 0xFFFF;
            opcode_range.end_opcode = pgd & 0xFFFF;
            ((OptimizedOpcodeRangeCallback*)cb)->set_opcode_range(opcode_range);
            break;
        case BLOCK_BEGIN_CB:
        case BLOCK_END_CB:
        case INSN_BEGIN_CB:
        case INSN_END_CB:
        case MEM_READ_CB:
        case MEM_WRITE_CB:
            //Flush TB unless there were already callbacks for that type
            if (callbacks[type].size() == 0){
                pyrebox_flush_tb();
            }
            cb = new Callback();
            break;
        default:
            cb = new Callback();
            break;
    }

    cb->set_trigger((trigger_t)0);
    cb->set_dll_handle(0);

    cb->set_callback_type(type);
    cb->set_module_handle(module_handle);
    cb->set_callback_function(callback_function);
    cb->set_handle(callback_handle_counter++);

    //Insert callback in list
    Py_XINCREF(callback_function);

    callbacks[type].insert(cb);
    //Return callback.
    return cb->get_handle();
}

void CallbackManager::deliver_callback(callback_type_t type, callback_params_t params){

    if (type == OP_INSN_BEGIN_CB || type == INSN_BEGIN_CB){
        memory_address_t addr;
        addr.address = get_cpu_addr(params.insn_begin_params.cpu);
        addr.pgd = get_pgd(params.insn_begin_params.cpu);
        //Deliver inmediately the internal callbacks 
        for (int i = 0; i < MAX_INTERNAL_CALLBACKS && internal_callbacks[i].callback_function != 0; ++i){
            if (internal_callbacks[i].pc == addr.address && (internal_callbacks[i].pgd == 0 || internal_callbacks[i].pgd == addr.pgd)){
                internal_callbacks[i].callback_function(params);
            }
        }
    }
    //Lock the python mutex
    pthread_mutex_lock(&pyrebox_mutex);
    fflush(stdout);
    fflush(stderr);

    //For each type of callback, trigger the python callback with its corresponding arguments 
    PyObject* arg = 0;
    list<Callback*> callbacks_needed;

    //For delivering callbacks, we must do it as efficiently as possible.
    //We have 4 cases: Optimized insn begin, optimized block begin, opcode ranges, and regular callbacks (all get called)
    //Optimized and general versions are joined together
    if (type == OP_BLOCK_BEGIN_CB || type == BLOCK_BEGIN_CB){
  
        pyrebox_target_ulong pgd = get_pgd(params.block_begin_params.cpu);

        // Check if process is monitored if there is no trigger
        for (multiset<Callback*,CompareCallbackP>::iterator it = this->callbacks[BLOCK_BEGIN_CB].begin(); it != this->callbacks[BLOCK_BEGIN_CB].end(); ++it){
            if (((*it)->get_trigger() == 0 && is_monitored_process(pgd)) || ((*it)->get_trigger() != 0 && (*it)->get_trigger()((*it)->get_handle(),params))){
                callbacks_needed.push_back((*it));
            }
        }

        //Search only blocks starting at that address
        OptimizedBlockBeginCallback *cb = new OptimizedBlockBeginCallback();
        memory_address_t addr;
        addr.address = get_tb_addr(params.block_begin_params.tb);
        addr.pgd = pgd; 
        cb->set_target_address(addr);
        multiset<Callback*,CompareCallbackP>::iterator it = this->callbacks[OP_BLOCK_BEGIN_CB].lower_bound((Callback*)cb);
        delete cb;
        while (it != this->callbacks[OP_BLOCK_BEGIN_CB].end() && addr.address == ((OptimizedBlockBeginCallback*)(*it))->get_target_address().address && addr.pgd == ((OptimizedBlockBeginCallback*)(*it))->get_target_address().pgd){
            if ((*it)->get_trigger() == 0 || (*it)->get_trigger()((*it)->get_handle(),params)){
                callbacks_needed.push_back((*it));
            }
            ++it;
        }
    }
    //Optimized and general versions are joined together
    else if (type == OP_INSN_BEGIN_CB || type == INSN_BEGIN_CB){

        memory_address_t addr;
        addr.address = get_cpu_addr(params.insn_begin_params.cpu);
        addr.pgd = get_pgd(params.insn_begin_params.cpu);


        // Defer the python callbacks
        // Check if process is monitored if there is no trigger
        for (multiset<Callback*,CompareCallbackP>::iterator it = this->callbacks[INSN_BEGIN_CB].begin(); it != this->callbacks[INSN_BEGIN_CB].end(); ++it){
            if (((*it)->get_trigger() == 0 && is_monitored_process(addr.pgd)) || ((*it)->get_trigger() != 0 && (*it)->get_trigger()((*it)->get_handle(),params))){
                callbacks_needed.push_back((*it));
            }
        }

        OptimizedInsBeginCallback *cb = new OptimizedInsBeginCallback();
        cb->set_target_address(addr);
        multiset<Callback*,CompareCallbackP>::iterator it = this->callbacks[OP_INSN_BEGIN_CB].lower_bound((Callback*)cb);
        delete cb;

        while (it != this->callbacks[OP_INSN_BEGIN_CB].end() && addr.address == ((OptimizedInsBeginCallback*)(*it))->get_target_address().address && addr.pgd == ((OptimizedInsBeginCallback*)(*it))->get_target_address().pgd){
            if ((*it)->get_trigger() == 0 || (*it)->get_trigger()((*it)->get_handle(),params)){
                callbacks_needed.push_back((*it));
            }
            ++it;
        }
    }
    else if (type == OPCODE_RANGE_CB){
        uint16_t opcode = params.opcode_range_params.opcode;
        pyrebox_target_ulong pgd = get_pgd(params.opcode_range_params.cpu);
        OptimizedOpcodeRangeCallback *cb = new OptimizedOpcodeRangeCallback();
        opcode_range_t opcoderange;
        opcoderange.start_opcode = opcode;
        opcoderange.end_opcode = opcode;
        cb->set_opcode_range(opcoderange);
        //With this, we can get the overlapping opcode_range blocks
        multiset<Callback*,CompareCallbackP>::iterator it = this->callbacks[type].lower_bound((Callback*)cb);
        delete cb;
        while (it != this->callbacks[type].end()) {
            if (((OptimizedOpcodeRangeCallback*)(*it))->get_opcode_range().start_opcode <= opcode){
                if (((*it)->get_trigger() == 0 && is_monitored_process(pgd)) || ((*it)->get_trigger() != 0 && (*it)->get_trigger()((*it)->get_handle(),params))){
                    callbacks_needed.push_back((*it));
                }
            }
            ++it;
        }
    }
    else if (type == BLOCK_END_CB || type == INSN_END_CB || type == MEM_READ_CB || type == MEM_WRITE_CB){
        // Get the PGD        
        pyrebox_target_ulong pgd = 0;
        if (type == BLOCK_END_CB){
            pgd = get_pgd(params.block_end_params.cpu);
        } else if (type == INSN_END_CB) {
            pgd = get_pgd(params.insn_end_params.cpu);
        } else if (type == MEM_READ_CB){
            pgd = get_pgd(params.mem_read_params.cpu);
        } else if (type == MEM_WRITE_CB){
            pgd = get_pgd(params.mem_write_params.cpu);
        }
        // Check if the process in monitored or not, only if there is no trigger
        for (multiset<Callback*,CompareCallbackP>::iterator it = this->callbacks[type].begin(); it != this->callbacks[type].end(); ++it){
            if (((*it)->get_trigger() == 0 && is_monitored_process(pgd)) || ((*it)->get_trigger() != 0 && (*it)->get_trigger()((*it)->get_handle(),params))){
                callbacks_needed.push_back((*it));
            }
        }
    }
    else {
        // The rest of the cases don't need the process to be monitored (VMI & system wide callbacks)
        // Check if the process in monitored or not
        //Here, just check the triggers. 
        for (multiset<Callback*,CompareCallbackP>::iterator it = this->callbacks[type].begin(); it != this->callbacks[type].end(); ++it){
            if ((*it)->get_trigger() == 0 || (*it)->get_trigger()((*it)->get_handle(),params)){
                callbacks_needed.push_back((*it));
            }
        }
    }

    if (callbacks_needed.size() == 0)
    {
        //Unlock the python mutex
        fflush(stdout);
        fflush(stderr);
        pthread_mutex_unlock(&pyrebox_mutex);
        return; 
    }


    switch(type)
    {
       case OP_BLOCK_BEGIN_CB:
            arg =  Py_BuildValue("(i,N,N)",params.block_begin_params.cpu_index,get_cpu_state(params.block_begin_params.cpu),
                                      get_tb(params.block_begin_params.tb));
            break;
       case OP_INSN_BEGIN_CB:
            arg =  Py_BuildValue("(i,N)",params.insn_begin_params.cpu_index,get_cpu_state(params.insn_begin_params.cpu));
            break;
       case BLOCK_BEGIN_CB:
            arg =  Py_BuildValue("(i,N,N)",params.block_begin_params.cpu_index,get_cpu_state(params.block_begin_params.cpu),
                                      get_tb(params.block_begin_params.tb));
            break;
       case BLOCK_END_CB:
#if TARGET_LONG_SIZE == 4
            arg =  Py_BuildValue("(i,N,N,I,I)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(i,N,N,K,K)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                      params.block_end_params.cpu_index,
                                      get_cpu_state(params.block_end_params.cpu),
                                      get_tb(params.block_end_params.tb),
                                      params.block_end_params.cur_pc,
                                      params.block_end_params.next_pc);
            break;
       case INSN_BEGIN_CB:
            arg =  Py_BuildValue("(i,N)",params.insn_begin_params.cpu_index,get_cpu_state(params.insn_begin_params.cpu));
            break;
       case INSN_END_CB:
            arg =  Py_BuildValue("(i,N)",params.insn_end_params.cpu_index,get_cpu_state(params.insn_end_params.cpu));
            break;
       case MEM_READ_CB:
#if TARGET_LONG_SIZE == 4
            arg =  Py_BuildValue("(i,I,I,K)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(i,K,K,K)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                           params.mem_read_params.cpu_index,
                                           params.mem_read_params.vaddr,
                                           params.mem_read_params.size,
                                           params.mem_read_params.haddr);
            break;
       case MEM_WRITE_CB:
#if TARGET_LONG_SIZE == 4
            arg =  Py_BuildValue("(i,I,I,K,I)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(i,K,K,K,K)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                           params.mem_write_params.cpu_index,
                                           params.mem_write_params.vaddr,
                                           params.mem_write_params.size,
                                           params.mem_write_params.haddr,
                                           params.mem_write_params.data);
            break;
       case KEYSTROKE_CB:
            arg =  Py_BuildValue("(I)",params.keystroke_params.keycode);
            break;
       case NIC_REC_CB:
            //Size is duplicated, first for the size of the string, second one for the size parameter
#if TARGET_LONG_SIZE == 4
            //Since this is target independent, we use always 64 bits
            arg =  Py_BuildValue("(s#,K,K,K,K)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(s#,K,K,K,K)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                           params.nic_rec_params.buf,
                                           params.nic_rec_params.size,
                                           params.nic_rec_params.size,
                                           params.nic_rec_params.cur_pos,
                                           params.nic_rec_params.start,
                                           params.nic_rec_params.stop);
            break;
       case NIC_SEND_CB:
#if TARGET_LONG_SIZE == 4
            //Since this is target independent, we use always 64 bits
            arg =  Py_BuildValue("(K,K,s#)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(K,K,s#)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                           params.nic_send_params.address,
                                           params.nic_send_params.size,
                                           params.nic_send_params.buf,
                                           params.nic_send_params.size);
            break;
       case OPCODE_RANGE_CB:
#if TARGET_LONG_SIZE == 4
            arg =  Py_BuildValue("(i,N,I,I)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(i,N,K,K)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                      params.opcode_range_params.cpu_index,
                                      get_cpu_state(params.opcode_range_params.cpu),
                                      params.opcode_range_params.cur_pc,
                                      params.opcode_range_params.next_pc);
            break;
       case TLB_EXEC_CB:
#if TARGET_LONG_SIZE == 4
            arg =  Py_BuildValue("(N,I)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(N,K)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                      get_cpu_state(params.tlb_exec_params.cpu),
                                      params.tlb_exec_params.vaddr);
            break;
       case CREATEPROC_CB:
#if TARGET_LONG_SIZE == 4
            arg =  Py_BuildValue("(I,I,s)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(K,K,s)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                        params.vmi_create_proc_params.pid,
                                        params.vmi_create_proc_params.pgd,
                                        params.vmi_create_proc_params.name);

            break;
       case REMOVEPROC_CB:
#if TARGET_LONG_SIZE == 4
            arg =  Py_BuildValue("(I,I,s)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(K,K,s)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                        params.vmi_create_proc_params.pid,
                                        params.vmi_create_proc_params.pgd,
                                        params.vmi_create_proc_params.name);
            break;
       case CONTEXTCHANGE_CB:
#if TARGET_LONG_SIZE == 4
            arg =  Py_BuildValue("(I,I)",
#elif TARGET_LONG_SIZE == 8
            arg =  Py_BuildValue("(K,K)",
#else
#error TARGET_LONG_SIZE undefined
#endif
                                        params.vmi_context_change_params.old_pgd,
                                        params.vmi_context_change_params.new_pgd);
            break;
       default:
            //Reaching this path means some case is
            //not implemented. Code it lazy ass!
            assert(0);
            break;
    }

    for (list<Callback*>::iterator it = callbacks_needed.begin(); it != callbacks_needed.end(); ++it)
    {
        PyObject* ret = PyObject_CallObject((*it)->get_callback_function(),arg);
        Py_XDECREF(ret);
    }
    //Once all callbacks have been triggered, just decref the arguments
    Py_XDECREF(arg);
    //Remove the installed callbacks whose removal was deferred until all callbacks have been dispatched
    this->commit_deferred_callback_removes();
    fflush(stdout);
    fflush(stderr);
    pthread_mutex_unlock(&pyrebox_mutex);
}

void CallbackManager::clean_callbacks(){
    //For whatever action that may be needed here.
}

CallbackManager::CallbackManager(){}
CallbackManager::~CallbackManager(){
    this->remove_all_callbacks();
}

void CallbackManager::remove_callback_deferred(callback_handle_t handle){
    this->callback_remove_list.push_front(handle);
}

void CallbackManager::commit_deferred_callback_removes(){
    for (std::list<callback_handle_t>::iterator it = this->callback_remove_list.begin(); it != this->callback_remove_list.end(); ++it){
        this->remove_callback(*it);
    }
    this->callback_remove_list.clear();
}

void CallbackManager::remove_callback(callback_handle_t handle){
    for (int i = OP_BLOCK_BEGIN_CB; i < LAST_CB;i++){
        std::multiset<Callback*,CompareCallbackP>::iterator it = this->callbacks[i].begin();
        while (it != this->callbacks[i].end())
        {
           if ((*it)->get_handle() == handle)
           {
               //Decrement reference count for the callback function
               Py_XDECREF((*it)->get_callback_function());
               //Remove trigger (will decrement reference count for loaded library
               if ((*it)->get_trigger() != (trigger_t)0){
                   this->remove_trigger((*it)->get_handle());
               }
               //Free memory for the Callback*
               if (*it != 0){
                   delete (*it);
               }
               it = this->callbacks[i].erase(it);
               switch(i){
                   case OP_BLOCK_BEGIN_CB:
                        //Flush TB unless we are instrumenting all
                        if (this->callbacks[BLOCK_BEGIN_CB].size() == 0){
                            pyrebox_flush_tb();
                        }
                        break;
                   case OP_INSN_BEGIN_CB:
                        //Flush TB unless we are instrumenting all
                        if (this->callbacks[INSN_BEGIN_CB].size() == 0){
                            pyrebox_flush_tb();
                        }
                        break;
                   case OPCODE_RANGE_CB:
                        //Always flush TB
                        pyrebox_flush_tb();
                        break;
                   default:
                        //For the rest of the cases, flush if the list now contains 0 callbacks
                        if (this->callbacks[i].size() == 0){
                            pyrebox_flush_tb();
                        }
                        break;
               }
           }
           else
           {
               ++it;
           }
        }
    }
    //Finally, call to callbacks for last actions
    this->clean_callbacks();
}

void CallbackManager::remove_all_callbacks(){
    std::multiset<Callback*,CompareCallbackP>::iterator it;
    for (int i = OP_BLOCK_BEGIN_CB; i < LAST_CB;i++){
        it = this->callbacks[i].begin();
        while (it != this->callbacks[i].end()){
           //Decrement reference count for the callback function
           Py_XDECREF((*it)->get_callback_function());
           if ((*it)->get_trigger() != (trigger_t)0){
               this->remove_trigger((*it)->get_handle());
           }
           //Free memory for the Callback*
           if (*it != 0){
               delete (*it);
           }
           it = this->callbacks[i].erase(it);
        }
    }
    //Finally, call to callbacks for last actions
    this->clean_callbacks();
    //Flush TB after such a step
    pyrebox_flush_tb();
}

void CallbackManager::remove_module_callbacks(module_handle_t handle){
    std::multiset<Callback*,CompareCallbackP>::iterator it;
    for (int i = OP_BLOCK_BEGIN_CB; i < LAST_CB;i++){
        it = this->callbacks[i].begin();
        while (it != this->callbacks[i].end()){
           if ((*it)->get_module_handle() == handle){
               //Decrement reference count for the callback function
               Py_XDECREF((*it)->get_callback_function());
               if ((*it)->get_trigger() != (trigger_t)0){
                   this->remove_trigger((*it)->get_handle());
               }
               //Free memory for the Callback*
               if (*it != 0){
                   delete (*it);
               }
               it = this->callbacks[i].erase(it);
           }
           else {
               ++i;
           }
        }
    }
    //Finally, call to callbacks for last actions
    this->clean_callbacks();
    //Flush TB after such a step
    pyrebox_flush_tb();
}

int CallbackManager::is_callback_needed(callback_type_t callback_type, pyrebox_target_ulong address, pyrebox_target_ulong pgd){
    std::multiset<Callback*,CompareCallbackP>::iterator it;
    Callback* cb;
    switch(callback_type){
        //Unified block begin callback. Only BLOCK_BEGIN_CB should be queried, anyway
        case OP_BLOCK_BEGIN_CB:
        case BLOCK_BEGIN_CB:
            //First, check if we have callbacks for the generic version 
            if (this->callbacks[BLOCK_BEGIN_CB].size() > 0){
                return 1;
            }
            //Second, check if we have the optimized version
            cb = new OptimizedBlockBeginCallback();
            memory_address_t addr_block;
            addr_block.address = address;
            addr_block.pgd = 0;
            ((OptimizedBlockBeginCallback*)cb)->set_target_address(addr_block);
            it = this->callbacks[OP_BLOCK_BEGIN_CB].lower_bound((Callback*)cb);
            delete cb;
            // Only check the address, regardless of the PGD. PGD will be checked on callback delivery
            if (it != this->callbacks[OP_BLOCK_BEGIN_CB].end() && address == ((OptimizedBlockBeginCallback*)(*it))->get_target_address().address){
                return 1;
            }
            break;
        //Unified insn begin callback. Only INSN_BEGIN_CB should be queried, anyway
        case OP_INSN_BEGIN_CB:
        case INSN_BEGIN_CB:
            //First, do a fast check over our internal callbacks
            for (int i = 0; i < MAX_INTERNAL_CALLBACKS && internal_callbacks[i].callback_function != 0; ++i){
                if (internal_callbacks[i].pc == address){
                    return 1;
                }
            }
            //First, check if we have callbacks for the generic version 
            if (this->callbacks[INSN_BEGIN_CB].size() > 0){
                return 1;
            }
 
            //Second, check if we have the optimized version
            cb = (Callback*) new OptimizedInsBeginCallback();
            memory_address_t addr;
            addr.address = address;
            addr.pgd = 0;
            ((OptimizedInsBeginCallback*)cb)->set_target_address(addr);
            it = this->callbacks[OP_INSN_BEGIN_CB].lower_bound((Callback*)cb);
            delete cb;
            // Only check the address, regardless of the PGD. PGD will be checked on callback delivery
            if (it != this->callbacks[OP_INSN_BEGIN_CB].end() && address == ((OptimizedInsBeginCallback*)(*it))->get_target_address().address){
                return 1;
            }
            break;
        case OPCODE_RANGE_CB:
            // Consider only the number of callbacks, because the pgd will be checked at
            // callback delivery
            if (this->callbacks[OPCODE_RANGE_CB].size() > 0){
                cb = (Callback*) new OptimizedOpcodeRangeCallback();
                opcode_range_t opcoderange;
                opcoderange.start_opcode = (uint16_t)(address & 0xFFFF);
                opcoderange.end_opcode = (uint16_t)(address & 0xFFFF);
                ((OptimizedOpcodeRangeCallback*)cb)->set_opcode_range(opcoderange);
                //With this, we can get the overlapping opcode_range blocks
                it = this->callbacks[OPCODE_RANGE_CB].lower_bound((Callback*)cb);
                delete cb;
                while (it != this->callbacks[OPCODE_RANGE_CB].end()) {
                    if (((OptimizedOpcodeRangeCallback*)(*it))->get_opcode_range().start_opcode <= (uint16_t)(address & 0xFFFF)){
                        return 1;
                    }
                    else{
                        ++it;
                    }
                }
            }
            break;
        case TLB_EXEC_CB:
        case KEYSTROKE_CB:
        case NIC_REC_CB:
        case NIC_SEND_CB:
        case CREATEPROC_CB:
        case REMOVEPROC_CB:
        case CONTEXTCHANGE_CB:
            //We always deliver TLB callbacks, because we need them to 
            //trigger certain VMI related actions
            return 1;
            break;
        default:
            // Consider only the number of callbacks, because the pgd will be checked at
            // callback delivery
            return (this->callbacks[callback_type].size() > 0);
            break;
    }
    return 0;
}
