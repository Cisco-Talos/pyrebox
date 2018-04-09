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

#ifndef CALLBACKS_H
#define CALLBACKS_H

#define INV_ADDR -1
#define INV_PGD -1

#define MAX_INTERNAL_CALLBACKS 16

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

// Several type definitions
typedef enum {
        //Although we do not distinguish between optimized
        //and non-optimized block begin events in python
        //scripting, we keep separate lists for both types
        OP_BLOCK_BEGIN_CB = 0,
        OP_INSN_BEGIN_CB,
        BLOCK_BEGIN_CB,
        BLOCK_END_CB,
        INSN_BEGIN_CB,
        INSN_END_CB,
        MEM_READ_CB,
        MEM_WRITE_CB,
        KEYSTROKE_CB,//keystroke event
        NIC_REC_CB,
        NIC_SEND_CB,
        OPCODE_RANGE_CB,
        TLB_EXEC_CB,
        CREATEPROC_CB,
        REMOVEPROC_CB,
        CONTEXTCHANGE_CB,
        LAST_CB, //Last position, not used
} callback_type_t;

//Internal (python callback) handles
typedef unsigned int module_handle_t;
typedef unsigned int callback_handle_t;

typedef struct block_begin_params {
    int cpu_index;
    qemu_cpu_opaque_t cpu;
    qemu_tb_opaque_t tb;   
} block_begin_params_t;

typedef struct block_end_params {
    int cpu_index;
    qemu_cpu_opaque_t cpu;
    qemu_tb_opaque_t tb;   
    pyrebox_target_ulong cur_pc;
    pyrebox_target_ulong next_pc;
} block_end_params_t;

typedef struct insn_begin_params {
    int cpu_index;
    qemu_cpu_opaque_t cpu;
} insn_begin_params_t;

typedef struct insn_end_params {
    int cpu_index;
    qemu_cpu_opaque_t cpu;
} insn_end_params_t;

typedef struct mem_read_params {
    int cpu_index;
    pyrebox_target_ulong vaddr;
    uintptr_t haddr;
    pyrebox_target_ulong size;
    qemu_cpu_opaque_t cpu;
} mem_read_params_t;

typedef struct mem_write_params {
    int cpu_index;
    pyrebox_target_ulong vaddr;
    uintptr_t haddr;
    pyrebox_target_ulong size;
    pyrebox_target_ulong data;
    qemu_cpu_opaque_t cpu;
} mem_write_params_t;

typedef struct keystroke_params {
    unsigned int keycode;
} keystroke_params_t;

typedef struct nic_rec_params {
    unsigned char* buf;
    uint64_t size;
    uint64_t cur_pos;
    uint64_t start;
    uint64_t stop;
} nic_rec_params_t;

typedef struct nic_send_params {
    unsigned char* buf;
    uint64_t size;
    uint64_t address;
} nic_send_params_t;

typedef struct opcode_range_params {
    int cpu_index;
    qemu_cpu_opaque_t cpu;
    pyrebox_target_ulong cur_pc;
    pyrebox_target_ulong next_pc;
    uint16_t opcode;
} opcode_range_params_t;

typedef struct tlb_exec_params {
    qemu_cpu_opaque_t cpu;
    pyrebox_target_ulong vaddr;
} tlb_exec_params_t;

typedef struct vmi_create_proc_params {
    pyrebox_target_ulong pid;
    pyrebox_target_ulong pgd;
    char* name;
} vmi_create_proc_params_t;

typedef struct vmi_remove_proc_params {
    pyrebox_target_ulong pid;
    pyrebox_target_ulong pgd;
    char* name;
} vmi_remove_proc_params_t;

typedef struct vmi_context_change_params {
    pyrebox_target_ulong old_pgd;
    pyrebox_target_ulong new_pgd;
} vmi_context_change_params_t;

//Params for the qemu->pyrebox callback (native)
typedef struct callback_params {
   union {
        block_begin_params_t block_begin_params;
        block_end_params_t block_end_params;
        insn_begin_params_t insn_begin_params;
        insn_end_params_t insn_end_params;
        mem_read_params_t mem_read_params;
        mem_write_params_t mem_write_params;
        keystroke_params_t keystroke_params;
        nic_rec_params_t nic_rec_params;
        nic_send_params_t nic_send_params;
        opcode_range_params_t opcode_range_params;
        tlb_exec_params_t tlb_exec_params;
        vmi_create_proc_params_t vmi_create_proc_params;
        vmi_remove_proc_params_t vmi_remove_proc_params;
        vmi_context_change_params_t vmi_context_change_params;
   };
} callback_params_t;

//Interface for the qemu->pyrebox callback (native)
typedef void (*callback_t)(callback_params_t);

//List of pyrebox callback functions
void block_begin_callback(callback_params_t params);
void block_end_callback(callback_params_t params);
void insn_begin_callback(callback_params_t params);
void insn_end_callback(callback_params_t params);
void mem_read_callback(callback_params_t params);
void mem_write_callback(callback_params_t params);
void keystroke_callback(callback_params_t params);
void nic_rec_callback(callback_params_t params);
void nic_send_callback(callback_params_t params);
void opcode_range_callback(callback_params_t params);
void tlb_exec_callback(callback_params_t params);
void create_proc_callback(callback_params_t params);
void remove_proc_callback(callback_params_t params);
void context_change_callback(callback_params_t params);

//Triggers
typedef int (*trigger_t)(callback_handle_t,callback_params_t);
typedef int (*trigger_get_type_t)(void);
typedef void (*trigger_clean_t)(callback_handle_t);
typedef void* (*get_var_t)(callback_handle_t,const char*);
typedef void (*set_var_t)(callback_handle_t,const char*,void*);

typedef struct memory_address{
    pyrebox_target_ulong address;
    pyrebox_target_ulong pgd;
} memory_address_t;

typedef struct opcode_range{
    uint16_t start_opcode;
    uint16_t end_opcode;
} opcode_range_t;


//Global handle counter for python callback handles
extern callback_handle_t callback_handle_counter;

//C interface of the callback manager
callback_handle_t add_callback_at(callback_type_t type, module_handle_t module_handle, PyObject* callback_function, pyrebox_target_ulong address, pyrebox_target_ulong pgd);
callback_handle_t add_callback(callback_type_t type, module_handle_t module_handle, PyObject* callback_function);
int is_callback_needed(callback_type_t callback_type, pyrebox_target_ulong address, pyrebox_target_ulong pgd);
void remove_callback(callback_handle_t handle);
void remove_callback_deferred(callback_handle_t handle);
void commit_deferred_callback_removes(void);
//For triggers
void add_trigger(callback_handle_t callback_handle, char* trigger_path);
void remove_trigger(callback_handle_t callback_handle);
void set_trigger_var(callback_handle_t callback_handle, const char* var, void* val);
void* get_trigger_var(callback_handle_t callback_handle, const char* var);
void InitCallbacks(void);
void FinalizeCallbacks(void);

typedef unsigned int internal_callback_handle_t;

//Internal callbacks, we can place up to a MAX number of internal callbacks
//that are delivered as OptimizedInsn callbacks, for VMI related actions.
typedef struct internal_callback{
    pyrebox_target_ulong pgd;
    pyrebox_target_ulong pc;
    callback_t callback_function; 
} internal_callbacks_t;

internal_callback_handle_t add_internal_callback(pyrebox_target_ulong pgd, pyrebox_target_ulong pc, callback_t callback_function);
// We do not implement an internal callback removal, since these callbacks are supposed to be static for VMI related
// actions, so there is no need to handle callback removal.
//void remove_internal_callback(internal_callback_handle_t callback_handle);

#ifdef __cplusplus
};
#endif//__cplusplus

#ifdef __cplusplus

class Callback
{
    public:
        //Constructor - destructor
        Callback() {};
        virtual ~Callback() {};
        //Public getters
        callback_type_t get_callback_type() { return this->callback_type; };
        module_handle_t get_module_handle() { return this->module_handle; };
        PyObject* get_callback_function() { return this->callback_function; };
        callback_handle_t get_handle() { return this->handle; };
        trigger_t get_trigger() { return this->trigger; };
        void* get_dll_handle() { return this->dll_handle; };
        //Public setters
        void set_callback_type(callback_type_t callback_type) { this->callback_type = callback_type; };
        void set_module_handle(module_handle_t module_handle) { this->module_handle = module_handle; };
        void set_callback_function(PyObject* callback_function) { this->callback_function = callback_function; };
        void set_handle(callback_handle_t handle) { this->handle = handle; };
        void set_trigger(trigger_t trigger) { this->trigger = trigger; };
        void set_dll_handle(void* dll_handle) { this->dll_handle = dll_handle; };
        //Comparison operators, for STL collections
        virtual bool compare_less(Callback* rhs){
            return this->handle < rhs->handle;
        }
        bool operator< (Callback &rhs) {
            //Calls to the virtual compare_less function, because comparison
            //operator cannot be polymorphic even if they are virtual. They
            //cannot be polymorphic because they have different interfaces (the
            //type of the parameter passed by referece is different in derived
            //classes).
            return this->compare_less((Callback*)(&rhs));
        };

    protected:
        callback_type_t callback_type = (callback_type_t) 0;
        module_handle_t module_handle = (module_handle_t)0;
        PyObject* callback_function = (PyObject*)0;
        callback_handle_t handle = (callback_handle_t)0; // our own handle
        //Trigger
        trigger_t trigger = (trigger_t)0;
        void* dll_handle = (void*)0;
};

class OptimizedInsBeginCallback : public Callback
{
    public:
        OptimizedInsBeginCallback(): Callback() {};
        memory_address_t get_target_address(){return this->target_address;};
        void set_target_address(memory_address_t target_address){this->target_address = target_address;};

        virtual bool compare_less(Callback* rhs) {
            OptimizedInsBeginCallback* casted_rhs = dynamic_cast<OptimizedInsBeginCallback*>(rhs);
            //Exit if it does not belong to the same class
            assert(casted_rhs != 0);
            return ((this->target_address.address < casted_rhs->target_address.address) || (this->target_address.address == casted_rhs->target_address.address && this->target_address.pgd < casted_rhs->target_address.pgd));
        }

    protected:
        memory_address_t target_address = {0,0};
};

class OptimizedBlockBeginCallback : public Callback
{
    public:
        OptimizedBlockBeginCallback(): Callback() {};
        virtual ~OptimizedBlockBeginCallback() {};

        memory_address_t get_target_address(){return this->target_address;};
        void set_target_address(memory_address_t target_address){this->target_address = target_address;};

        virtual bool compare_less(Callback* rhs) {
            OptimizedBlockBeginCallback* casted_rhs = dynamic_cast<OptimizedBlockBeginCallback*>(rhs);
            //Exit if it does not belong to the same class
            assert(casted_rhs != 0);
            return ((this->target_address.address < casted_rhs->target_address.address) || (this->target_address.address == casted_rhs->target_address.address && this->target_address.pgd < casted_rhs->target_address.pgd));
        }

    protected:
        memory_address_t target_address = {0,0};
};

class OptimizedOpcodeRangeCallback : public Callback
{
    public:
        OptimizedOpcodeRangeCallback(): Callback() {};

        void set_opcode_range(opcode_range_t opcode_range) { this->opcode_range = opcode_range; };
        opcode_range_t get_opcode_range() { return this->opcode_range; };
        virtual bool compare_less(Callback* rhs) {
            OptimizedOpcodeRangeCallback* casted_rhs = dynamic_cast<OptimizedOpcodeRangeCallback*>(rhs);
            //Exit if it does not belong to the same class
            assert(casted_rhs != 0);
            return (this->opcode_range.end_opcode < casted_rhs->opcode_range.end_opcode);
        }
        
    protected:
        opcode_range_t opcode_range = {0,0};
};


/** Comparison for multiset of Callback* **/
struct CompareCallbackP {
    bool operator()(Callback* lhs, Callback* rhs)
    {
        return lhs->compare_less(rhs);
    }
};


class CallbackManager
{
        public:
            CallbackManager();
            ~CallbackManager();
            callback_handle_t add_callback(callback_type_t type, module_handle_t module_handle, PyObject* callback_function, pyrebox_target_ulong address);
            callback_handle_t add_callback(callback_type_t type, module_handle_t module_handle, PyObject* callback_function, pyrebox_target_ulong address,pyrebox_target_ulong pgd);
            void deliver_callback(callback_type_t type,callback_params_t params);
            void remove_callback(callback_handle_t handle);
            void remove_callback_deferred(callback_handle_t handle);
            void commit_deferred_callback_removes();
            void remove_all_callbacks();
            void remove_module_callbacks(module_handle_t handle);
            void add_trigger(callback_handle_t callback_handle,char* trigger_path);
            void remove_trigger(callback_handle_t callback_handle);
            void set_trigger_var(callback_handle_t callback_handle,const char* var,void* val);
            void* get_trigger_var(callback_handle_t callback_handle,const char* var);
            int is_callback_needed(callback_type_t callback_type, pyrebox_target_ulong address, pyrebox_target_ulong pgd);
        protected:
        private:
            //Array of lists, used to hold the pyrebox callbacks
            std::multiset<Callback*,CompareCallbackP> callbacks[LAST_CB];
            std::list<callback_handle_t> callback_remove_list;
            void clean_callbacks();
};
#endif //__cplusplus

#endif //CALLBACKS_H
