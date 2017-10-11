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

#include <inttypes.h>
#include <Python.h>
#include <set>
#include <list>
#include <pthread.h>

extern "C"{
#include "qemu_glue.h"
#include "utils.h"
#include "pyrebox.h"
}
#include "vmi.h"
#include "linux_vmi.h"

#include "callbacks.h"

using namespace std;

//Absolute offset of init_task
pyrebox_target_ulong init_task_offset = 0;
//Offsets inside task_struct
pyrebox_target_ulong pid_offset = 0;
pyrebox_target_ulong comm_offset = 0;
pyrebox_target_ulong tasks_offset = 0;
pyrebox_target_ulong mm_offset = 0;
pyrebox_target_ulong parent_offset = 0;
pyrebox_target_ulong exit_state_offset = 0;
pyrebox_target_ulong thread_stack_size = 0;
//Offsets inside mm_struct
pyrebox_target_ulong pgd_offset = 0;

//Offset for process creation / kill kernel functions
pyrebox_target_ulong proc_exec_connector_offset = 0;
pyrebox_target_ulong trim_init_extable_offset = 0;
pyrebox_target_ulong proc_exit_connector_offset = 0;

//Offsets we save once we find the init_task address and 
//the kernel shift
pyrebox_target_ulong init_task_address = 0;
pyrebox_target_ulong kernel_shift = 0;

//Flag to indicate that the process list is already 
//a valid list
int process_list_valid = 0;

//Flag to indicate that we need to populate the list
//of processes for the first time
int populate_initial_process_list = 0;

static unsigned long long tlb_counter = 0;

typedef struct list_head {
    pyrebox_target_ulong next;
    pyrebox_target_ulong prev;
} list_head;

void linux_init_address_space(){
   utils_print_debug("[*] Initializing volatility address space...\n");
   if (init_task_offset != 0){
       PyObject* py_module_name = PyString_FromString("linux_vmi");
       PyObject* py_vmi_module = PyImport_Import(py_module_name);
       Py_DECREF(py_module_name);
       if(py_vmi_module != NULL){
           PyObject* py_linux_init_address_space = PyObject_GetAttrString(py_vmi_module,"linux_init_address_space");
           if (py_linux_init_address_space){
               if (PyCallable_Check(py_linux_init_address_space)){
                    PyObject* ret = PyObject_CallObject(py_linux_init_address_space,NULL);
                    if (ret){
                        if (ret == Py_True){
                            utils_print_debug("[*] Volatility address space initialized!\n");
                        } else{
                            utils_print_error("[!] Could not initialize address space!");
                        }
                        Py_DECREF(ret);
                    }
                    else{
                        utils_print_error("[!] Could not initialize address space!");
                    }
               }
               Py_XDECREF(py_linux_init_address_space);
           }
           Py_DECREF(py_vmi_module);
       }
   }
}

void linux_vmi_init(os_index_t os_index){
   utils_print_debug("[*] Setting up Linux Profile...\n");

   //Update the OS family in the Python VMI module
   PyObject* py_module_name = PyString_FromString("vmi");
   PyObject* py_vmi_module = PyImport_Import(py_module_name);
   Py_DECREF(py_module_name);

   if(py_vmi_module != NULL){
       PyObject* py_setosfamily = PyObject_GetAttrString(py_vmi_module,"set_os_family_linux");
       if (py_setosfamily){
           if (PyCallable_Check(py_setosfamily)){
                PyObject* py_args = PyTuple_New(0);
                PyObject* ret = PyObject_CallObject(py_setosfamily,py_args);
                Py_DECREF(py_args);
                if (ret){
                    Py_DECREF(ret);
                }
           }
           Py_XDECREF(py_setosfamily);
       }
       Py_DECREF(py_vmi_module);
   }

   if (init_task_offset == 0){
       PyObject* py_module_name = PyString_FromString("linux_vmi");
       PyObject* py_vmi_module = PyImport_Import(py_module_name);
       Py_DECREF(py_module_name);
       if(py_vmi_module != NULL){
           PyObject* py_linux_get_offsets = PyObject_GetAttrString(py_vmi_module,"linux_get_offsets");
           if (py_linux_get_offsets){
               if (PyCallable_Check(py_linux_get_offsets)){
                    PyObject* ret = PyObject_CallObject(py_linux_get_offsets,NULL);
                    //Parse return and get offsets
                    if (ret){
                        PyObject* py_init_task_offset = PyTuple_GetItem(ret,0);
                        PyObject* py_comm_offset = PyTuple_GetItem(ret,1);
                        PyObject* py_pid_offset = PyTuple_GetItem(ret,2);
                        PyObject* py_tasks_offset = PyTuple_GetItem(ret,3);
                        PyObject* py_mm_offset = PyTuple_GetItem(ret,4);
                        PyObject* py_pgd_offset = PyTuple_GetItem(ret,5);
                        PyObject* py_parent_offset = PyTuple_GetItem(ret,6);
                        PyObject* py_exit_state_offset = PyTuple_GetItem(ret,7);
                        PyObject* py_thread_stack_size = PyTuple_GetItem(ret,8);
                        PyObject* py_proc_exec_connector_offset = PyTuple_GetItem(ret,9);
                        PyObject* py_trim_init_extable_offset = PyTuple_GetItem(ret,10);
                        PyObject* py_proc_exit_connector_offset = PyTuple_GetItem(ret,11);

                        if (arch_bits[os_index] == 32){
                            init_task_offset = PyLong_AsUnsignedLong(py_init_task_offset);
                            pid_offset = PyLong_AsUnsignedLong(py_pid_offset);
                            comm_offset = PyLong_AsUnsignedLong(py_comm_offset);
                            tasks_offset = PyLong_AsUnsignedLong(py_tasks_offset);
                            mm_offset = PyLong_AsUnsignedLong(py_mm_offset);
                            pgd_offset = PyLong_AsUnsignedLong(py_pgd_offset);
                            parent_offset = PyLong_AsUnsignedLong(py_parent_offset);
                            exit_state_offset = PyLong_AsUnsignedLong(py_exit_state_offset);
                            thread_stack_size = PyLong_AsUnsignedLong(py_thread_stack_size);

                            proc_exec_connector_offset = PyLong_AsUnsignedLong(py_proc_exec_connector_offset);
                            trim_init_extable_offset = PyLong_AsUnsignedLong(py_trim_init_extable_offset);
                            proc_exit_connector_offset = PyLong_AsUnsignedLong(py_proc_exit_connector_offset);
                        }
                        else{
                            init_task_offset = PyLong_AsUnsignedLongLong(py_init_task_offset);
                            pid_offset = PyLong_AsUnsignedLongLong(py_pid_offset);
                            comm_offset = PyLong_AsUnsignedLongLong(py_comm_offset);
                            tasks_offset = PyLong_AsUnsignedLongLong(py_tasks_offset);
                            mm_offset = PyLong_AsUnsignedLongLong(py_mm_offset);
                            pgd_offset = PyLong_AsUnsignedLongLong(py_pgd_offset);
                            parent_offset = PyLong_AsUnsignedLongLong(py_parent_offset);
                            exit_state_offset = PyLong_AsUnsignedLongLong(py_exit_state_offset);
                            thread_stack_size = PyLong_AsUnsignedLongLong(py_thread_stack_size);

                            proc_exec_connector_offset = PyLong_AsUnsignedLongLong(py_proc_exec_connector_offset);
                            trim_init_extable_offset = PyLong_AsUnsignedLongLong(py_trim_init_extable_offset);
                            proc_exit_connector_offset = PyLong_AsUnsignedLongLong(py_proc_exit_connector_offset);
                        }
                        /*utils_print_debug("  [-] init_task offset: %016lx\n", init_task_offset);
                        utils_print_debug("  [-] pid offset: %016lx\n", pid_offset);
                        utils_print_debug("  [-] comm offset: %016lx\n", comm_offset);
                        utils_print_debug("  [-] tasks offset: %016lx\n", tasks_offset);
                        utils_print_debug("  [-] mm offset: %016lx\n", mm_offset);
                        utils_print_debug("  [-] pgd offset: %016lx\n", pgd_offset);
                        utils_print_debug("  [-] parent offset: %016lx\n", parent_offset);
                        utils_print_debug("  [-] exit_state offset: %016lx\n", exit_state_offset);
                        utils_print_debug("  [-] proc exec connector: %016lx\n", proc_exec_connector_offset);
                        utils_print_debug("  [-] trim init extable: %016lx\n", trim_init_extable_offset);
                        utils_print_debug("  [-] proc exit connector: %016lx\n", proc_exit_connector_offset);
                        utils_print_debug("  [-] thread stack size: %016lx\n", thread_stack_size);*/

                        Py_DECREF(ret);
                    }
                    else{
                        utils_print_error("[!] Could not retrieve offsets for profile initialization");
                    }
               }
               Py_XDECREF(py_linux_get_offsets);
           }
           Py_DECREF(py_vmi_module);
       }
   }
}

int is_init_task_valid(pyrebox_target_ulong init_task_addr){
    char buf[12];
    connection_read_memory(init_task_addr + comm_offset,(char*) buf,12);
    return (!strncmp((const char*)buf,"swapper",7));
}


void update_process_list(pyrebox_target_ulong pgd){

    if (!is_init_task_valid(init_task_address)){
        init_task_address = 0;
        kernel_shift = 0;
        process_list_valid = 0;
        initialize_init_task(pgd);
    }

    //Reset the list of flags marking the process as present
    vmi_reset_process_present();
    //Set the swapper task as present
    vmi_set_process_pid_present(0);

    list_head h;
    h.next = 0;
    h.prev = 0;

    //Read initial task
    connection_read_memory(init_task_address + tasks_offset,(char*)&h,sizeof(list_head));

    //Traverse linked list
    while (h.next != 0 && h.next != (init_task_address + tasks_offset + kernel_shift)){
        //Read PID
        uint32_t pid = 0;
        pyrebox_target_ulong exit_state = 0;
        qemu_virtual_memory_rw_with_pgd(pgd,h.next - tasks_offset + pid_offset,(uint8_t*)&pid,4,0);
        qemu_virtual_memory_rw_with_pgd(pgd,h.next - tasks_offset + exit_state_offset,(uint8_t*)&exit_state,4,0);
        //If the process does not have an exit state (still active), and it nos present in our process list:
        if (exit_state == 0 && is_process_pid_in_list((pyrebox_target_ulong)pid) == PROC_NOT_PRESENT){
            //Read mm pointer
            //Read PGD
            //Read Pid, ppid, name
            pyrebox_target_ulong mm_addr = 0;
            pyrebox_target_ulong proc_pgd = 0;
            uint32_t ppid = 0;
            pyrebox_target_ulong parent_task = 0;
            char proc_name[MAX_PROCNAME_LEN];
            //Set string to 0
            memset(proc_name,0,MAX_PROCNAME_LEN);
            assert(MAX_PROCNAME_LEN >= LINUX_PROCESS_NAME_SIZE);
            qemu_virtual_memory_rw_with_pgd(pgd,h.next - tasks_offset + mm_offset,(uint8_t*)&mm_addr,sizeof(pyrebox_target_ulong),0);
            if (mm_addr == 0 || mm_addr == (pyrebox_target_ulong) -1){
                proc_pgd = 0;
            } else {
                qemu_virtual_memory_rw_with_pgd(pgd,mm_addr + pgd_offset,(uint8_t*)&proc_pgd,sizeof(pyrebox_target_ulong),0);
                proc_pgd = qemu_virtual_to_physical_with_pgd(pgd,proc_pgd);
            }
            qemu_virtual_memory_rw_with_pgd(pgd,h.next - tasks_offset + parent_offset,(uint8_t*)&parent_task,sizeof(pyrebox_target_ulong),0);
            if (parent_task != 0){
                qemu_virtual_memory_rw_with_pgd(pgd,parent_task + pid_offset,(uint8_t*)&ppid,4,0);
            }
            qemu_virtual_memory_rw_with_pgd(pgd,h.next - tasks_offset + comm_offset,(uint8_t*)&proc_name,LINUX_PROCESS_NAME_SIZE,0);
             
            //utils_print_debug("[!] Curr PGD: %016lx Proc PGD: %016lx PID: %016x PPID: %x (%016x) State: %x Name: %s\n",pgd,proc_pgd,pid,ppid,(h.next - tasks_offset + comm_offset),exit_state,proc_name);
            //Add the process
            vmi_add_process(proc_pgd, (pyrebox_target_ulong)pid, (pyrebox_target_ulong)ppid, h.next - tasks_offset, 0,(char*) proc_name);
            //Mark the process as present
            vmi_set_process_pid_present((pyrebox_target_ulong)pid);

            //Init task 
            if (pid == 1){
                 //Now, initialize volatility address space
                 linux_init_address_space();
            }
        //If the process is present, but the exit_state is != 0, it means the process has exited but the task struct is
        //still there, so we just remove it from the list (do not mark as present).
        } else if (exit_state == 0){
            //Mark the process as present
            vmi_set_process_pid_present((pyrebox_target_ulong)pid);
        }
        if (h.next != 0){
            //Now, read pointer to next process, only if we want to continue
            qemu_virtual_memory_rw_with_pgd(pgd,h.next,(uint8_t*)&h,sizeof(list_head),0);
        }
    }

    //Remove non-present processes
    vmi_remove_not_present_processes();
    vmi_reset_process_present();
}

void linux_vmi_context_change_callback(pyrebox_target_ulong old_pgd,pyrebox_target_ulong new_pgd, os_index_t os_index){
    //Callback not used currently
    return;
}

void process_create_delete_callback(callback_params_t params){
    update_process_list(get_pgd(params.insn_begin_params.cpu));
}


void linux_vmi_tlb_callback(pyrebox_target_ulong pgd, os_index_t os_index){

    if (init_task_address == 0 || process_list_valid == 0 || populate_initial_process_list == 1){
        tlb_counter += 1;
        if (tlb_counter % 1000 == 0){
            initialize_init_task(pgd);
        }
    }
}

void initialize_init_task(pyrebox_target_ulong pgd){
    //Array to contain the possible hardcoded shifts
    pyrebox_target_ulong shifts[3] = {0,0,0};
    int number_shifts = 0;

    //If the init_task_address has not been yet found,
    //we first try to locate it in the physical memory.
    //If kaslr is not in place, it should be located at a fixed
    //virtual offset. Then, we just need to try different
    //kernel shifts in order to find how the kernel is mapped
    //into physical memory (due to identity paging).
    //Once we locate the init_task, we can compute the 
    //kernel shift.
    //If kaslr is in place, or the shift is not on the list (has
    //been modified), we need to find the init_task_addr by 
    //scanning the physical memory. Then we compute the kernel 
    //shift based on the diffence between the init_task_addr (physical
    //offset) and the virtual offset declared in the System.map).
    if (init_task_address == 0){
        //Check if we can locate the swapper task. If so, initialize the volatility address space, and check for new processes
        //32 bit linux
        #if TARGET_LONG_SIZE == 4
            shifts[0] = 0xc0000000;
            number_shifts = 1;
        //64 bit linux
        #elif TARGET_LONG_SIZE == 8
            shifts[0] = 0xffffffff80000000;
            shifts[1] = 0xffffffff80000000 - 0x1000000;
            shifts[2] = 0xffffffff7fe00000;
            number_shifts = 3;
        #else
            #error TARGET_LONG_SIZE undefined
        #endif
        pyrebox_target_ulong addr;
        char buf[12];
        for(int i = 0; i < number_shifts && init_task_address == 0; i++){
            addr = init_task_offset - shifts[i] + comm_offset;
            //Read 12 bytes of the address and check if it contains "swapper"
            connection_read_memory(addr,(char*) buf,12);
            if(!strncmp((const char*)buf,"swapper",7)){
                //Physical address
                init_task_address = addr - comm_offset;
                kernel_shift = shifts[i];
                //Set flag to trigger initial process list population
                populate_initial_process_list = 1;
                utils_print_debug("[*] init_task located at: %016x\n", init_task_address);
                utils_print_debug("[*] kernel shift: %016lx\n", kernel_shift);
            }
        }
        //If we could not find the swapper task with the previous method, then 
        //we try to find it, in case theres KASLR in place
        if (init_task_address == 0){
            //We search it in physical memory instead of virtual memory, due to
            //identity paging we should not have any problem to locate the different 
            //offsets of task struct.
            uint64_t memory_size = get_memory_size();
            uint8_t buff[0x2000];
            //Search in blocks of 2 pages, overlapping 1 page each time
            for (uint64_t mem_addr = 0; (mem_addr+0x2000) <= memory_size; mem_addr += 0x1000){
                connection_read_memory(mem_addr,(char*)buff,0x2000);
                //Search in the buffer
                //needle -> "swapper/0\x00\x00\x00\x00\x00\x00"
                uint8_t needle[15] = {0x73, 0x77, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2f, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                unsigned int offset = 0;
                while(init_task_address == 0 && offset < (0x2000 - 15)){
                    uint8_t* p = (uint8_t*) memmem(buff + offset, 0x2000 - offset, needle, 15);
                    if (p != 0){
                        //Needle found
                        offset = p - buff;
                        uint64_t swapper_address = (mem_addr + offset) - comm_offset;
                        uint8_t chunk1[4] = {0,0,0,0};
                        uint8_t chunk2[4] = {0,0,0,0};
                        //Check first 4 bytes (must be 0) the PID (must be 0) and the alignment
                        //of the KASLR shift, (must be page aligned).
                        connection_read_memory(swapper_address,(char*)chunk1,4);
                        connection_read_memory(swapper_address + pid_offset,(char*)chunk2,4);
                        if (*((uint32_t*)chunk1) == 0 && 
                            *((uint32_t*)chunk2) == 0 && 
                            ((swapper_address - (init_task_offset - shifts[0])) & 0xfff) == 0x0){
                            init_task_address = swapper_address;
                            //Set flag to trigger initial process list population
                            populate_initial_process_list = 1;
                            kernel_shift = (init_task_offset - swapper_address);
                            utils_print_debug("[*] init_task located at: %016x\n", init_task_address);
                            utils_print_debug("[*] kernel shift: %016x\n", kernel_shift);
                        }
                    } else {
                        //Force while exit
                        offset = 0x2000;
                    }
                }
            }
        }
    }
    //Once we have located the init_task_addr, we wait until
    //the next & prev pointers are correctly initialized and the 
    //task list is already valid.
    //Check when we have a real valid swapper task (during boot)
    if (init_task_address != 0 && process_list_valid == 0){
        //Read init task address
        list_head h;
        h.next = 0;
        h.prev = 0;
        connection_read_memory(init_task_address + tasks_offset,(char*)&h,sizeof(list_head));

        //During boot, in the beginning, next and prev are either 0 or garbage data.
        //The tasks pointers are not valid until they point to the task itself.
        if (h.next != 0){
            //If we are booting up and init_task is just pointing to itself, we are fine
            //If we are not booting up, we should check the validity of the tasks list:
            //Go to the first task, then go to the next one, and then go back with the prev pointer and check if it points to the first one
            //At this point, h.next would be pointing to the first task's list_head (the first after swapper)
            qemu_virtual_memory_rw_with_pgd(pgd,h.next,(uint8_t*)&h,sizeof(list_head),0);
            //Now, h.prev would be pointing to the first task (swapper task)
            if ((h.prev - tasks_offset) == (init_task_address + kernel_shift)){
                //utils_print_debug("[*] Adding initial swapper process...\n");
                process_list_valid = 1;
                //Add the swapper task
                vmi_add_process(0, 0, 0, init_task_address, 0,(char*)"swapper");
                //Add internal callbacks for process creation and exit
                add_internal_callback(0,proc_exec_connector_offset,process_create_delete_callback);
                add_internal_callback(0,proc_exit_connector_offset,process_create_delete_callback);
            }
        }
    }

    //Finally, we do an initial process list initialization.
    if (process_list_valid != 0 && (populate_initial_process_list > 0)){
        update_process_list(pgd);
        //Reset this flag, because we already should have populated the list
        populate_initial_process_list = 0;
    }

}


