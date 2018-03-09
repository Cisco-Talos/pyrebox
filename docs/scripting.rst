.. _scripting:

Scripting in PyREBox
====================

PyREBox scripts (see examples under ``scripts/`` folder) allow to:

- Define new commands for the PyREBox environment.
- Define callbacks (functions that will be called on different events for each of the monitored processes).
- Assign triggers to callbacks.
- Use the python API exported by PyREBox, allowing:
    - To query processes, modules.
    - To query symbols (API name resolution).
    - To read and manipulate registers and memory.
    - To start a PyREBox shell.
    - To make use of the volatility library.

Examples
--------

You can find self-documented examples in the scripts folder. New scripts and contributions will be added there.

Script life-cycle
-----------------

PyREBox scripts can be loaded and unloaded dynamically at any moment during the execution of the VM. The configuration 
file pyrebox.conf allows to specify a list of scripts that should be loaded at startup.

After this moment, you can load or unload scripts using the ``import_module`` and ``unload_module`` commands on QEMU's prompt.

Additionally, if a script has been loaded but you modified its code, you can reload it using the ``reload_module`` command.

In the ``scripts/`` directory you can find a good self-documented example PyREBox script.

Any PyREBox script needs to implement 2 basic functions: ``initialize_callbacks`` and ``clean``. The
first one will be called when the script is loaded, while the second one will be called when it is 
unloaded. The first one can register the callbacks you want to listen to, while the latter
should unregister them. The clean() function of the CallbackManager class will help you 
to unregister all the active callbacks previously registered for a CallbackManager instance.

A script can optionally have one additional member named ``requirements``, which consists
of a list of additional scripts (in python module notation), that should get loaded before
the script can be loaded.

Once the initialization function has been executed, the script will only be executed if:
  - One of the custom commands implemented in your script is executed.
  - Some callback is triggered by an event in the system.

Another important aspect is the concept of *monitored processes*. In general, the callbacks
will only be triggered for those processes being monitored. This limits the number of events
that trigger the execution of our script. You can set and unset which processes you want to monitor both
from the python API and from the interactive shell. Also, at any point you will be able to see
which processes are being monitored running the ``ps`` command in the PyREBox shell environment.

There are some exceptions to these rules:

- **Block begin / Instruction begin**. If an address and pgd are specified for the callback (see examples), this callback will be triggered only for that address and process, no matter if it is monitored or not.
- **Keystroke callback**. It will be called for all the processes in the system and in the context of any process in the system.
- **NIC send/receive**. It will be called for all the processes in the system and in the context of any process in the system. 
- **Opcode range callback**. It will be called at the instruction end for instructions with the specified opcodes, only for the monitored processes.
- **Triggers**. Triggers are C/C++ compiled shared objects that are associated to a given callback. This code will be executed before the python callback function is called, and can decide whether the callback should be delivered to the python function or not. This approach allows to improve the overall performance by setting arbitrary callback conditions. When a trigger is attached to a callback, the trigger will be executed for every event (no matter if the process is being monitored or not), and it is the responsibility of the developer to check that the callback happened in the appropiate context (usually checking the PGD, that determines the current address space).

Defining a new command
----------------------

In order to define a new command, you just need to declare a function in your script with the following prototype:
::
  def do_command(self,line):

Where ``command`` is the command name you want to create, and ``line`` is the argument containing all the command arguments.
When the script is loaded, the command will be available in the PyREBox shell. In order to use the command, you will
need to use the ``custom`` keyword, followed by the command name and its parameters. You can document your command
using the standard python docstring based documentation, that will be automatically loaded by PyREBox.


Callback types
--------------

This section lists the different callback types, together with a description
of the callback and the parameters that the python callback function expects.

There are some common data types used in many callbacks.

================= ==================================================================================
**Parameter**     **Description**
----------------- ---------------------------------------------------------------------------------- 
cpu               Object representing the CPU state. It will contain one member (field) for every register in the CPU
tb                Tuple containing information about the translation block (set of instructions translated at one time) by QEMU, similar in concept to a basic block. The tuple contains 3 values: (pc,size,icount), where pc is the program counter of the first instruction, size is the size of the block, and icount the number of instructions in it. **Translation blocks may not necessarily match basic blocks. The QEMU emulator will disassemble instruction by instruction until it finds either a control flow instruction, or a point where the next address cannot be guessed statically. All these instructions conform a translation block. Note that in some cases (e.g. special instructions), translation blocks may not necessarily match basic blocks.**
================= ==================================================================================

Block begin
***********

The callback is triggered for every executed translation block in the context of the monitored processes, at the beginning of the translation block. It is useful for tracing translation blocks. It allows to specify an address and PGD. In such a case, it will be triggered only for that address and process address space, no matter if the process is monitored or not.

Callback type:  ``CallbackManager.BLOCK_BEGIN_CB``

Example:
::
    cm.add_callback(CallbackManager.BLOCK_BEGIN_CB,my_function)

    cm.add_callback(CallbackManager.BLOCK_BEGIN_CB,my_function,address=address,pgd=pgd)

Callback interface:
::
    def my_function(cpu_index,cpu,tb): 
        ...

Block end
*********

The callback is triggered for every executed translation block in the context of the monitored processes, at the end of the translation block. It is useful for tracing translation blocks. The ``cur_pc`` 
parameter represents the current instruction pointer, while ``next_pc`` represents the next instruction to execute. When the callback is triggered, the emulated cpu is already at the start of the next instruction.

Callback type:  ``CallbackManager.BLOCK_END_CB``

Example:
::
    cm.add_callback(CallbackManager.BLOCK_END_CB,my_function)

Callback interface:
::
    def my_function(cpu_index,cpu,tb,cur_pc,next_pc): 
        ...

Instruction begin
*****************

Similar to previous callbacks, but at instruction level. Useful to trace single instructions. It allows to specify an address and pgd. In such a case, it will be triggered only for that address no matter if the process is monitored or not.

Callback type:  ``CallbackManager.INSN_BEGIN_CB``

Example:
::
    cm.add_callback(CallbackManager.INSN_BEGIN_CB,my_function)

    cm.add_callback(CallbackManager.INSN_BEGIN_CB,my_function,addr=addr,pgd=pgd)

Callback interface:
::
    def my_function(cpu_index,cpu): 
        ...

Instruction end
***************

Similar to previous callbacks, but at instruction level. Useful to trace single instructions. When the callback is triggered, the emulated cpu is already at the start of the next instruction.

Callback type:  ``CallbackManager.INSN_END_CB``

Example:
::
    cm.add_callback(CallbackManager.INSN_END_CB,my_function)

Callback interface:
::
    def my_function(cpu_index,cpu): 
        ...

Memory read
***********

Triggered whenever any memory address is read in any of the processes monitored. The parameter ``vaddr`` represents the modified virtual address. ``haddr`` is the corresponding physical address, and ``size`` is the size of the modification.

Callback type: ``CallbackManager.MEM_READ_CB``

Example:
::
    cm.add_callback(CallbackManager.MEM_READ_CB,my_function)

Callback interface:
::
    def my_function(cpu_index,vaddr,size,haddr):
        ...

Memory write
************

Triggered whenever any memory address is written in any of the processes monitored. The parameter ``vaddr`` represents the modified virtual address. ``haddr`` is the corresponding physical address, and ``size`` is the size of the modification. The callback is called *after* the memory has been written. The ``data`` parameter contains the written memory value.

Callback type: ``CallbackManager.MEM_WRITE_CB``

Example:
::
    cm.add_callback(CallbackManager.MEM_WRITE_CB,my_function)

Callback interface:
::
    def my_function(cpu_index,vaddr,size,haddr,data):
        ...

Keystroke event
***************

Triggered whenever a key is pressed into the system.

Callback type:  ``CallbackManager.KEYSTROKE_CB``

Example:
::
    cm.add_callback(CallbackManager.KEYSTROKE_CB,my_function)

Callback interface:
::
    def my_function(keycode): 
        ...


NIC send
********

Triggered whenever data is sent through the network interface. This event requires the network card to be configured in this way:
::
    -device ne2k_pci,netdev=network0

The parameter ``addr`` represents the address of the buffer, ``size`` represents its size, and buffer is the content being sent.
    
Callback type:  ``CallbackManager.NIC_SEND_CB``

Example:
::
    cm.add_callback(CallbackManager.NIC_SEND_CB,my_function)

Callback interface:
::
    def my_function(addr,size,buf): 
        ...

NIC receive 
***********

Triggered whenever data is received through the network interface. This event requires the network card to be configured in this way:
::
    -device ne2k_pci,netdev=network0

The parameter ``size`` represents its size, and ``buffer`` is the content being sent.

Callback type:  ``CallbackManager.NIC_REC_CB``

Example:
::
    cm.add_callback(CallbackManager.NIC_REC_CB,my_function)

Callback interface:
::
    def my_function(buf,size,cur_pos,start,stop): 
        ...

Opcode range callback
*********************

Triggered whenever an instruction with an opcode in the specified range is executed. E.g.: trigger for all call instructions, for the monitored processes.
This callback presents some particularities:
  - The callback is called after the instruction has been executed. The cpu parameter corresponds to this new state. Interrupt instructions are an exception. In those cases, it happens at instruccion beginning.
  - The ``pc`` parameter corresponds to the PC where the involved instruction was located.
  - The ``next_pc`` parameter corresponds to the next instruction. It might be 0 if the address is not provided in the instruction (e.g.: interrupts or return instructions).


Callback type:  ``CallbackManager.OPCODE_RANGE_CB``

Example:
::
    cm.add_callback(CallbackManager.OPCODE_RANGE_CB,my_function,start_opcode=0xE8,end_opcode=0xE9)

Callback interface:
::
    def my_function(cpu_index,cpu,pc,next_pc): 
        ...

TLB callback
************

Triggered for every TLB flush callback.

Callback type:  ``CallbackManager.TLB_EXEC_CB``

Example:
::
    cm.add_callback(CallbackManager.TLB_EXEC_CB,my_function)

Callback interface:
::
    def my_function(cpu,vaddr): 
        ...

Context change
**************

Triggered for every context change.

Callback type:  ``CallbackManager.CONTEXTCHANGE_CB``

Example:
::
    cm.add_callback(CallbackManager.CONTEXTCHANGE_CB,my_function)

Callback interface:
::
    def my_function(old_pgd, new_pgd): 
        ...


Create process
**************

Triggered whenever a new process is created in the system. Parameters are self-descriptive.

Callback type:  ``CallbackManager.CREATEPROC_CB``

Example:
::
    cm.add_callback(CallbackManager.VMI_CREATEPROC_CB,my_function)

Callback interface:
::
    def my_function(pid,cr3,name): 
        ...

Remove process
**************

Triggered whenever a new process is killed in the system. Parameters are self-descriptive.

Callback type:  ``CallbackManager.REMOVEPROC_CB``

Example:
::
    cm.add_callback(CallbackManager.REMOVEPROC_CB,my_function)

Interface:
::
    def my_function(pid,cr3,name): 
        ...

Module load
***********

Triggered whenever a library or a driver is loaded in the address space of a process. Parameters are self-descriptive.

Callback type:  ``CallbackManager.LOADMODULE_CB``

Example:
::
    cm.add_callback(CallbackManager.LOADMODULE_CB, my_function, pgd = cpu.CR3)

Callback interface:
::
    def my_function(pid, pgd, base, size, name, fullname): 
        ...

Module remove
*************

Triggered whenever a library or a driver is removed from the address space of a process. Parameters are self-descriptive.

Callback type:  ``CallbackManager.REMOVEPROC_CB``

Example:
::
    cm.add_callback(CallbackManager.REMOVEMODULE_CB, my_function, pgd = cpu.CR3)

Interface:
::
    def my_function(pid, pgd, base, size, name, fullname): 
        ...


Triggers
--------

Triggers are libraries developed in C/C++ that are compiled into native code and loaded at runtime. These triggers define a function named ``trigger`` that can perform any necessary computation and use the API offered by ``qemu_glue.h``. This function will then decide if the attached python callback should be executed or not. If the function returns 1, the python callback will be executed. If the function returns 0, the python callback is not executed.

**When a trigger is added to a callback, it will be called for every event happening in any process context (not only monitored processes). Note that this is different from the default behavior in certain callback types. For instance, if we add a block begin callback and attach a trigger to it, the trigger will be called every time a block is executed in any process on the system. The trigger should then decide whether the event must be followed by a python callback function call, or be ignored, by checking the process context, or any other relevant value.**

Triggers can access variables associated to the callback (trigger variables), which can be set in the python script once the trigger has been loaded.

You can find several examples of triggers under directory ``triggers/``.

Each trigger has to implement 3 functions (using the extern "C" clause): ``get_type``, ``trigger``, and
``clean``. 
  - **get_type** should return the callback type it can be loaded into. The system will not allow us to load a trigger into an incomptible callback type. 
  - **trigger** should return 1 if the callback should be executed, and 0 otherwise.
  - **clean** should clean all the variables (and deallocate memory), and it will be called only once, when the trigger is unloaded.

These triggers allow us to:
  - Precompute some condition and decide whether to call the python callback (reduce run-time overhead).
  - Precompute some value efficiently and store it in some variable that can be read afterwards from python.

In order to access variables, we need to use the functions ``get_var()``, and ``set_var()``.
::
  void* get_var(callback_handle_t handle, const char* key_str);
  void set_var(callback_handle_t handle, const char* key_str,void* val);

The value is a pointer in all cases. When a variable is created, you should allocate some memory and pass to the function the address of your allocated memory. If we call set_var() for an already existing variable, it will deallocate the memory pointed by the previous variable by calling free() over the pointer.

Be careful with using complex data structures, because the set_var() will only call free over the pointed chunck. It is your responsibility to avoid memory leaks when using these variables.

In order to create variables in a trigger accesible from python code (in its triggered python callback), see the provided examples and be careful with reference counting and garbage collection (scripts/getset_var_example.py). 

Bellow you can find the definition of the callback_params_t type
::
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
        pyrebox_target_ulong paddr;
        pyrebox_target_ulong size;
    } mem_read_params_t;

    typedef struct mem_write_params {
        int cpu_index;
        pyrebox_target_ulong vaddr;
        pyrebox_target_ulong paddr;
        pyrebox_target_ulong size;
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

In order to test if a trigger compiles correctly, cd to the PyREBox directory and run the following command. Adjust the target architecture and name of the plugin depending on your needs.
::
  make triggers/trigger_template-i386-softmmu.so

