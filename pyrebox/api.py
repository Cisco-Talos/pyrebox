#-------------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox 
#   Author: Xabier Ugarte-Pedrero 
#   
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#   
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#   
#-------------------------------------------------------------------------------

"""
.. module:: api
   :platform: Unix
   :synopsis: PyREbox API 

.. moduleauthor:: Xabier Ugarte-Pedrero
"""
import traceback
from cpus import X86CPU
from cpus import X64CPU
from api_internal import *
import functools

#================================================== API FUNCTIONS ====================================================

#This python script wraps the c based API, and also provides new API functionality such as module/symbol info retrieval

def r_pa(addr,length):
    """ Read physical address

        :param addr: The address to read
        :type addr: int

        :param length: The length to read, between 0 and 0x2000 bytes
        :type length: int

        :return: The read content
        :rtype: str
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.r_pa(addr,length)

def r_va(pgd,addr,length):
    """Read virtual address

        :param pgd: The PGD (address space) to read from.
        :type pgd: int

        :param addr: The address to read
        :type addr: int

        :param length: The length to read, between 0 and 0x2000 bytes
        :type length: int

        :return: The read content
        :rtype: str
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.r_va(pgd,addr,length)

def r_cpu(cpu_index = 0):
    """Read CPU register values 
        :param cpu_index: The CPU index to read. 0 by default.
        :type cpu_index: int
        
        :return: The CPU
        :rtype: X64CPU | X86CPU | ...
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.r_cpu(cpu_index)

def w_pa(addr,buff,length):
    """Write physical address

        :param addr: The address to write
        :type addr: int

        :param buff: The buffer to write, between 0 and 0x2000 bytes
        :type buffer: str

        :param length: The length to write, between 0 and 0x2000 bytes
        :type length: int

        :return: None 
        :rtype: None
    """
    import c_api
    if len(buff) != length:
        raise ValueError("Length of the buffer does not match the declared length")
    else:
        #If this function call fails, it will raise an exception. 
        #Given that the exception is self explanatory, we just let it propagate upwards 
        return c_api.w_pa(addr,buff)

def w_va(pgd,addr,buff,length):
    """Write virtual address

        :param pgd: The PGD (address space) to write to.
        :type pgd: int

        :param addr: The address to write
        :type addr: int

        :param buff: The buffer to write, between 0 and 0x2000 bytes
        :type buffer: str

        :param length: The length to write, between 0 and 0x2000 bytes
        :type length: int

        :return: None 
        :rtype: None
    """
    import c_api
    if len(buff) != length:
        raise ValueError("Length of the buffer does not match the declared length")
    else:
        #If this function call fails, it will raise an exception. 
        #Given that the exception is self explanatory, we just let it propagate upwards 
        return c_api.w_va(pgd,addr,buff)

def r_ioport(address,size):
    """Read I/O port

        :param address: The port address to read, from 0 to 65536
        :type address: int

        :param size: The size to read (1, 2, or 4)
        :type size: int

        :return: The value read
        :rtype: int
    """
    import c_api
    if size not in [1,2,4]:
        raise ValueError("Incorrect size to read: it must be 1, 2 or 4")
    if address < 0 or address > 65536:
        raise ValueError("Incorrect port address: it must be between 0-65536")
    return c_api.r_ioport(address,size)

def w_ioport(address,size,value):
    """Write I/O port

        :param address: The port address to write, from 0 to 65536
        :type address: int

        :param size: The size to read (1, 2, or 4)
        :type size: int

        :return: The value written 
        :rtype: int
    """
    import c_api
    if size not in [1,2,4]:
        raise ValueError("Incorrect size to read: it must be 1, 2 or 4")
    if address < 0 or address > 65536:
        raise ValueError("Incorrect port address: it must be between 0-65536")
    return c_api.w_ioport(address,size,value)

def w_r(cpu_index,regname,val):
    """Write register

        :param cpu_index: CPU index of the register to write
        :type cpu_index: int

        :param regname: Name of the register to write
        :type regname: str

        :param val: Value to write
        :type val: int

        :return: None
        :rtype: None
    """
    from utils import ConfigurationManager as conf_m
    import c_api

    if conf_m.conf.platform == "i386-softmmu":
        if regname in X86CPU.reg_nums:
            #If this function call fails, it will raise an exception. 
            #Given that the exception is self explanatory, we just let it propagate upwards 
            return c_api.w_r(cpu_index,X86CPU.reg_nums[regname],val)
        else:
            raise ValueError("[w_r] Wrong register specification")
    elif conf_m.conf.platform == "x86_64-softmmu":
        if regname in X64CPU.reg_nums:
            #If this function call fails, it will raise an exception. 
            #Given that the exception is self explanatory, we just let it propagate upwards 
            return c_api.w_r(cpu_index,X64CPU.reg_nums[regname],val)
        else:
            raise ValueError("[w_r] Wrong register specification")
    else:
        raise ValueError("[w_r] Wrong platform specification")

def w_sr(cpu_index,regname,selector,base,limit,flags):
    """Write segment register. Only applies to x86 / x86-64

        :param cpu_index: CPU index of the register to write
        :type cpu_index: int

        :param regname: Name of the register to write
        :type regname: str

        :param selector: Value (selector) to write
        :type selector: int

        :param base: Value (base) to write
        :type selector: int

        :param limit: Value (limit) to write
        :type selector: int

        :return: None
        :rtype: None
    """
    from utils import ConfigurationManager as conf_m
    import c_api

    if conf_m.conf.platform == "i386-softmmu":
        if regname in X86CPU.reg_nums:
            #If this function call fails, it will raise an exception. 
            #Given that the exception is self explanatory, we just let it propagate upwards 
            return c_api.w_sr(cpu_index,X86CPU.reg_nums[regname],selector,base,limit,flags)
        else:
            raise ValueError("[w_r] Wrong register specification")
    elif conf_m.conf.platform == "x86_64-softmmu":
        if regname in X64CPU.reg_nums:
            #If this function call fails, it will raise an exception. 
            #Given that the exception is self explanatory, we just let it propagate upwards 
            return c_api.w_sr(cpu_index,X64CPU.reg_nums[regname],selector,base,limit,flags)
        else:
            raise ValueError("[w_r] Wrong register specification")
    else:
        raise ValueError("[w_r] Wrong platform specification")
    
def va_to_pa(pgd,addr):
    """ Virtual to physical address.

        :param pgd: PGD, or address space of the address to translate  
        :type addr: int

        :param addr: Virtual address to translate
        :type addr: int

        :return: The translated physical address
        :rtype: int
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.va_to_pa(pgd,addr)

def start_monitoring_process(pgd):
    """ Start monitoring a process. Process-wide callbacks will be called for every process that is being monitored
        
        :param pgd: PGD, or address space of the process to check
        :type pgd: int

        :return: None
        :rtype: None
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.start_monitoring_process(pgd)

def is_monitored_process(pgd):
    """Returns true of a given process is being monitored. Process-wide callbacks will be called for every process that is being monitored

        :param pgd: PGD, or address space of the process to monitor
        :type pgd: int

        :return: True of the process is being monitored, False otherwise
        :rtype: bool
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.is_monitored_process(pgd)

def stop_monitoring_process(pgd,force=False):
    """ Start monitoring a process. Process-wide callbacks will be called for every process that is being monitored
        
        :param pgd: PGD, or address space of the process to stop monitoring
        :type pgd: int

        :return: None
        :rtype: None
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.stop_monitoring_process(pgd,1 if force else 0)

def get_running_process(cpu_index = 0):
    """Returns the PGD or address space of the process that is being executed at this moment
        
        :param cpu_index: CPU index that we want to query. Each CPU might be executing a different address space
        :type cpu_index: int

        :return: The PGD or address space for the process that is executing on the indicated CPU
        :rtype: int
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.get_running_process(cpu_index)

def get_num_cpus():
    """ Returns the number of CPUs on the emulated system

        :return: The number of CPUs on the emulated system
        :rtype: int
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.get_num_cpus()

def is_kernel_running(cpu_index):
    """ Returns True if the corresponding CPU is executing in Ring 0

        :param cpu_index: CPU index that we want to query. Each CPU might be executing a different address space
        :type cpu_index: int

        :return: True if the corresponding CPU is executing in Ring 0, False otherwise 
        :rtype: bool
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.is_kernel_running(cpu_index)

def save_vm(name):
    """Save the state of the virtual machine so that it can be restored later
    
        :param name: Name of the snapshot to save
        :type name: str

        :return: None
        :rtype: None
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.save_vm(name)

def load_vm(name):
    """Load a previously saved snapshot of the virtual machine.

        :param name: Name of the snapshot to load 
        :type name: str

        :return: None
        :rtype: None
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.load_vm(name)

def get_process_list():
    """ Return list of processes.

        :return: List of processes. List of dictionaries with keys: "pid", "pgd", "name", "kaddr", where kaddr stands for the kernel address representing the process (e.g.: EPROCESS)
        :rtype: list
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.get_process_list()

def get_os_bits():
    """ Return the bitness of the system / O.S. being emulated

        :return: The bitness of the system / O.S. being emualated
        :rtype: int
    """
    import c_api
    #If this function call fails, it will raise an exception. 
    #Given that the exception is self explanatory, we just let it propagate upwards 
    return c_api.get_os_bits()

#Rest of API functions
def get_module_list(pgd):
    """ Return list of modules for a given PGD

        :param pgd: The PGD of the process for which we want to extract the modules
        :type pgd: int

        :return: List of modules, each element is a dictionary with keys: "name", "base", and "size"
        :rtype: list
    """
    import vmi
    import windows_vmi
    proc_list = get_process_list()
    mods = []
    found = False
    for proc in proc_list: 
        proc_pid = proc["pid"]
        proc_pgd = proc["pgd"]
        if proc_pgd == pgd:
            found = True
            windows_vmi.windows_update_modules(proc_pgd,update_symbols=False)
            for mod in vmi.modules[(proc_pid,proc_pgd)].values():
                mods.append({"name": mod.get_name(), "base": mod.get_base(), "size": mod.get_size()})
    if found:
        return mods
    else:
        raise ValueError("Process with PGD %x not found" % pgd)

def get_symbol_list():
    """ Return list of symbols 

        :return: List of symbols, each element is a dictionary with keys: "mod", "name", and "addr"
        :rtype: list
    """
    import vmi
    import windows_vmi
    from utils import pp_print
    syms = []
    diff_modules = {}
    proc_list = get_process_list()
    pp_print("[*] Updating symbol list... Be patient, this may take a while\n")
    for proc in proc_list: 
        proc_pid = proc["pid"]
        proc_pgd = proc["pgd"]
        windows_vmi.windows_update_modules(proc_pgd,update_symbols=True)
        for module in vmi.modules[proc_pid,proc_pgd].values():
            c =  module.get_checksum()
            n = module.get_fullname()
            if (c,n) not in diff_modules:
                diff_modules[(c,n)] = module
    for mod in diff_modules.values():
        for ordinal,addr,name in mod.get_symbols():
            syms.append({"mod": mod.get_name(),"name": name, "addr": addr})
    return syms

def sym_to_va(pgd,mod_name,func_name):
    """ Resolve an address given a symbol name

        :param pgd: The PGD or address space for the process for which we want to search the symbol
        :type pgd: int

        :param mod_name: The module name that contains the symbol
        :type mod_name: str

        :param func_name: The function name to resolve
        :type func_name: str

        :return: The address, or None if the symbol is not found
        :rtype: str
    """
    import vmi
    mod_name = mod_name.lower()
    func_name = func_name.lower()
    for proc_pid,proc_pgd in vmi.modules:
        if proc_pgd == pgd:
            for module in vmi.modules[proc_pid,proc_pgd].values():
                if mod_name in module.get_name().lower():
                    syms = module.get_symbols()
                    for ordinal,symbol_offset,name in syms:
                        if func_name == name.lower():
                            return (module.get_base() + symbol_offset)
        else:
            raise ValueError("Process with PGD %x not found"  % pgd)
    return None

def va_to_sym(pgd,addr):
    """ Find symbols for a particular virtual address

        :param pgd: The PGD or address space for the process for which we want to search the symbol
        :type pgd: int

        :param addr: The virtual address to search 
        :type addr: int

        :return: A tuple containing the module name and the function name, None if nothing found
        :rtype: tuple 
    """
    import vmi
    mod_name = mod_name.lower()
    func_name = func_name.lower()
    for proc_pid,proc_pgd in vmi.modules:
        if proc_pgd == pgd:
            for module in vmi.modules[proc_pid,proc_pgd].values():
                offset = (addr - module.get_base())
                if offset > 0 and offset < module.get_size():
                    syms = module.get_symbols()
                    if (ordinal,offset,name) in syms:
                        return (module.get_name(),name)
        else:
            raise ValueError("Process with PGD %x not found"  % pgd)

    return None

#================================================== CLASSES  ====================================================

class CallbackManager:
    '''
        Class that abstracts callback management,optionally associating names to callbacks, and registering the list of 
        added callbacks so that we can remove them all with a single call to "clean()" after we are done.
    '''
    INV0_CB = 0 #Shadow optimized callbacks for block and insn begin
    INV1_CB = 1 #Shadow optimized callbacks for block and insn begin
    BLOCK_BEGIN_CB = 2
    BLOCK_END_CB = 3
    INSN_BEGIN_CB = 4
    INSN_END_CB = 5
    MEM_READ_CB = 6
    MEM_WRITE_CB = 7
    KEYSTROKE_CB = 8
    NIC_REC_CB = 9
    NIC_SEND_CB = 10
    OPCODE_RANGE_CB = 11
    TLB_EXEC_CB = 12
    CREATEPROC_CB = 13
    REMOVEPROC_CB = 14
    CONTEXTCHANGE_CB = 15

    def __init__(self,module_hdl):
        """ Constructor of the class
            
            :param module_hdl: The module handle provided to the script as parameter to the initialize_callbacks function. Use 0 if it doesn't apply.
            :type module_hdl: int
        """
        self.callbacks = {}
        self.module_hdl = module_hdl

    def __generate_callback_name(self,name):
        """ Generates a unique callback name given an initial name

            :param name: The initial name
            :type name: str

            :return: The new generated name
            :rtype: str
        """
        subname = name
        if subname in self.callbacks:
            counter = 1
            while subname in self.callbacks:
                subname = "%s_%d" % (name,counter)
                counter += 1
        return name

    def add_callback(self,callback_type,func,name=None,addr=None,pgd=None,start_opcode=None,end_opcode=None):
        """ Add a callback to the module, given a name, so that we can refer to it later. 
        
            If the name is repeated, it will provide back a new name based on the one passed as argument,
            that can be used later for removing it or attaching triggers to it.
            
            :param name: The name of the callback
            :type name: str

            :param callback_type: The callback type to insert. One of INSN_BEGIN_CB, BLOCK_BEGIN_CB, etc... See help(api) from a pyrebox shell to get a complete listing of constants ending in _CB
            :type callback_type: int

            :param func: The callback function (python function) 
            :type func: function

            :param addr: Optional. The address where we want to place the callback. Only applies to INSN_BEGIN_CB, BLOCK_BEGIN_CB 
            :type addr: int

            :param pgd: Optional. The PGD (addr space) where we want to place the callback. Only applies to INSN_BEGIN_CB, BLOCK_BEGIN_CB 
            :type pgd: int

            :return: The actual inserted callback name. If the callback name indicated already existed, this name will be updated to make it unique. This name can be used as a handle to the callback
            :rtype: str
        """
        import random,string,time
        #If a name was not provided, just provide a 16 lowercase letter random name
        if name is None:
            random.seed(time.time())
            name = "".join(random.choice(string.lowercase) for i in range(16))
        name = self.__generate_callback_name(name)
        #addr,pgd and start_opcode,end_opcode are exclusive, so we join them together to call register_callback
        first_param = start_opcode if addr is None else addr
        second_param = end_opcode if pgd is None else pgd
        self.callbacks[name] = register_callback(self.module_hdl,callback_type,wrap(func),first_param,second_param)
        return name

    def rm_callback(self,name):
        """ Remove a callback given its name. Associated triggers will get unloaded too.

            :param name: The name of the callback to remove
            :type name: str

            :return: None
            :rtype: None
        """
        if name not in self.callbacks:
            raise ValueError("[!] CallbackManager: A callback with name %s does not exist and cannot be removed\n" % (name))
            return
        unregister_callback(self.callbacks[name])
        del(self.callbacks[name])

    def callback_exists(self,name):
        """ Determine if a callback exists or not, given its name 

            :param name: The callback name to check 
            :type name: str

            :return: True if the callback already exists
            :rtype: bool
        """
        return (name in self.callbacks)

    def add_trigger(self,name,trigger_path):
        ''' Add trigger to a callback.

            Adds a trigger to a given callback. If the trigger is not compiled or the binary is outdated,
            it will force a compilation of the trigger before loading it.

            :param name: The callback name to which we want to add the trigger
            :type name: str

            :param trigger_path: The path to the trigger. 
            :type trigger_path: str

            :return: None
            :rtype: None
        '''
        from utils import ConfigurationManager as conf_m
        import subprocess
        import os
        if name not in self.callbacks:
            raise ValueError("[!] CallbackManager: A callback with name %s does not exist\n" % (name))
            return
        #Remove ".so" from the path, if present
        if trigger_path[-3:] == ".so":
            trigger_path = trigger_path[:-3]
        #Check if we have the plugin compiled for the correct architecture
        trigger_path = "%s-%s.so" % (trigger_path, conf_m.conf.platform)
        p = subprocess.Popen("make %s" % trigger_path, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        p.wait()
        if os.path.isfile(trigger_path):
            #Trigger compiled correctly
            add_trigger(self.callbacks[name],trigger_path)
        else:
            raise ValueError("Could not correctly compile trigger\n")

    def rm_trigger(self,name):
        ''' Remove the trigger from the callback specified as parameter

            :param name: The callback name from which we want to remove the trigger
            :type name: str

            :return: None
            :rtype: None
        '''
        if name not in self.callbacks:
            raise ValueError("[!] CallbackManager: A callback with name %s does not exist\n" % (name))
            return
        remove_trigger(self.callbacks[name])

    def set_trigger_var(self,name,var_name,val):
        '''
        Add a trigger variable with name var_name and value val, to the callback with the given name

            :param name: Name of the callback 
            :type name: str

            :param var_name: Name of the variable to set
            :type var_name: str

            :param val: Value of the variable to set
            :type val: unsigned int or str

            :return: None
            :rtype: None
        '''
        from utils import ConfigurationManager as conf_m

        if name not in self.callbacks:
            raise ValueError("[!] CallbackManager: A callback with name %s does not exist\n" % (name))
            return
        if type(val) == str:
            set_trigger_str(self.callbacks[name],var_name,val)
        elif (type(val) == int or type(val) == long) and val < 0:
            raise ValueError("Negative integers not supported, use only unsigned integers")
        elif (type(val) == int or type(val) == long) and conf_m.conf.platform == "i386-softmmu":
            set_trigger_uint32(self.callbacks[name],var_name,val)
        elif (type(val) == int or type(val) == long) and conf_m.conf.platform == "x86_64-softmmu":
            set_trigger_uint64(self.callbacks[name],var_name,long(val))
        else:
            raise ValueError("[!] Unsupported trigger var type: %s\n" % str(type(val)))

    def get_trigger_var(self,name,var_name):
        '''
        Get a trigger variable associated to callback (name) with variable name var_name

            :param name: The callback name
            :type name: str

            :param var_name: The variable name
            :type var_name: str

            :return: The value, if it exists, None otherwise
            :rtype: str or int
        '''
        if name not in self.callbacks:
            raise ValueError("[!] CallbackManager: A callback with name %s does not exist\n" % (name))
            return
        return get_trigger_var(self.callbacks[name],var_name)

    def clean(self):
        """ Clean all the inserted callbacks. 
        
            Clean all the inserted callbacks. Will remove all the callbacks registered within this manager.

            :return: None
            :rtype: None
        """
        names = self.callbacks.keys()
        for name in names:
            self.rm_callback(name)

#================================================== CLASSES ====================================================

class BP:
    '''
    Class used to create execution, memory read, and memory write breakpoints
    '''
    EXECUTION = 0
    MEM_READ = 1
    MEM_WRITE = 2
    __active_bps = {}
    __cm = CallbackManager(0)
    __bp_num = 0

    def __init__(self,addr,pgd,size=0,typ=0):
        """ Constructor for a BreakPoint

            :param addr: The (start) address where we want to put the breakpoint
            :type addr: int

            :param pgd: The PGD or address space where we want to put the breakpoing
            :type pgd: int

            :param size: Optional. The size of the area we want to put a breakpoint on. We can put the BP on a single address or a memory range.
            :type size: int

            :param typ: The type of breakpoint: BP.EXECUTION, BP.MEM_READ, BP.MEM_WRITE
            :type typ: int
            
            :return: An instance of class BP for the inserted breakpoint
            :rtype: BP
        """

        self.typ = typ
        typ_str = "x" if typ==self.EXECUTION else ("r" if typ==self.MEM_READ else "w")
        self.__bp_repr = "BP%s_%d" % (typ_str,BP.__bp_num)
        BP.__bp_num += 1
        self.addr = addr
        self.pgd = pgd
        self.en = False
        if (typ == self.MEM_READ or typ == self.MEM_WRITE) and size == 0:
            self.size = 1
        else:
            self.size = size
        self.func = functools.partial(bp_func,self.__bp_repr)

    def __str__(self):
        """ String representation of the breakpoint
        
            :return: The string representation of the breakpoint
            :rtype: str
        """
        return self.__bp_repr

    def get_addr(self):
        """ Get the address where the breakpoint is registered

            :return: The address
            :rtype: int
        """
        return self.addr

    def get_pgd(self):
        """ Get the PGD of the process where the breakpoint is registered

            :return: The PGD of the process where the breakpoint is registered
            :rtype: int
        """
        return self.pgd

    def get_size(self):
        """ Get the size of the breakpoint

            :return: The size of the breakpoint
            :rtype: int
        """
        return self.size

    def get_type(self):
        """ Get the type of the breakpoint

            :return: The type of the breakpoint: BP.EXECUTION, BP.MEM_READ, BP.MEM_WRITE
            :rtype: int
        """
        return self.typ

    def enabled(self):
        """ Return whether the breakpoint is enabled or not

            :return: Whether the breakpoint is enabled or not
            :rtype: bool
        """
        return self.en

    def enable(self):
        """ Enable a breakpoint

            :return: None
            :rtype: None
        """
        if not self.en:
            self.en = True
            if self.typ == self.EXECUTION:
                if self.size == 0:
                    self.__bp_repr = BP.__cm.add_callback(CallbackManager.INSN_BEGIN_CB,self.func,name=self.__bp_repr,addr=self.addr,pgd=self.pgd)
                else:
                    if not is_monitored_process(self.pgd):
                        start_monitoring_process(self.pgd)
                    if not self.pgd in BP.__active_bps:
                        BP.__active_bps[self.pgd] = 1
                    else:
                        BP.__active_bps[self.pgd] += 1
                    self.__bp_repr = BP.__cm.add_callback(CallbackManager.INSN_BEGIN_CB,self.func,name=self.__bp_repr)
                    BP.__cm.add_trigger(self.__bp_repr,"triggers/trigger_bp_memrange.so")
                    BP.__cm.set_trigger_var(self.__bp_repr,"begin",self.addr)
                    BP.__cm.set_trigger_var(self.__bp_repr,"end",self.addr+self.size)
                    BP.__cm.set_trigger_var(self.__bp_repr,"pgd",self.pgd)
            elif self.typ == self.MEM_READ:
                if not is_monitored_process(self.pgd):
                    start_monitoring_process(self.pgd)
                if not self.pgd in BP.__active_bps:
                    BP.__active_bps[self.pgd] = 1
                else:
                    BP.__active_bps[self.pgd] += 1
                self.__bp_repr = BP.__cm.add_callback(CallbackManager.MEM_READ_CB,self.func,name=self.__bp_repr)
                BP.__cm.add_trigger(self.__bp_repr,"triggers/trigger_bpr_memrange.so")
                BP.__cm.set_trigger_var(self.__bp_repr,"begin",self.addr)
                BP.__cm.set_trigger_var(self.__bp_repr,"end",self.addr+self.size)
                BP.__cm.set_trigger_var(self.__bp_repr,"pgd",self.pgd)
            elif self.typ == self.MEM_WRITE:
                if not is_monitored_process(self.pgd):
                    start_monitoring_process(self.pgd)
                if not self.pgd in BP.__active_bps:
                    BP.__active_bps[self.pgd] = 1
                else:
                    BP.__active_bps[self.pgd] += 1
                self.__bp_repr = BP.__cm.add_callback(CallbackManager.MEM_WRITE_CB,self.func,name=self.__bp_repr)
                BP.__cm.add_trigger(self.__bp_repr,"triggers/trigger_bpw_memrange.so")
                BP.__cm.set_trigger_var(self.__bp_repr,"begin",self.addr)
                BP.__cm.set_trigger_var(self.__bp_repr,"end",self.addr+self.size)
                BP.__cm.set_trigger_var(self.__bp_repr,"pgd",self.pgd)

    def disable(self):
        """ Disable a breakpoint

            :return: None
            :rtype: None
        """

        if self.en:
            self.en = False
            #Trigger is deleted automagically
            BP.__cm.rm_callback(self.__bp_repr)
            if self.pgd in BP.__active_bps:
                BP.__active_bps[self.pgd] -= 1
                if BP.__active_bps[self.pgd] == 0:
                    stop_monitoring_process(self.pgd)
