# -------------------------------------------------------------------------
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
# -------------------------------------------------------------------------

"""
.. module:: api
   :platform: Unix
   :synopsis: PyREbox API

.. moduleauthor:: Xabier Ugarte-Pedrero
"""
from cpus import X86CPU
from cpus import X64CPU
from api_internal import bp_func
from api_internal import wrap
from api_internal import register_callback
from api_internal import unregister_callback
from api_internal import add_trigger
from api_internal import remove_trigger
from api_internal import set_trigger_uint32
from api_internal import set_trigger_uint64
from api_internal import set_trigger_str
from api_internal import get_trigger_var
from api_internal import unregister_module_load_callback
from api_internal import unregister_module_remove_callback
from api_internal import register_module_load_callback
from api_internal import register_module_remove_callback

import functools

# ================================================== API FUNCTIONS ========

# This python script wraps the c based API, and also provides new API
# functionality such as module/symbol info retrieval


def get_num_cpus():
    """ Returns the number of CPUs on the emulated system

        :return: The number of CPUs on the emulated system
        :rtype: int
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.get_num_cpus()


def r_pa(addr, length):
    """ Read physical address

        :param addr: The address to read
        :type addr: int

        :param length: The length to read
        :type length: int

        :return: The read content
        :rtype: str
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    offset = addr
    ret_buffer = ""
    while offset < (addr + length):
        read_length = 0x2000 if (addr + length - offset) > 0x2000 else (addr + length - offset)
        ret_buffer += c_api.r_pa(offset, read_length)
        offset += read_length
    return ret_buffer


def r_va(pgd, addr, length):
    """Read virtual address

        :param pgd: The PGD (address space) to read from.
        :type pgd: int

        :param addr: The address to read
        :type addr: int

        :param length: The length to read
        :type length: int

        :return: The read content
        :rtype: str
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    offset = addr
    ret_buffer = ""
    while offset < (addr + length):
        read_length = 0x2000 if (addr + length - offset) > 0x2000 else (addr + length - offset)
        ret_buffer += c_api.r_va(pgd, offset, read_length)
        offset += read_length
    return ret_buffer


def r_cpu(cpu_index=0):
    """Read CPU register values
        :param cpu_index: The CPU index to read. 0 by default.
        :type cpu_index: int

        :return: The CPU
        :rtype: X64CPU | X86CPU | ...
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    if cpu_index >= get_num_cpus():
        raise ValueError("Incorrect cpu index specified")

    return c_api.r_cpu(cpu_index)


def w_pa(addr, buff, length=None):
    """Write physical address

        :param addr: The address to write
        :type addr: int

        :param buff: The buffer to write
        :type buffer: str

        :return: None
        :rtype: None
    """
    import c_api
    # The length parameter is not used at this moment,
    # but is kept to avoid breaking old scripts.
    if length is not None and len(buff) != length:
        raise ValueError(
            "Length of the buffer does not match the declared length")
    else:
        # If this function call fails, it will raise an exception.
        # Given that the exception is self explanatory, we just let it
        # propagate upwards
        offset = addr
        length = len(buff)
        while offset < (addr + length):
            write_length = 0x2000 if (addr + length - offset) > 0x2000 else (addr + length - offset)
            c_api.w_pa(offset, buff[(offset - addr):(offset - addr + write_length)])
            offset += write_length
        return None


def w_va(pgd, addr, buff, length=None):
    """Write virtual address

        :param pgd: The PGD (address space) to write to.
        :type pgd: int

        :param addr: The address to write
        :type addr: int

        :param buff: The buffer to write
        :type buffer: str

        :return: None
        :rtype: None
    """
    import c_api
    # The length parameter is not used at this moment,
    # but is kept to avoid breaking old scripts.
    if length is not None and len(buff) != length:
        raise ValueError(
            "Length of the buffer does not match the declared length")
    else:
        # If this function call fails, it will raise an exception.
        # Given that the exception is self explanatory, we just let it
        # propagate upwards
        offset = addr
        length = len(buff)
        while offset < (addr + length):
            write_length = 0x2000 if (addr + length - offset) > 0x2000 else (addr + length - offset)
            c_api.w_va(pgd, offset, buff[(offset - addr):(offset - addr + write_length)])
            offset += write_length
        return None


def r_ioport(address, size):
    """Read I/O port

        :param address: The port address to read, from 0 to 65536
        :type address: int

        :param size: The size to read (1, 2, or 4)
        :type size: int

        :return: The value read
        :rtype: int
    """
    import c_api
    if size not in [1, 2, 4]:
        raise ValueError("Incorrect size to read: it must be 1, 2 or 4")
    if address < 0 or address > 65536:
        raise ValueError("Incorrect port address: it must be between 0-65536")
    return c_api.r_ioport(address, size)


def w_ioport(address, size, value):
    """Write I/O port

        :param address: The port address to write, from 0 to 65536
        :type address: int

        :param size: The size to read (1, 2, or 4)
        :type size: int

        :return: The value written
        :rtype: int
    """
    import c_api
    if size not in [1, 2, 4]:
        raise ValueError("Incorrect size to read: it must be 1, 2 or 4")
    if address < 0 or address > 65536:
        raise ValueError("Incorrect port address: it must be between 0-65536")
    return c_api.w_ioport(address, size, value)


def w_r(cpu_index, regname, val):
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

    if cpu_index >= get_num_cpus():
        raise ValueError("Incorrect cpu index specified")

    if conf_m.platform == "i386-softmmu":
        if regname in X86CPU.reg_nums:
            # If this function call fails, it will raise an exception.
            # Given that the exception is self explanatory, we just let it
            # propagate upwards
            return c_api.w_r(cpu_index, X86CPU.reg_nums[regname], val)
        else:
            raise ValueError("[w_r] Wrong register specification")
    elif conf_m.platform == "x86_64-softmmu":
        if regname in X64CPU.reg_nums:
            # If this function call fails, it will raise an exception.
            # Given that the exception is self explanatory, we just let it
            # propagate upwards
            return c_api.w_r(cpu_index, X64CPU.reg_nums[regname], val)
        else:
            raise ValueError("[w_r] Wrong register specification")
    else:
        raise ValueError("[w_r] Wrong platform specification")


def w_sr(cpu_index, regname, selector, base, limit, flags):
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

    if cpu_index >= get_num_cpus():
        raise ValueError("Incorrect cpu index specified")

    if conf_m.platform == "i386-softmmu":
        if regname in X86CPU.reg_nums:
            # If this function call fails, it will raise an exception.
            # Given that the exception is self explanatory, we just let it
            # propagate upwards
            return c_api.w_sr(
                cpu_index,
                X86CPU.reg_nums[regname],
                selector,
                base,
                limit,
                flags)
        else:
            raise ValueError("[w_r] Wrong register specification")
    elif conf_m.platform == "x86_64-softmmu":
        if regname in X64CPU.reg_nums:
            # If this function call fails, it will raise an exception.
            # Given that the exception is self explanatory, we just let it
            # propagate upwards
            return c_api.w_sr(
                cpu_index,
                X64CPU.reg_nums[regname],
                selector,
                base,
                limit,
                flags)
        else:
            raise ValueError("[w_r] Wrong register specification")
    else:
        raise ValueError("[w_r] Wrong platform specification")


def va_to_pa(pgd, addr):
    """ Virtual to physical address.

        :param pgd: PGD, or address space of the address to translate
        :type addr: int

        :param addr: Virtual address to translate
        :type addr: int

        :return: The translated physical address
        :rtype: int
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.va_to_pa(pgd, addr)


def start_monitoring_process(pgd):
    """ Start monitoring a process. Process-wide callbacks will be called for every process that is being monitored

        :param pgd: PGD, or address space of the process to check
        :type pgd: int

        :return: None
        :rtype: None
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.start_monitoring_process(pgd)


def is_monitored_process(pgd):
    """Returns true of a given process is being monitored. Process-wide callbacks will be called for every
       process that is being monitored

        :param pgd: PGD, or address space of the process to monitor
        :type pgd: int

        :return: True of the process is being monitored, False otherwise
        :rtype: bool
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.is_monitored_process(pgd)


def stop_monitoring_process(pgd, force=False):
    """ Start monitoring a process. Process-wide callbacks will be called for every process that is being monitored

        :param pgd: PGD, or address space of the process to stop monitoring
        :type pgd: int

        :return: None
        :rtype: None
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.stop_monitoring_process(pgd, 1 if force else 0)


def get_running_process(cpu_index=0):
    """Returns the PGD or address space of the process that is being executed at this moment

        :param cpu_index: CPU index that we want to query. Each CPU might be executing a different address space
        :type cpu_index: int

        :return: The PGD or address space for the process that is executing on the indicated CPU
        :rtype: int
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    if cpu_index >= get_num_cpus():
        raise ValueError("Incorrect cpu index specified")
    return c_api.get_running_process(cpu_index)


def is_kernel_running(cpu_index=0):
    """ Returns True if the corresponding CPU is executing in Ring 0

        :param cpu_index: CPU index that we want to query. Each CPU might be executing a different address space
        :type cpu_index: int

        :return: True if the corresponding CPU is executing in Ring 0, False otherwise
        :rtype: bool
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    if cpu_index >= get_num_cpus():
        raise ValueError("Incorrect cpu index specified")

    return c_api.is_kernel_running(cpu_index)


def save_vm(name):
    """Save the state of the virtual machine so that it can be restored later

        :param name: Name of the snapshot to save
        :type name: str

        :return: None
        :rtype: None
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.save_vm(name)


def load_vm(name):
    """Load a previously saved snapshot of the virtual machine.

        :param name: Name of the snapshot to load
        :type name: str

        :return: None
        :rtype: None
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.load_vm(name)


def get_process_list():
    """ Return list of processes.

        :return: List of processes. List of dictionaries with keys: "pid", "pgd", "name", "kaddr", where kaddr
                 stands for the kernel address representing the process (e.g.: EPROCESS)
        :rtype: list
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.get_process_list()


def get_os_bits():
    """ Return the bitness of the system / O.S. being emulated

        :return: The bitness of the system / O.S. being emualated
        :rtype: int
    """
    import c_api
    # If this function call fails, it will raise an exception.
    # Given that the exception is self explanatory, we just let it propagate
    # upwards
    return c_api.get_os_bits()

# Rest of API functions


def get_module_list(pgd):
    """ Return list of modules for a given PGD

        :param pgd: The PGD of the process for which we want to extract the modules, or 0 to extract kernel modules
        :type pgd: int

        :return: List of modules, each element is a dictionary with keys: "name", "base", "size", and "symbols_resolved"
        :rtype: list
    """
    import vmi
    proc_list = get_process_list()
    mods = []
    found = False
    if pgd == 0:
        proc_pid = 0
        proc_pgd = 0
        found = True
    else:
        for proc in proc_list:
            proc_pid = proc["pid"]
            proc_pgd = proc["pgd"]
            if proc_pgd == pgd:
                found = True
                break

    if found:
        vmi.update_modules(proc_pgd, update_symbols=False)
        if (proc_pid, proc_pgd) in vmi.modules:
            for mod in vmi.modules[(proc_pid, proc_pgd)].values():
                mods.append({"name": mod.get_name(),
                             "base": mod.get_base(),
                             "size": mod.get_size(),
                             "symbols_resolved" : mod.are_symbols_resolved()})
        return mods
    else:
        raise ValueError("Process with PGD %x not found" % pgd)


def get_symbol_list(pgd = None):
    """ Return list of symbols

        :param pgd: The pgd to obtain the symbols from. 0 to get kernel symbols
        :type pgd: int

        :return: List of symbols, each element is a dictionary with keys: "mod", "name", and "addr"
        :rtype: list
    """
    import vmi
    from utils import pp_print
    res_syms = []
    diff_modules = {}
    if pgd is None: 
        proc_list = get_process_list()
        pp_print("[*] Updating symbol list... Be patient, this may take a while\n")
        for proc in proc_list:
            proc_pid = proc["pid"]
            proc_pgd = proc["pgd"]
            if proc_pgd != 0:
                vmi.update_modules(proc_pgd, update_symbols=True)
                if (proc_pid, proc_pgd) in vmi.modules:
                    for module in vmi.modules[proc_pid, proc_pgd].values():
                        c = module.get_checksum()
                        n = module.get_fullname()
                        if (c, n) not in diff_modules:
                            diff_modules[(c, n)] = [module]
                        else:
                            diff_modules[(c, n)].append(module)
        # Include kernel modules too
        vmi.update_modules(0, update_symbols=True)
        if (0, 0) in vmi.modules:
            for module in vmi.modules[0, 0].values():
                c = module.get_checksum()
                n = module.get_fullname()
                if (c, n) not in diff_modules:
                    diff_modules[(c, n)] = [module]
                else:
                    diff_modules[(c, n)].append(module)

    else:
        pp_print("[*] Updating symbol list for one process... Be patient, this may take a while\n")
        vmi.update_modules(pgd, update_symbols=True)
        for proc_pid, proc_pgd in vmi.modules:
            if proc_pgd == pgd:
                for module in vmi.modules[proc_pid, proc_pgd].values():
                    c = module.get_checksum()
                    n = module.get_fullname()
                    if (c, n) not in diff_modules:
                        diff_modules[(c, n)] = [module]
                    else:
                        diff_modules[(c, n)].append(module)

    for mod_list in diff_modules.values():
        added_names = []
        for mod in mod_list:
            syms = mod.get_symbols()
            for name in syms:
                if name not in added_names:
                    res_syms.append({"mod": mod.get_name(), "name": name, "addr": syms[name]})
                    added_names.append(name)
    return res_syms


def sym_to_va(pgd, mod_name, func_name):
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
    # First, check if the process exists
    process_found = False
    for proc in get_process_list():
        if pgd == proc["pgd"]:
            process_found = True
            break
    if not process_found:
        raise ValueError("Process with PGD %x not found" % pgd)
    mod_name = mod_name.lower()
    func_name = func_name.lower()
    for proc_pid, proc_pgd in vmi.modules:
        if proc_pgd == pgd:
            for module in vmi.modules[proc_pid, proc_pgd].values():
                if mod_name in module.get_name().lower():
                    syms = module.get_symbols()
                    for name in syms:
                        symbol_offset = syms[name]
                        if func_name == name.lower():
                            return (module.get_base() + symbol_offset)
    # Finally, return None if the symbol is not found
    return None


def va_to_sym(pgd, addr):
    """ Find symbols for a particular virtual address

        :param pgd: The PGD or address space for the process for which we want to search the symbol
        :type pgd: int

        :param addr: The virtual address to search
        :type addr: int

        :return: A tuple containing the module name and the function name, None if nothing found
        :rtype: tuple
    """
    import vmi
    # First, check if the process exists
    process_found = False
    for proc in get_process_list():
        if pgd == proc["pgd"]:
            process_found = True
            break
    if not process_found:
        raise ValueError("Process with PGD %x not found" % pgd)

    for proc_pid, proc_pgd in vmi.modules:
        if proc_pgd == pgd:
            for module in vmi.modules[proc_pid, proc_pgd].values():
                offset = (addr - module.get_base())
                if offset > 0 and offset < module.get_size():
                    syms = module.get_symbols()
                    for name in syms:
                        symbol_offset = syms[name]
                        if offset == symbol_offset:
                            return (module.get_name(), name)
    # Finally, return None if the symbol is not found
    return None


def import_module(module_name):
    """ Import a module given its name (e.g. scripts.script_example)

        :param module_name: The module name following python notation. 
                            E.g.: scripts.script_example
        :type module_name: str 

        :return: None 
        :rtype: None 
    """
    import c_api
    c_api.import_module(module_name)


def unload_module(module_handle):
    """ Unload a module given its handle. 

        :param module_handle: The module handle. 
        :type module_name: int 

        :return: None 
        :rtype: None 
    """
    import c_api
    c_api.unload_module(module_handle)


def reload_module(module_handle):
    """ Reload a module given its handle. 

        :param module_handle: The module handle.
        :type module_handle: int

        :return: None 
        :rtype: None 
    """
    import c_api
    c_api.reload_module(module_handle)

def get_loaded_modules():
    """ Returns a dictionary of modules loaded in pyrebox.

        :return: Dictionary with the keys: "module_handle", "module_name", "is_loaded"
        :rtype: dict 
    """
    import c_api
    return c_api.get_loaded_modules()


# ================================================== CLASSES  =============

class CallbackManager:
    '''
        Class that abstracts callback management,optionally associating names to callbacks, and registering the list of
        added callbacks so that we can remove them all with a single call to "clean()" after we are done.
    '''
    INV0_CB = 0  # Shadow optimized callbacks for block and insn begin
    INV1_CB = 1  # Shadow optimized callbacks for block and insn begin
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
    LOADMODULE_CB = 16
    REMOVEMODULE_CB = 17

    def __init__(self, module_hdl):
        """ Constructor of the class

            :param module_hdl: The module handle provided to the script as parameter to the initialize_callbacks
                               function. Use 0 if it doesn't apply.
            :type module_hdl: int
        """
        self.callbacks = {}
        self.load_module_callbacks = {}
        self.remove_module_callbacks = {}

        self.module_hdl = module_hdl

    def get_module_handle(self):
        """ Returns the module handle associated to this callback manager
            
            :return: The handle of the module this callback manager is bound to.
            :rtype: int
        """
        return self.module_hdl

    def generate_callback_name(self, name):
        """ Generates a unique callback name given an initial name

            :param name: The initial name
            :type name: str

            :return: The new generated name
            :rtype: str
        """
        subname = name
        counter = 0
        while subname in self.callbacks or \
              subname in self.load_module_callbacks or \
              subname in self.remove_module_callbacks:
            subname = "%s_%d" % (name, counter)
            counter += 1
        return subname

    def add_callback(
            self,
            callback_type,
            func,
            name=None,
            addr=None,
            pgd=None,
            start_opcode=None,
            end_opcode=None):
        """ Add a callback to the module, given a name, so that we can refer to it later.

            If the name is repeated, it will provide back a new name based on the one passed as argument,
            that can be used later for removing it or attaching triggers to it.

            :param name: The name of the callback
            :type name: str

            :param callback_type: The callback type to insert. One of INSN_BEGIN_CB, BLOCK_BEGIN_CB, etc... See help(api)
                                  from a pyrebox shell to get a complete listing of constants ending in _CB
            :type callback_type: int

            :param func: The callback function (python function)
            :type func: function

            :param addr: Optional. The address where we want to place the callback. Only applies
                         to INSN_BEGIN_CB, BLOCK_BEGIN_CB
            :type addr: int

            :param pgd: Optional. The PGD (addr space) where we want to place the callback. Only applies
                        to INSN_BEGIN_CB, BLOCK_BEGIN_CB
            :type pgd: int

            :return: The actual inserted callback name. If the callback name indicated already existed,
                     this name will be updated to make it unique. This name can be used as a handle to the callback
            :rtype: str
        """
        import random
        import string
        import time

        # If a name was not provided, just provide a 16 lowercase letter random
        # name
        if name is None:
            random.seed(time.time())
            name = "".join(random.choice(string.lowercase) for i in range(16))
        name = self.generate_callback_name(name)

        # If the callback_type is a module callback, register it with specific API
        if callback_type == CallbackManager.LOADMODULE_CB:
            self.load_module_callbacks[name] = register_module_load_callback(pgd, name, func)
            return name
        if callback_type == CallbackManager.REMOVEMODULE_CB:
            self.remove_module_callbacks[name] = register_module_remove_callback(pgd, name, func)
            return name

        # addr,pgd and start_opcode,end_opcode are exclusive, so we join them
        # together to call register_callback
        first_param = start_opcode if addr is None else addr
        second_param = end_opcode if pgd is None else pgd
        self.callbacks[name] = register_callback(
            self.module_hdl, callback_type, wrap(func), first_param, second_param)
        return name

    def rm_callback(self, name):
        """ Remove a callback given its name. Associated triggers will get unloaded too.

            :param name: The name of the callback to remove
            :type name: str

            :return: None
            :rtype: None
        """
        if name in self.callbacks:
            unregister_callback(self.callbacks[name])
            del(self.callbacks[name])
            return

        if name in self.load_module_callbacks:
            unregister_module_load_callback(self.load_module_callbacks[name])
            del(self.load_module_callbacks[name])
            return

        if name in self.remove_module_callbacks:
            unregister_module_remove_callback(self.remove_module_callbacks[name])
            del(self.remove_module_callbacks[name])
            return

        raise ValueError(
                "[!] CallbackManager: A callback with name %s does not exist and cannot be removed\n" %
                (name))

    def callback_exists(self, name):
        """ Determine if a callback exists or not, given its name

            :param name: The callback name to check
            :type name: str

            :return: True if the callback already exists
            :rtype: bool
        """
        return (name in self.callbacks) or (name in self.module_load_callbacks) or (name in self.module_remove_callbacks)

    def add_trigger(self, name, trigger_path):
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
            raise ValueError(
                "[!] CallbackManager: A callback with name %s does not exist, or it is a module callback (non-trigger compatible)\n" %
                (name))
            return
        # Remove ".so" from the path, if present
        if trigger_path[-3:] == ".so":
            trigger_path = trigger_path[:-3]
        # Check if we have the plugin compiled for the correct architecture
        trigger_path = "%s-%s.so" % (trigger_path, conf_m.platform)
        p = subprocess.Popen(
            "make %s" %
            trigger_path,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        p.wait()
        if os.path.isfile(trigger_path):
            # Trigger compiled correctly
            add_trigger(self.callbacks[name], trigger_path)
        else:
            raise ValueError("Could not correctly compile trigger\n")

    def rm_trigger(self, name):
        ''' Remove the trigger from the callback specified as parameter

            :param name: The callback name from which we want to remove the trigger
            :type name: str

            :return: None
            :rtype: None
        '''
        if name not in self.callbacks:
            raise ValueError(
                "[!] CallbackManager: A callback with name %s does not exist, or it is a module callback (non-trigger compatible)\n" %
                (name))
            return
        remove_trigger(self.callbacks[name])

    def set_trigger_var(self, name, var_name, val):
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
            raise ValueError(
                "[!] CallbackManager: A callback with name %s does not exist, or it is a module callback (non-trigger compatible)\n" %
                (name))
            return
        if isinstance(val, str):
            set_trigger_str(self.callbacks[name], var_name, val)
        elif (isinstance(val, int) or isinstance(val, long)) and val < 0:
            raise ValueError(
                "Negative integers not supported, use only unsigned integers")
        elif (isinstance(val, int) or isinstance(val, long)) and conf_m.platform == "i386-softmmu":
            set_trigger_uint32(self.callbacks[name], var_name, val)
        elif (isinstance(val, int) or isinstance(val, long)) and conf_m.platform == "x86_64-softmmu":
            set_trigger_uint64(self.callbacks[name], var_name, long(val))
        else:
            raise ValueError(
                "[!] Unsupported trigger var type: %s\n" % str(
                    type(val)))

    def get_trigger_var(self, name, var_name):
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
            raise ValueError(
                "[!] CallbackManager: A callback with name %s does not exist, or it is a module callback (non-trigger compatible)\n" %
                (name))
            return
        return get_trigger_var(self.callbacks[name], var_name)

    def clean(self):
        """ Clean all the inserted callbacks.

            Clean all the inserted callbacks. Will remove all the callbacks registered within this manager.

            :return: None
            :rtype: None
        """
        names = self.callbacks.keys()
        for name in names:
            self.rm_callback(name)
        names = self.load_module_callbacks.keys()
        for name in names:
            self.rm_callback(name)
        names = self.remove_module_callbacks.keys()
        for name in names:
            self.rm_callback(name)


# ================================================== CLASSES ==============


class BP:
    '''
    Class used to create execution, memory read, and memory write breakpoints
    '''
    EXECUTION = 0
    MEM_READ = 1
    MEM_WRITE = 2
    MEM_READ_PHYS = 3
    MEM_WRITE_PHYS = 4
    __active_bps = {}
    __cm = CallbackManager(0)
    __bp_num = 0

    def __init__(self, addr, pgd, size=0, typ=0, func=None):
        """ Constructor for a BreakPoint

            :param addr: The (start) address where we want to put the breakpoint
            :type addr: int

            :param pgd: The PGD or address space where we want to put the breakpoint. Irrelevant for physical address
                        breakpoints.
            :type pgd: int

            :param size: Optional. The size of the area we want to put a breakpoint on.
                         We can put the BP on a single address or a memory range.
            :type size: int

            :param typ: The type of breakpoint: BP.EXECUTION, BP.MEM_READ, BP.MEM_WRITE, BP.MEM_READ_PHYS, BP.MEM_WRITE_PHYS
            :type typ: int

            :param func: Optional. The function that will be called as callback for the breakpoint. The
                         parameters for the function should be the ones corresponding to the
                         INSN_BEGIN_CB callback for execution breakpoints, and MEM_READ_CB or
                         MEM_WRITE_CB for memory read/write breakpoints. If no function is specified,
                         a shell is started when the breakpoint is hit.
            :type func: function

            :return: An instance of class BP for the inserted breakpoint
            :rtype: BP
        """

        self.typ = typ
        if typ == self.EXECUTION:
            typ_str = "x"
        elif typ == self.MEM_READ:
            typ_str = "r"
        elif typ == self.MEM_WRITE:
            typ_str = "w"
        elif typ == self.MEM_READ_PHYS:
            typ_str = "rp"
        elif typ == self.MEM_WRITE_PHYS:
            typ_str = "wp"
        self.__bp_repr = "BP%s_%d" % (typ_str, BP.__bp_num)
        BP.__bp_num += 1
        self.addr = addr
        self.pgd = pgd
        self.en = False
        if (typ > self.EXECUTION) and size == 0:
            self.size = 1
        else:
            self.size = size
        if func is not None:
            self.func = func
        else:
            self.func = functools.partial(bp_func, self.__bp_repr)

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
                    self.__bp_repr = BP.__cm.add_callback(
                        CallbackManager.INSN_BEGIN_CB,
                        self.func,
                        name=self.__bp_repr,
                        addr=self.addr,
                        pgd=self.pgd)
                else:
                    if not is_monitored_process(self.pgd):
                        start_monitoring_process(self.pgd)
                    if self.pgd not in BP.__active_bps:
                        BP.__active_bps[self.pgd] = 1
                    else:
                        BP.__active_bps[self.pgd] += 1
                    self.__bp_repr = BP.__cm.add_callback(
                        CallbackManager.INSN_BEGIN_CB, self.func, name=self.__bp_repr)
                    BP.__cm.add_trigger(
                        self.__bp_repr, "triggers/trigger_bp_memrange.so")
                    BP.__cm.set_trigger_var(self.__bp_repr, "begin", self.addr)
                    BP.__cm.set_trigger_var(
                        self.__bp_repr, "end", self.addr + self.size)
                    BP.__cm.set_trigger_var(self.__bp_repr, "pgd", self.pgd)
            elif self.typ == self.MEM_READ:
                if not is_monitored_process(self.pgd):
                    start_monitoring_process(self.pgd)
                if self.pgd not in BP.__active_bps:
                    BP.__active_bps[self.pgd] = 1
                else:
                    BP.__active_bps[self.pgd] += 1
                self.__bp_repr = BP.__cm.add_callback(
                    CallbackManager.MEM_READ_CB, self.func, name=self.__bp_repr)
                BP.__cm.add_trigger(
                    self.__bp_repr, "triggers/trigger_bpr_memrange.so")
                BP.__cm.set_trigger_var(self.__bp_repr, "begin", self.addr)
                BP.__cm.set_trigger_var(
                    self.__bp_repr, "end", self.addr + self.size)
                BP.__cm.set_trigger_var(self.__bp_repr, "pgd", self.pgd)
            elif self.typ == self.MEM_WRITE:
                if not is_monitored_process(self.pgd):
                    start_monitoring_process(self.pgd)
                if self.pgd not in BP.__active_bps:
                    BP.__active_bps[self.pgd] = 1
                else:
                    BP.__active_bps[self.pgd] += 1
                self.__bp_repr = BP.__cm.add_callback(
                    CallbackManager.MEM_WRITE_CB, self.func, name=self.__bp_repr)
                BP.__cm.add_trigger(
                    self.__bp_repr, "triggers/trigger_bpw_memrange.so")
                BP.__cm.set_trigger_var(self.__bp_repr, "begin", self.addr)
                BP.__cm.set_trigger_var(
                    self.__bp_repr, "end", self.addr + self.size)
                BP.__cm.set_trigger_var(self.__bp_repr, "pgd", self.pgd)
            elif self.typ == self.MEM_READ_PHYS:
                self.__bp_repr = BP.__cm.add_callback(
                    CallbackManager.MEM_READ_CB, self.func, name=self.__bp_repr)
                BP.__cm.add_trigger(
                    self.__bp_repr, "triggers/trigger_bprh_memrange.so")
                BP.__cm.set_trigger_var(self.__bp_repr, "begin", self.addr)
                BP.__cm.set_trigger_var(
                    self.__bp_repr, "end", self.addr + self.size)
            elif self.typ == self.MEM_WRITE_PHYS:
                self.__bp_repr = BP.__cm.add_callback(
                    CallbackManager.MEM_WRITE_CB, self.func, name=self.__bp_repr)
                BP.__cm.add_trigger(
                    self.__bp_repr, "triggers/trigger_bpwh_memrange.so")
                BP.__cm.set_trigger_var(self.__bp_repr, "begin", self.addr)
                BP.__cm.set_trigger_var(
                    self.__bp_repr, "end", self.addr + self.size)

    def disable(self):
        """ Disable a breakpoint

            :return: None
            :rtype: None
        """

        if self.en:
            self.en = False
            # Trigger is deleted automagically
            BP.__cm.rm_callback(self.__bp_repr)
            if self.typ < BP.MEM_READ_PHYS and self.pgd in BP.__active_bps:
                BP.__active_bps[self.pgd] -= 1
                if BP.__active_bps[self.pgd] == 0:
                    stop_monitoring_process(self.pgd)
