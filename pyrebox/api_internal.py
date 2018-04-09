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

import traceback
from cpus import X86CPU
from cpus import X64CPU

module_load_callbacks = {}
module_remove_callbacks = {}
module_load_remove_pgds = []

module_load_remove_breakpoints = {}

def module_change_callback(pgd, bp_vaddr, bp_haddr, cpu_index, vaddr, size, haddr, data):
    '''
    Callback function triggered whenever there is a change in the list of linked
    modules for a given process.
 
    Updates the module list for that PGD (or kernel).
    ''' 
    import functools
    import struct
    import api
    from api import BP
    from vmi import update_modules
    from utils import pp_error
    from vmi import set_modules_non_present
    from vmi import clean_non_present_modules

    # First, we check if the memory address written points to a module
    # that we have already detected (it is in our list of hooking points).
    # In this way we avoid triggering one update operation for every
    # modified pointer (inserting a module requires to change several
    # pointers, due to the different linked lists).
   
    # Return if it points inside a module that we have already added to our list
    for module_base, hook_addr, hook_size in module_load_remove_breakpoints[pgd]:
        if data >= module_base and data < (hook_addr + hook_size):
            return

    hooking_points = update_modules(pgd)

    if hooking_points is not None:
        # Update hooking points
        # 1) Remove the breakpoints not used anymore
        bps_to_remove = []
        for hp in module_load_remove_breakpoints[pgd]:
            if hp not in hooking_points:
                bps_to_remove.append(hp)

        for hp in bps_to_remove:
            module_load_remove_breakpoints[pgd][hp].disable()
            del module_load_remove_breakpoints[pgd][hp]

        # 2) Add new breakpoints
        for hp in hooking_points:
            if hp not in module_load_remove_breakpoints[pgd]:
                 module_base, addr, size = hp
                 haddr = api.va_to_pa(pgd, addr)
                 bp = BP(haddr,
                         None,
                         size = size,
                         typ = BP.MEM_WRITE_PHYS,
                         func = functools.partial(module_change_callback, pgd, addr, haddr))
                 module_load_remove_breakpoints[pgd][hp] = bp
                 bp.enable()
    else:
        # Just remove all the  modules for the process
        # Mark all modules as non-present
        set_modules_non_present(None, pgd)
        # Remove all the modules that are not marked as present
        clean_non_present_modules(None, pgd)


def add_module_monitoring_hooks(pgd):
    ''' 
    Adds initial set of breakpoints for a given process, so that
    we can detect when a new module is inserted, or a module is
    removed from any of its linked lists.
    '''
    from api import BP
    import api
    from vmi import update_modules
    import functools
    from utils import pp_error

    if pgd not in module_load_remove_breakpoints:
        module_load_remove_breakpoints[pgd] = {}

    # Update the module list for this pgd
    hooking_points = update_modules(pgd)

    if hooking_points is not None:
        # Add the BPW breakpoints
        for module_base, addr, size in hooking_points:
            haddr = api.va_to_pa(pgd, addr)
            bp = BP(haddr, 
                    None, 
                    size = size, 
                    typ = BP.MEM_WRITE_PHYS,
                    func = functools.partial(module_change_callback, pgd, addr, haddr))
            module_load_remove_breakpoints[pgd][(module_base, addr, size)] = bp
            bp.enable()
    else:
        pp_error("Could not set initial list of breakpoints for module monitoring: %x" % pgd)

def remove_module_monitoring_hooks(pgd):
    ''' 
    Remove BPW breakpoints on every link of its module linked list
    '''
    for k in module_load_remove_breakpoints[pgd]:
        module_load_remove_breakpoints[pgd][k].disable()

def register_module_load_callback(pgd, callback_name, callback_function):
    '''
    Register a module load callback. The parameters for the callback
    function should be: func(pid, pgd, base, size, name, fullname)

    :param pgd: The PGD of the process that will be monitored. The callback
                function will be called whenever a new module is loaded
                in the context of that process. A value of 0 will subscribe
                to kernel module updates.
    :type pgd: int

    :param callback_function: The callback function
    :type callback_function: func(pid, pgd, base, size, name, fullname)
    '''
    if pgd not in module_load_callbacks:
        module_load_callbacks[pgd] = {}
        module_remove_callbacks[pgd] = {}

    for pgd in module_load_callbacks:
        if callback_name in module_load_callbacks[pgd]:
            raise ValueError("Cannot register 2 callbacks with the same name! %s" % callback_name)

    module_load_callbacks[pgd][callback_name] = callback_function

    # module_load_remove_pgds checks which PGDs we are monitoring
    # for either module load or module removes...
    if pgd not in module_load_remove_pgds:
        module_load_remove_pgds.append(pgd)
        add_module_monitoring_hooks(pgd)

    return callback_name


def register_module_remove_callback(pgd, callback_name, callback_function):
    '''
    Register a module remove callback. The parameters for the callback
    function should be: func(pid, pgd, base, size, name, fullname)

    :param pgd: The PGD of the process that will be monitored. The callback
                function will be called whenever a module is removed
                in the context of that process. A value of 0 will subscribe
                to kernel module updates.
    :type pgd: int

    :param callback_function: The callback function
    :type callback_function: func(pid, pgd, base, size, name, fullname)
    '''
    if not pgd in module_remove_callbacks:
        module_remove_callbacks[pgd] = {}
        module_load_callbacks[pgd] = {}

    for pgd in module_remove_callbacks:
        if callback_name in module_remove_callbacks[pgd]:
            raise ValueError("Cannot register 2 callbacks with the same name! %s" % callback_name)

    module_remove_callbacks[pgd][callback_name] = callback_function

    # module_load_remove_pgds checks which PGDs we are monitoring
    # for either module load or module removes...
    if pgd not in module_load_remove_pgds:
        module_load_remove_pgds.append(pgd)
        add_module_monitoring_hooks(pgd)

    return callback_name

def unregister_module_load_callback(callback_name):
    '''
    Unregister a module load callback.

    :param callback_name: The name of the callback.
    :type callback_name: str
    '''
    pgd = None
    for pgd_ in module_load_callbacks:
        if callback_name in module_load_callbacks[pgd_]:
            pgd = pgd_
    if pgd is None:
        raise ValueError("The provided callback_name does not exist in the list of callbacks!")
        
    del module_load_callbacks[pgd][callback_name]

    if len(module_load_callbacks[pgd]) == 0 and len(module_remove_callbacks[pgd]) == 0:
        module_load_remove_pgds.remove(pgd)
        remove_module_monitoring_hooks(pgd)


def unregister_module_remove_callback(callback_name):
    '''
    Unregister a module load callback.

    :param callback_name: The name of the callback.
    :type callback_name: str
    '''
    pgd = None
    for pgd_ in module_remove_callbacks:
        if callback_name in module_remove_callbacks[pgd_]:
            pgd = pgd_
    if pgd is None:
        raise ValueError("The provided callback_name does not exist in the list of callbacks!")
        
    del module_remove_callbacks[pgd][callback_name]

    if len(module_remove_callbacks[pgd]) == 0 and len(module_load_callbacks[pgd]) == 0:
        module_load_remove_pgds.remove(pgd)
        remove_module_monitoring_hooks(pgd)


def dispatch_module_load_callback(pid, pgd, base, size, name, fullname):
    '''
    Internal function. Dispatch all module load callbacks.
    '''
    if pgd in module_load_callbacks:
        for cn in module_load_callbacks[pgd]:
            module_load_callbacks[pgd][cn](pid, pgd, base, size, name, fullname)

def dispatch_module_remove_callback(pid, pgd, base, size, name, fullname):
    '''
    Internal function. Dispatch all module remove callbacks.
    '''
    if pgd in module_remove_callbacks:
        for cn in module_remove_callbacks[pgd]:
            module_remove_callbacks[pgd][cn](pid, pgd, base, size, name, fullname)

def convert_x86_cpu(args):
    '''
    Converts a dict of values to a X86CPU type
    '''
    return X86CPU(*args)


def convert_x64_cpu(args):
    '''
    Converts a dict of values to a X64CPU type
    '''
    return X64CPU(*args)


def bp_func(*arg):
    '''
    Function to use as a callback on breakpoints
    '''
    from ipython_shell import start_shell
    import api
    from utils import pp_print
    # bp_num = arg[0]
    # The first argument of insn begin and mem write/read callbacks should
    # always be cpu_index
    cpu_index = arg[1]
    cpu = api.r_cpu(cpu_index)
    pp_print("[!] Breakpoint %s hit at address %x\n" % (arg[0], cpu.PC))
    start_shell()


def vol_get_memory_size():
    '''
    Function to be used internally from volatility to read the memory of the emulated system
    '''
    import c_api
    return c_api.vol_get_memory_size()


def vol_read_memory(addr, length):
    '''
    Function to be used internally from volatility to read the memory of the emulated system
    '''
    import c_api
    return c_api.vol_read_memory(addr, length)


def vol_write_memory(addr, length, buff):
    '''
    Function to be used internally from volatility to read the memory of the emulated system
    '''
    import c_api
    return c_api.vol_write_memory(addr, length, buff)


def print_internal(plugin_name, string_to_print):
    import c_api
    num_breaks = string_to_print.count("\n")
    # Adjust output depending on the "\n" usage in the string to print
    if num_breaks == 0:
        c_api.plugin_print_internal("[%s] %s\n" % (plugin_name, string_to_print))
    elif num_breaks == 1 and string_to_print[-1] != "\n":
        c_api.plugin_print_internal("\n[%s]\n" % (plugin_name))
        c_api.plugin_print_internal("-" * (2 + len(plugin_name)) + "\n")
        c_api.plugin_print_internal("%s\n" % string_to_print)
    elif num_breaks == 1 and string_to_print[-1] == "\n":
        c_api.plugin_print_internal("[%s] %s" % (plugin_name, string_to_print))
    else:
        c_api.plugin_print_internal("\n[%s]\n" % (plugin_name))
        c_api.plugin_print_internal("-" * (2 + len(plugin_name)) + "\n")
        if string_to_print[-1] != "\n":
            c_api.plugin_print_internal("%s\n" % string_to_print)
        else:
            c_api.plugin_print_internal("%s" % string_to_print)
    return None


def function_wrapper(f, *args):
    try:
        f(*args)
    except Exception:
        traceback.print_exc()
    finally:
        return


def wrap(f):
    return lambda *args: function_wrapper(f, *args)


def register_callback(
        module_hdl,
        callback_type,
        py_callback,
        first_param=None,
        second_param=None):
    """Register a callback. For a richer interface, use the CallbackManager class.

        :param module_hdl: The module handle provided to the script as parameter to the initialize_callbacks function.
                           Use 0 if it doesn't apply.
        :type module_hdl: int

        :param callback_type: The callback type. See callback type constants referenced in the API module (ending on CB)
        :type callback_type: int

        :param py_callback: Callback function.
        :type py_callback: function

        :return: Callback handle for the registered callback, that can be used to unregister it.
        :rtype: int
    """
    import c_api
    if first_param is None:
        return c_api.register_callback(module_hdl, callback_type, py_callback)
    elif second_param is None:
        return c_api.register_callback(
            module_hdl, callback_type, py_callback, first_param)
    else:
        return c_api.register_callback(
            module_hdl,
            callback_type,
            py_callback,
            first_param,
            second_param)


def unregister_callback(callback_handle):
    """Unregister a callback. For a richer interface, use the CallbackManager class.

    :param callback_handle: The handle of the callback to unregister
    :type callback_handle: int

    :return: None
    :rtype: None
    """
    import c_api

    return c_api.unregister_callback(callback_handle)


def add_trigger(handle, path):
    """ Add (attach) a trigger to a given callback.

        Triggers are C/C++ plugins with a defined entry point that will get called just before a given callback,
        in such a way that the trigger can decide whether to pass the event to the python callback function or
        to return immediately to the emulation routine.
        In many cases this approach allows to perform certain fast computations and either reduce the number of calls
        to python code or even avoid them. This is strongly benefitial for callbacks that get triggered frequently
        such as memory read/write or instruction execution, given that the python code is heavier than native
        C/C++ code. Triggers can also compute values that can be read from the python callback function, and can
        also read values set by the python callback function.

        :param handle: Handle of the callback to which we want to attach the trigger.
        :type handle: int

        :param path: Full path to the dynamic library containing the trigger.
        :type path: str

        :return: None
        :rtype: None
    """
    import c_api
    return c_api.add_trigger(handle, path)


def remove_trigger(handle):
    """ Remove a trigger from a given callback.

        Triggers are C/C++ plugins with a defined entry point that will get called just before a given callback,
        in such a way that the trigger can decide whether to pass the event to the python callback function or
        to return immediately to the emulation routine.
        In many cases this approach allows to perform certain fast computations and either reduce the number of calls
        to python code or even avoid them. This is strongly benefitial for callbacks that get triggered frequently
        such as memory read/write or instruction execution, given that the python code is heavier than native
        C/C++ code. Triggers can also compute values that can be read from the python callback function, and can
        also read values set by the python callback function.

        :param handle: Handle of the callback from which we want to remove the trigger.
        :type handle: int

        :return: None
        :rtype: None
    """
    import c_api
    return c_api.remove_trigger(handle)


def set_trigger_uint32(handle, name, val):
    """ Create or update an uint32_t variable that can be read from a trigger.

        :param handle: Handle of the callback with the trigger.
        :type handle: int

        :param name: Name of the variable
        :type name: str

        :param val: Value for the variable, must fit in a uint32_t
        :type val: int

        :return: None
        :rtype: None
    """
    import c_api
    return c_api.set_trigger_uint32(handle, name, val)


def set_trigger_uint64(handle, name, val):
    """ Create or update an uint64_t variable that can be read from a trigger.

        :param handle: Handle of the callback with the trigger.
        :type handle: int

        :param name: Name of the variable
        :type name: str

        :param val: Value for the variable, must fit in a uint64_t
        :type val: int

        :return: None
        :rtype: None
    """
    import c_api
    return c_api.set_trigger_uint64(handle, name, val)


def set_trigger_str(handle, name, val):
    """ Create or update a string variable that can be read from a trigger.

        :param handle: Handle of the callback with the trigger.
        :type handle: int

        :param name: Name of the variable
        :type name: str

        :param val: Value for the variable, must be a string
        :type val: str

        :return: None
        :rtype: None
    """
    import c_api
    return c_api.set_trigger_str(handle, name, val)


def get_trigger_var(handle, name):
    """ Retrieve a variable from a trigger.

        :param handle: Handle of the callback with the trigger.
        :type handle: int

        :param name: Name of the variable
        :type name: str

        :return: None
        :rtype: None
    """
    import c_api
    return c_api.get_trigger_var(handle, name)
