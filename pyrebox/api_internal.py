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


def print_internal(plugin_name, f, *args):
    import c_api
    string_to_print = (f % args)
    num_breaks = string_to_print.count("\n")
    # Adjust output depending on the "\n" usage in the string to print
    if num_breaks == 0:
        c_api.plugin_print_internal("[%s] %s\n" % (plugin_name, (f % args)))
    elif num_breaks == 1 and string_to_print[-1] != "\n":
        c_api.plugin_print_internal("\n[%s]\n" % (plugin_name))
        c_api.plugin_print_internal("-" * (2 + len(plugin_name)) + "\n")
        c_api.plugin_print_internal("%s\n" % (f % args))
    elif num_breaks == 1 and string_to_print[-1] == "\n":
        c_api.plugin_print_internal("[%s] %s" % (plugin_name, (f % args)))
    else:
        c_api.plugin_print_internal("\n[%s]\n" % (plugin_name))
        c_api.plugin_print_internal("-" * (2 + len(plugin_name)) + "\n")
        if string_to_print[-1] != "\n":
            c_api.plugin_print_internal("%s\n" % (f % args))
        else:
            c_api.plugin_print_internal("%s" % (f % args))
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
