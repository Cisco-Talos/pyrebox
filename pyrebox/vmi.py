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

import os
import json

from utils import pp_print
from utils import pp_debug
from utils import pp_warning
from utils import pp_error
from api import BP 

# symbol cache
__symbols = {}

symbol_cache_path = None

__modules = {}  # List of modules for each process, index is pgd

OS_FAMILY_WIN = 0
OS_FAMILY_LINUX = 1

os_family = None

gdb_breakpoint_list = {}

def get_modules():
    global __modules
    return __modules

def has_module(pid, pgd, base):
    global __modules
    return (((pid, pgd) in __modules) and (base in __modules[(pid, pgd)]))

def get_module(pid, pgd, base):
    global __modules
    if (((pid, pgd) in __modules) and (base in __modules[(pid, pgd)])):
        return __modules[(pid, pgd)][base]
    else:
        return None

def add_module(pid, pgd, base, mod):
    global __modules
    if not (pid, pgd) in __modules:
        __modules[(pid, pgd)] = {}
    __modules[(pid, pgd)][base] = mod

def add_symbols(mod_full_name, syms):
    global __symbols
    __symbols[mod_full_name] = syms

def get_symbols(mod_full_name):
    global __symbols
    if mod_full_name in __symbols:
        return __symbols[mod_full_name]
    else:
        return {}

def has_symbols(mod_full_name):
    global __symbols
    return ((mod_full_name in __symbols))

def set_symbol_cache_path(path):
    global symbol_cache_path
    symbol_cache_path = path

# Function to load symbols from a file cache
def load_symbols_from_cache_file():
    global __symbols
    global symbol_cache_path
    if symbol_cache_path is not None and os.path.isfile(symbol_cache_path):
        try:
            f = open(symbol_cache_path, "r")
            __symbols = json.loads(f.read())
            f.close()
        except Exception as e:
            pp_error("Error while reading symbols from %s: %s\n" % (symbol_cache_path, str(e)))


# Function to save symbols to a file cache
def save_symbols_to_cache_file():
    global __symbols
    global symbol_cache_path
    if symbol_cache_path is not None:
        f = open(symbol_cache_path, "w")
        f.write(json.dumps(__symbols))
        f.close()

class Module:
    def __init__(self, base, size, pid, pgd, checksum, name, fullname):
        self.__base = base
        self.__size = size
        self.__pid = pid
        self.__pgd = pgd
        self.__checksum = checksum
        self.__name = name
        self.__fullname = fullname
        self.__symbols = None 

        self.__is_present = False
    # Getters

    def get_base(self):
        return self.__base

    def get_size(self):
        return self.__size

    def get_pid(self):
        return self.__pid

    def get_pgd(self):
        return self.__pgd

    def get_name(self):
        return self.__name

    def get_fullname(self):
        return self.__fullname

    def get_symbols(self):
        if self.__symbols is None:
            return []
        else:
            return self.__symbols

    def are_symbols_resolved(self):
        return (self.__symbols is not None)

    def get_checksum(self):
        return self.__checksum

    def is_present(self):
        return self.__is_present    

    # Setters

    def set_base(self, base):
        self.__base = base

    def set_size(self, size):
        self.__size = size

    def set_pid(self, pid):
        self.__pid = pid

    def set_pgd(self, pgd):
        self.__pgd = pgd

    def set_name(self, name):
        self.__name = name

    def set_fullname(self, fullname):
        self.__fullname = fullname

    def set_checksum(self, checksum):
        self.__checksum = checksum

    def set_symbols(self, syms):
        self.__symbols = syms

    def set_present(self, present = True):
        self.__is_present = present

def set_os_family_win():
    global os_family
    os_family = OS_FAMILY_WIN


def set_os_family_linux():
    global os_family
    os_family = OS_FAMILY_LINUX


def update_modules(proc_pgd, update_symbols=False):
    global os_family
    from windows_vmi import windows_update_modules
    from linux_vmi import linux_update_modules
    hook_points = None
    if os_family == OS_FAMILY_WIN:
        hook_points = windows_update_modules(proc_pgd, update_symbols)
    elif os_family == OS_FAMILY_LINUX:
        hook_points = linux_update_modules(proc_pgd, update_symbols)
    return hook_points


def set_modules_non_present(pid, pgd):
    global __modules
    if pid is not None:
        if (pid, pgd) in __modules:
            for base, mod in __modules[(pid, pgd)].iteritems():
                mod.set_present(False)
    else:
        for pid, _pgd in __modules.keys():
            if _pgd == pgd:
                if (pid, pgd) in __modules:
                    for base, mod in __modules[(pid, _pgd)].iteritems():
                        mod.set_present(False)

def clean_non_present_modules(pid, pgd):
    from api_internal import dispatch_module_remove_callback
    global __modules

    mods_to_remove = []
    if pid is not None:
        if (pid, pgd) in __modules:
            for base, mod in __modules[(pid, pgd)].iteritems():
                if not mod.is_present():
                    mods_to_remove.append((pid, pgd, base))
    else:
        for pid, _pgd in __modules.keys():
            if _pgd == pgd:
                if (pid, _pgd) in __modules:
                    for base, mod in __modules[(pid, _pgd)].iteritems():
                        if not mod.is_present():
                            mods_to_remove.append((pid, pgd, base))

    for pid, pgd, base in mods_to_remove:
        # Callback notification
        dispatch_module_remove_callback(pid, pgd, base, 
                                        __modules[(pid, pgd)][base].get_size(),
                                        __modules[(pid, pgd)][base].get_name(),
                                        __modules[(pid, pgd)][base].get_fullname())

        del __modules[(pid, pgd)][base]


def read_paged_out_memory(pgd, addr, size):
    global os_family
    from windows_vmi import windows_read_paged_out_memory
    from linux_vmi import linux_read_paged_out_memory
    if os_family == OS_FAMILY_WIN:
        return windows_read_paged_out_memory(pgd, addr, size)
    elif os_family == OS_FAMILY_LINUX:
        return linux_read_paged_out_memory(pgd, addr, size)


def get_system_time():
    global os_family
    from windows_vmi import get_system_time as win_get_system_time
    if os_family == OS_FAMILY_WIN:
        return win_get_system_time()
    elif os_family == OS_FAMILY_LINUX:
        raise NotImplementedError("get_system_time not implemented on Linux guests")

def get_threads():
    global os_family
    from windows_vmi import get_threads as win_get_threads
    if os_family == OS_FAMILY_WIN:
        return list(win_get_threads())
    elif os_family == OS_FAMILY_LINUX:
        raise NotImplementedError("get_threads not implemented yet on Linux guests")

def get_thread_id(thread_number, thread_list):
    if thread_number < len(thread_list):
        return long(thread_list[thread_number]['id'])
    else:
        return long(0)

def get_thread_description(thread_id, thread_list):
    for element in thread_list:
        if element['id'] == thread_id:
            return "%s(%x) - %x" % (element['process_name'], element['pid'], element['tid'])
    return ""

def get_running_thread_first_cpu(thread_list):
    for element in thread_list:
        if element['running'] is not None and element['running'] == 0:
            return long(element['id'])

    # As a fallback, just return the first thread in the list
    return long(thread_list[0]['id'])

def does_thread_exist(thread_id, thread_list):
    for element in thread_list:
        if element['id'] == thread_id:
            return True
    return False

def str_to_val(buf, str_size):
    import struct
    from utils import ConfigurationManager as conf_m

    if str_size == 1:
        struct_letter = "B"
    elif str_size == 2:
        struct_letter = "H"
    elif str_size == 4:
        struct_letter = "I"
    elif str_size == 8:
        struct_letter = "Q"
    else:
        raise NotImplementedError("[val_to_str - gdb_write_thread_register] Not implemented")

    if conf_m.endianess == "l":
        struct_letter = "<" + struct_letter
    else:
        struct_letter = ">" + struct_letter

    try:
        ret_val = struct.unpack(struct_letter, buf)[0]
    except Exception as e:
        raise e
    return ret_val 

def val_to_str(val, str_size):
    import struct
    from utils import ConfigurationManager as conf_m

    if str_size == 1:
        struct_letter = "B"
    elif str_size == 2:
        struct_letter = "H"
    elif str_size == 4:
        struct_letter = "I"
    elif str_size == 8:
        struct_letter = "Q"
    else:
        raise NotImplementedError("[val_to_str - gdb_read_thread_register] Not implemented")

    if conf_m.endianess == "l":
        struct_letter = "<" + struct_letter
    else:
        struct_letter = ">" + struct_letter

    try:
        ret_val = struct.pack(struct_letter, val)
    except Exception as e:
        raise e
    return ret_val 

def gdb_read_thread_register(thread_id, thread_list, gdb_register_index):
    '''
    Given a GDB register index, return an str with its value. Obtain
    the value either from the running CPU or the saved KTRAP_FRAME.
    NOTE: Not all registers are supported, if so, 0's are returned.
    '''
    from utils import ConfigurationManager as conf_m
    from api import r_cpu
    from cpus import RT_SEGMENT
    from cpus import RT_REGULAR

    if conf_m.platform == "i386-softmmu":
        from cpus import gdb_map_i386_softmmu as gdb_map
    elif conf_m.platform == "x86_64-softmmu":
        from cpus import gdb_map_x86_64_softmmu as gdb_map
    else:
        raise NotImplementedError("[gdb_read_thread_register] Architecture not supported yet")

    # If it is not mapped to a CPU register or KTRAP_FRAME value,
    # we just return 0s.
    if gdb_register_index not in gdb_map:
        return "\0" * (conf_m.bitness / 8)
    else:
        str_size = gdb_map[gdb_register_index][2]

    cpu_index = None
    thread = None

    some_thread_running = False
    # First, check if we can read the register from the CPU object
    for element in thread_list:
        if element['id'] == thread_id:
            thread = element
            cpu_index = element['running']
            if cpu_index:
                some_thread_running = True

    if thread is None:
        return None

    if cpu_index is None and not some_thread_running:
        cpu_index = 0

    if cpu_index is not None:
        cpu = r_cpu(cpu_index)
        val = 0
        try:
            if gdb_map[gdb_register_index][3] == RT_SEGMENT:
                val = getattr(cpu, gdb_map[gdb_register_index][0])['base']
            else:
                val = getattr(cpu, gdb_map[gdb_register_index][0])
        except:
            val = 0
        if val == -1:
            val = 0
        return val_to_str(val, str_size)
    # If the thread is not running, read it from the KTRAP_FRAME
    else:
        if os_family == OS_FAMILY_WIN:
            from windows_vmi import win_read_thread_register_from_ktrap_frame
            val = 0
            try:
                val = win_read_thread_register_from_ktrap_frame(thread, gdb_map[gdb_register_index][1])
            except Exception as e:
                pp_debug("Exception after win_read_thread_register_from_ktrap_frame: " + str(e))
            if val == -1:
                val = 0
            return val_to_str(val, str_size)
        elif os_family == OS_FAMILY_LINUX:
            raise NotImplementedError("gdb_read_thread_register not implemented yet on Linux guests")

def gdb_write_thread_register(thread_id, thread_list, gdb_register_index, buf):
    '''
    Given a GDB register index, write the provided value. Obtain
    the value either from the running CPU or the saved KTRAP_FRAME.
    NOTE: Not all registers are supported, if so, 0's are returned.
    '''
    from utils import ConfigurationManager as conf_m
    from api import r_cpu
    from cpus import RT_SEGMENT
    from cpus import RT_REGULAR


    if conf_m.platform == "i386-softmmu":
        from cpus import gdb_map_i386_softmmu as gdb_map
    elif conf_m.platform == "x86_64-softmmu":
        from cpus import gdb_map_x86_64_softmmu as gdb_map
    else:
        raise NotImplementedError("[gdb_write_thread_register] Architecture not supported yet")

    # If it is not mapped to a CPU register or KTRAP_FRAME value,
    # we just return 0s.
    if gdb_register_index not in gdb_map:
        return 0 
    else:
        str_size = gdb_map[gdb_register_index][2]

    cpu_index = None
    thread = None
    # First, check if we can read the register from the CPU object
    for element in thread_list:
        if element['id'] == thread_id:
            cpu_index = element['running']
            thread = element
            break

    if thread is None:
        return None

    if cpu_index is not None:
        val = str_to_val(buf, str_size)
        w_r(cpu_index, gdb_map[gdb_register_index][0], val)
        return str_size
    # If the thread is not running, read it from the KTRAP_FRAME
    else:
        if os_family == OS_FAMILY_WIN:
            from windows_vmi import win_read_thread_register_from_ktrap_frame
            try:
                bytes_written = win_write_thread_register_in_ktrap_frame(thread, gdb_map[gdb_register_index][1], buf, str_size)
            except Exception as e:
                pp_debug("Exception after win_write_thread_register_in_ktrap_frame: " + str(e))
            if bytes_written < 0:
                bytes_written = 0
            return bytes_written 
        elif os_family == OS_FAMILY_LINUX:
            raise NotImplementedError("gdb_write_thread_register not implemented yet on Linux guests")

def gdb_set_cpu_pc(thread_id, thread_list, val):
    ''' Set cpu PC '''
    if conf_m.platform == "i386-softmmu":
        from cpus import gdb_map_i386_softmmu as gdb_map
        gdb_register_index = 8 
    elif conf_m.platform == "x86_64-softmmu":
        from cpus import gdb_map_x86_64_softmmu as gdb_map
        gdb_register_index = 16
    else:
        raise NotImplementedError("[gdb_write_thread_register] Architecture not supported yet")

    # If it is not mapped to a CPU register or KTRAP_FRAME value,
    # we just return 0s.
    if gdb_register_index not in gdb_map:
        return 0 
    else:
        str_size = gdb_map[gdb_register_index][2]

    cpu_index = None
    thread = None
    # First, check if we can read the register from the CPU object
    for element in thread_list:
        if element['id'] == thread_id:
            cpu_index = element['running']
            thread = element
            break

    if thread is None:
        return None

    if cpu_index is not None:
        w_r(cpu_index, gdb_map[gdb_register_index][0], val)
        return str_size
    # If the thread is not running, read it from the KTRAP_FRAME
    else:
        if os_family == OS_FAMILY_WIN:
            from windows_vmi import win_read_thread_register_from_ktrap_frame
            try:
                bytes_written = win_write_thread_register_in_ktrap_frame(thread, gdb_map[gdb_register_index][1], val_to_str(val, str_size), str_size)
            except Exception as e:
                pp_debug("Exception after win_write_thread_register_in_ktrap_frame: " + str(e))
            if bytes_written < 0:
                bytes_written = 0
            return bytes_written 
        elif os_family == OS_FAMILY_LINUX:
            raise NotImplementedError("gdb_set_cpu_pc not implemented yet on Linux guests")

def gdb_get_register_size(gdb_register_index):
    ''' Given a register index, returns its register size'''
    if conf_m.platform == "i386-softmmu":
        from cpus import gdb_map_i386_softmmu as gdb_map
    elif conf_m.platform == "x86_64-softmmu":
        from cpus import gdb_map_x86_64_softmmu as gdb_map
    else:
        raise NotImplementedError("[gdb_get_register_size] Architecture not supported yet")

    if gdb_register_index in gdb_map:
        return gdb_map[gdb_register_index][2]
    else:
        return 0

def gdb_memory_rw_debug(thread_id, thread_list, addr, length, buf, is_write):
    ''' Read / Write memory '''

    thread = None
    # First, check if we can read the register from the CPU object
    for element in thread_list:
        if element['id'] == thread_id:
            thread = element
            break

    if thread is None:
        return None

    if is_write:
        from api import w_va
        w_va(thread['pgd'], addr, buf, length)
        return buf
    else:
        try:
            from api import r_va
            import binascii
            mem = r_va(thread['pgd'], addr, length)
            return mem
        except Exception as e:
            raise e

GDB_BREAKPOINT_SW = 0
GDB_BREAKPOINT_HW = 1
GDB_WATCHPOINT_WRITE = 2
GDB_WATCHPOINT_READ = 3
GDB_WATCHPOINT_ACCESS = 4

def gdb_breakpoint_callback(addr, pgd, length, bp_type, params):
    import c_api
    import api

    if bp_type == GDB_BREAKPOINT_SW or bp_type == GDB_BREAKPOINT_HW:
        cpu_index = params["cpu_index"]
        cpu = params["cpu"]
    else:
        cpu_index = params["cpu_index"]
        addr = params["vaddr"]
        size = params["size"]
        haddr = params["haddr"]

    pgd = api.get_running_process(cpu_index)

    thread_id = None
    thread_list = get_threads()
    for thread in thread_list:
        if thread['running'] == cpu_index:
            thread_id = thread['id']

    if thread_id is None:
        return None

    # We must signal GDB client that a breakpoint has occurred
    c_api.gdb_signal_breakpoint(thread_id)

def gdb_breakpoint_insert(thread_id, thread_list, addr, length, bp_type):
    ''' Insert a breakpoing for GDB '''
    global gdb_breakpoint_list
    from api import BP
    import functools

    # Obtain PGD from thread
    thread = None
    # First, check if we can read the register from the CPU object
    for element in thread_list:
        if element['id'] == thread_id:
            thread = element
            break

    if thread is None:
        return 0 

    pgd = thread['pgd']

    if bp_type not in gdb_breakpoint_list:
        gdb_breakpoint_list[bp_type] = {}
    if pgd not in gdb_breakpoint_list[bp_type]:
        gdb_breakpoint_list[bp_type][pgd] = {}
    if addr not in gdb_breakpoint_list[bp_type][pgd]:
        gdb_breakpoint_list[bp_type][pgd][addr] = []

    nb_breakpoints_added = 0

    if bp_type == GDB_BREAKPOINT_SW:
        f = functools.partial(gdb_breakpoint_callback, addr, pgd, length, bp_type)
        bp = BP(addr=addr, pgd=pgd, size=length, typ=BP.EXECUTION, func=f, new_style=True)
        bp.enable()
        gdb_breakpoint_list[bp_type][pgd][addr].append(bp)
        nb_breakpoints_added += 1

    if bp_type == GDB_BREAKPOINT_HW:
        f = functools.partial(gdb_breakpoint_callback, addr, pgd, length, bp_type, new_style=True)
        bp = BP(addr=addr, pgd=pgd, size=length, typ=BP.EXECUTION, func=f)
        bp.enable()
        gdb_breakpoint_list[bp_type][pgd][addr].append(bp)
        nb_breakpoints_added += 1

    if bp_type == GDB_WATCHPOINT_WRITE or bp_type == GDB_WATCHPOINT_ACCESS:
        f = functools.partial(gdb_breakpoint_callback, addr, pgd, length, bp_type, new_style=True)
        bp = BP(addr=addr, pgd=pgd, size=length, typ=BP.MEM_WRITE, func=f)
        bp.enable()
        gdb_breakpoint_list[bp_type][pgd][addr].append(bp)
        nb_breakpoints_added += 1

    if bp_type == GDB_WATCHPOINT_READ or bp_type == GDB_WATCHPOINT_ACCESS:
        f = functools.partial(gdb_breakpoint_callback, addr, pgd, length, bp_type, new_style=True)
        bp = BP(addr=addr, pgd=pgd, size=length, typ=BP.MEM_READ, func=f)
        bp.enable()
        gdb_breakpoint_list[bp_type][pgd][addr].append(bp)
        nb_breakpoints_added += 1

    return nb_breakpoints_added  

def gdb_breakpoint_remove(thread_id, thread_list, addr, length, bp_type):
    ''' Remove a breakpoint from GDB'''
    global gdb_breakpoint_list

    # Obtain PGD from thread
    thread = None
    # First, check if we can read the register from the CPU object
    for element in thread_list:
        if element['id'] == thread_id:
            thread = element
            break

    if thread is None:
        return False 

    pgd = thread['pgd']

    nb_breakpoints_removed = 0
    bps_to_keep = []
    # Disable the corresponding breakpoints
    if bp_type in gdb_breakpoint_list:
        if pgd in gdb_breakpoint_list[bp_type]:
            if addr in gdb_breakpoint_list[bp_type][pgd]:
                for bp in gdb_breakpoint_list[bp_type][pgd][addr]:
                    if bp.get_size() == length:
                        bp.disable()
                    else:
                        bps_to_keep.append(bp)

                nb_breakpoints_removed = len(gdb_breakpoint_list[bp_type][pgd][addr]) - len(bps_to_keep)
                gdb_breakpoint_list[bp_type][pgd][addr] = bps_to_keep

    return nb_breakpoints_removed

def gdb_breakpoint_remove_all():
    ''' Remove all breakpoints from GDB'''
    global gdb_breakpoint_list

    # Disable all breakpoints:
    for bp_type in gdb_breakpoint_list:
        for pgd in gdb_breakpoint_list[bp_type]:
            for addr in gdb_breakpoint_list[bp_type][pgd]:
                for bp in gdb_breakpoint_list[bp_type][pgd][addr]:
                    bp.disable()

    # Empty the list
    gdb_breakpoing_list = {}
