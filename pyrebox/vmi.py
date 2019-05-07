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

# symbol cache
__symbols = {}

symbol_cache_path = None

__modules = {}  # List of modules for each process, index is pgd

OS_FAMILY_WIN = 0
OS_FAMILY_LINUX = 1

os_family = None

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
