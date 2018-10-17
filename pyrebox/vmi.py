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
symbols = {}

symbol_cache_path = None

modules = {}  # List of modules for each process, index is pgd

OS_FAMILY_WIN = 0
OS_FAMILY_LINUX = 1

os_family = None

def set_symbol_cache_path(path):
    global symbol_cache_path
    symbol_cache_path = path

# Function to load symbols from a file cache
def load_symbols_from_cache_file():
    global symbols
    global symbol_cache_path
    if symbol_cache_path is not None and os.path.isfile(symbol_cache_path):
        try:
            f = open(symbol_cache_path, "r")
            symbols = json.loads(f.read())
            f.close()
        except Exception as e:
            pp_error("Error while reading symbols from %s: %s\n" % (symbol_cache_path, str(e)))


# Function to save symbols to a file cache
def save_symbols_to_cache_file():
    global symbols
    global symbol_cache_path
    if symbol_cache_path is not None:
        f = open(symbol_cache_path, "w")
        f.write(json.dumps(symbols))
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
    if pid is not None:
        if (pid, pgd) in modules:
            for base, mod in modules[(pid, pgd)].iteritems():
                mod.set_present(False)
    else:
        for pid, _pgd in modules.keys():
            if _pgd == pgd:
                if (pid, pgd) in modules:
                    for base, mod in modules[(pid, _pgd)].iteritems():
                        mod.set_present(False)

def clean_non_present_modules(pid, pgd):
    from api_internal import dispatch_module_remove_callback

    mods_to_remove = []
    if pid is not None:
        if (pid, pgd) in modules:
            for base, mod in modules[(pid, pgd)].iteritems():
                if not mod.is_present():
                    mods_to_remove.append((pid, pgd, base))
    else:
        for pid, _pgd in modules.keys():
            if _pgd == pgd:
                if (pid, _pgd) in modules:
                    for base, mod in modules[(pid, _pgd)].iteritems():
                        if not mod.is_present():
                            mods_to_remove.append((pid, pgd, base))

    for pid, pgd, base in mods_to_remove:
        # Callback notification
        dispatch_module_remove_callback(pid, pgd, base, 
                                        modules[(pid, pgd)][base].get_size(),
                                        modules[(pid, pgd)][base].get_name(),
                                        modules[(pid, pgd)][base].get_fullname())

        # Remove module
        del modules[(pid, pgd)][base]


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
