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

# symbol cache
symbols = {}

modules = {}  # List of modules for each process, index is pgd

OS_FAMILY_WIN = 0
OS_FAMILY_LINUX = 1

os_family = None


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

class PseudoLDRDATA:
    '''
        Used to trick volatility to let it parse the export table
    '''

    def __init__(self, base, name, export_directory):
        self.DllBase = base
        self.BaseDllName = name
        self.export_directory = export_directory

    def export_dir(self):
        return self.export_directory


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
