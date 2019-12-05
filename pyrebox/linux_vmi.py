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

import os.path
from utils import pp_error
from utils import pp_print
from utils import pp_debug
from utils import pp_warning
from utils import pp_error
import json

# To mark whether or not we need to save the cache
symbol_cache_must_be_saved = False


def linux_get_offsets():
    # Get the offsets directly from the json file
    # before we initialize volatility
    from utils import ConfigurationManager as conf_m

    # Find the json file
    #'Linux_x64_[filename]'
    file_name = os.path.join(conf_m.volatility_path, "volatility", "symbols", "linux", conf_m.vol_profile[10:] + ".json")
    try:
        f = open(file_name, "r")
        symbols = json.load(f)
        f.close()
    except Exception as e:
        pp_error("Unable to open symbol file: %s" % file_name)

    try:
        init_task_offset = symbols['symbols']['init_task']['address']
        comm_offset = symbols['user_types']['task_struct']['fields']['comm']['offset']
        pid_offset = symbols['user_types']['task_struct']['fields']['pid']['offset']
        tasks_offset = symbols['user_types']['task_struct']['fields']['tasks']['offset']
        mm_offset = symbols['user_types']['task_struct']['fields']['mm']['offset']
        pgd_offset = symbols['user_types']['mm_struct']['fields']['pgd']['offset']
        parent_offset = symbols['user_types']['task_struct']['fields']['parent']['offset']
        exit_state_offset = symbols['user_types']['task_struct']['fields']['exit_state']['offset']

        # new process
        proc_exec_connector_offset = symbols['symbols']['proc_exec_connector']['address']
        # new kernel module
        trim_init_extable_offset = symbols['symbols']['trim_init_extable']['address']
        # process exit
        proc_exit_connector_offset = symbols['symbols']['proc_exit_connector']['address']

        return (int(init_task_offset),
                int(comm_offset),
                int(pid_offset),
                int(tasks_offset),
                int(mm_offset),
                int(pgd_offset),
                int(parent_offset),
                int(exit_state_offset),
                int(proc_exec_connector_offset),
                int(trim_init_extable_offset),
                int(proc_exit_connector_offset))

    except Exception as e:
        pp_error("Could not retrieve symbols for profile initialization %s" %
                 str(e))
        return None


def linux_init_address_space():
    from utils import ConfigurationManager as conf_m
    from volatility_glue import get_volatility_interface

    try:
        conf_m.vol_plugin = get_volatility_interface() 
        if conf_m.vol_plugin is None:
            pp_error("Could not initialize volatility interface")
            return False
        return True
    except Exception as e:
        pp_error("Could not load volatility address space: %s" % str(e))


def linux_insert_module(task, pid, pgd, base, size, basename, fullname, update_symbols=False):
    from utils import ConfigurationManager as conf_m
    from vmi import add_symbols
    from vmi import get_symbols
    from vmi import add_module
    from vmi import has_module
    from vmi import get_module
    from vmi import Module
    from api_internal import dispatch_module_load_callback
    from api_internal import dispatch_module_remove_callback
    from api import r_va
    import api
    import hashlib
    global symbol_cache_must_be_saved


    if conf_m.vol_plugin is None:
        return None

    plugin = conf_m.vol_plugin

    checksum = 0

    # Create module, use 0 as checksum as it is irrelevant here
    mod = Module(base, size, pid, pgd, 0, basename, fullname)

    #Module load/del notification
    if has_module(pid, pgd, base):
        ex_mod = get_module(pid, pgd, base)
        if ex_mod.get_size() != size or \
           ex_mod.get_checksum() != checksum or \
           ex_mod.get_name() != basename or \
           ex_mod.get_fullname() != fullname:
            # Notify of module deletion and module load
            dispatch_module_remove_callback(pid, pgd, base,
                                            ex_mod.get_size(),
                                            ex_mod.get_name(),
                                            ex_mod.get_fullname())
            add_module(pid, pgd, base, mod)
            dispatch_module_load_callback(pid, pgd, base, size, basename, fullname)
    else:
        # Just notify of module load
        dispatch_module_load_callback(pid, pgd, base, size, basename, fullname)
        add_module(pid, pgd, base, mod)

    # Mark the module as present
    get_module(pid, pgd, base).set_present()

    # In Linux, we get one VMA region per program header, and all of them
    # refer to the same file, it is just mapped into different regions.
    # We must only update symbols for the first region (that contains
    # the elf headers).

    is_elf = (api.r_va(pgd, base, 4) == b"\x7f\x45\x4c\x46")

    if is_elf and update_symbols:
        # TODO: Compute the checksum of the ELF Header, as a way to avoid name
        # collisions on the symbol cache. May extend this hash to other parts
        # of the binary if necessary in the future.

        e = plugin.get_elf(task, base)

        if e and e.is_valid():
            syms = {}
            # Fetch symbols
            for sym in e.get_symbols():
                if sym.st_value == 0 or (sym.st_info & 0xf) != 2:
                    continue
                sym_name = sym.get_name()
                if sym.st_value >= base:
                    sym_offset = sym.st_value - base
                else:
                    sym_offset = sym.st_value
                if sym_name:
                    if sym_name in syms:
                        if syms[sym_name] != sym_offset:
                            # There are cases in which the same import is present twice, such as in this case:
                            # nm /lib/x86_64-linux-gnu/libpthread-2.24.so | grep "pthread_getaffinity_np"
                            # 00000000000113f0 T pthread_getaffinity_np@GLIBC_2.3.3
                            # 00000000000113a0 T
                            # pthread_getaffinity_np@@GLIBC_2.3.4
                            sym_name = sym_name + "_"
                            while sym_name in syms and syms[sym_name] != sym_offset:
                                sym_name = sym_name + "_"
                            if sym_name not in syms:
                                syms[sym_name] = sym_offset
                    else:
                        syms[sym_name] = sym_offset

            add_symbols(fullname, syms)
        symbol_cache_must_be_saved = True


    # Always set symbols
    mod.set_symbols(get_symbols(fullname))

    return None


def linux_insert_kernel_module(module, base, size, basename, fullname, update_symbols=False):
    from vmi import add_module
    from vmi import has_module
    from vmi import get_module
    from vmi import get_symbols
    from vmi import add_symbols
    from vmi import Module
    from api_internal import dispatch_module_load_callback
    from api_internal import dispatch_module_remove_callback
    global symbol_cache_must_be_saved

    # Create module, use 0 as checksum as it is irrelevant here
    mod = Module(base, size, 0, 0, 0, basename, fullname)

    checksum = 0

    #Module load/del notification
    if has_module(0, 0, base):
        ex_mod = get_module(0, 0, base)
        if ex_mod.get_size() != size or \
           ex_mod.get_checksum() != checksum or \
           ex_mod.get_name() != basename or \
           ex_mod.get_fullname() != fullname:
            # Notify of module deletion and module load
            dispatch_module_remove_callback(0, 0, base,
                                            ex_mod.get_size(),
                                            ex_mod.get_name(),
                                            ex_mod.get_fullname())
            dispatch_module_load_callback(0, 0, base, size, basename, fullname)
            add_module(0, 0, base, mod)
    else:
        # Just notify of module load
        dispatch_module_load_callback(0, 0, base, size, basename, fullname)
        add_module(0, 0, base, mod)

    # Mark the module as present
    get_module(0, 0, base).set_present()

    if update_symbols:
        syms = {}
        try:
            for sym in module.get_symbols():
                if sym.st_value == 0 or (sym.st_info & 0xf) != 2:
                    continue
                sym_name  = sym.get_name()
                if sym.st_value >= base:
                    sym_offset = sym.st_value - base
                else:
                    sym_offset = sym.st_value
                if sym_name:
                    if sym_name in syms:
                        if syms[sym_name] != sym_offset:
                            # There are cases in which the same import is present twice, such as in this case:
                            # nm /lib/x86_64-linux-gnu/libpthread-2.24.so | grep "pthread_getaffinity_np"
                            # 00000000000113f0 T pthread_getaffinity_np@GLIBC_2.3.3
                            # 00000000000113a0 T
                            # pthread_getaffinity_np@@GLIBC_2.3.4
                            sym_name = sym_name + "_"
                            while sym_name in syms and syms[sym_name] != sym_offset:
                                sym_name = sym_name + "_"
                            if sym_name not in syms:
                                syms[sym_name] = sym_offset
                    else:
                        syms[sym_name] = sym_offset

            add_symbols(fullname, syms)
        except Exception as e:
            # Probably could not fetch the symbols for this module
            pp_error("%s" % str(e))
            pass

        symbol_cache_must_be_saved = True

    # Always set the symbols
    mod.set_symbols(get_symbols(fullname))

    return None


def linux_update_modules(pgd, update_symbols=False):
    from utils import ConfigurationManager as conf_m
    from vmi import set_modules_non_present
    from vmi import clean_non_present_modules

    from utils import ConfigurationManager as conf_m
    global symbol_cache_must_be_saved


    if conf_m.vol_plugin is None:
        return None

    plugin = conf_m.vol_plugin

    list_entry_size = plugin.get_type_size("list_head")

    # pgd == 0 means that kernel modules have been requested
    if pgd == 0:

        # List entries are returned, so that
        # we can monitor memory writes to these
        # entries and detect when a module is added
        # or removed
        list_entry_regions = []

        # Add the initial list pointer as a list entry
        # modules_addr is the offset of a list_head (2 pointers) that points to the
        # first entry of a module list of type module.
        modules_addr = plugin.get_symbol("modules")
        modules_size = plugin.get_symbol_size("modules")
        list_entry_regions.append((modules_addr, modules_addr, modules_size))

        # Mark all modules as non-present
        set_modules_non_present(0, 0)

        for module in plugin.list_kernel_modules():
            # The 'module' type has a field named list of type list_head, that points
            # to the next module in the linked list.
            entry = (plugin.get_object_offset(module), plugin.get_object_offset(module.list), list_entry_size)
            if entry not in list_entry_regions:
                list_entry_regions.append(entry)

            # First, create a module for the "module_core", that contains
            # .text, readonly data and writable data
            mod_core = plugin.get_object_offset(module.get_module_core())
            if module.get_core_size() != 0:
                linux_insert_kernel_module(module, mod_core, 
                                           module.get_core_size(), module.get_name(), module.get_name(),
                                           update_symbols)
            # Now, check if there is "module_init" region, which will contain init sections such as .init.text , init
            # readonly and writable data...
            if module.get_init_size() != 0:
                linux_insert_kernel_module(module, plugin.get_object_offset(module.get_module_init()), module.get_init_size(),
                                           module.get_name() + "/module_init", module.get_name() + "/module_init",
                                           update_symbols)
            else:
                # If there is no module_init, check if there is any section
                # outside the module_core region
                secs = []
                for section in module.get_sections():
                    if section.address < mod_core or section.address >= (mod_core + module.get_core_size()):
                        secs.append(section)

                if len(secs) > 0:
                    # Now, compute the range of sections and put them into a
                    # module_init module block
                    secs = sorted(secs, key=lambda k: k.address)
                    start = secs[0].address
                    # Address of the last section + 0x4000 cause we do not know
                    # the size
                    size = (secs[-1].address + 0x4000) - secs[0].address
                    linux_insert_kernel_module(module, start, size,
                                               module.get_name() + "/module_init", module.get_name() + "/module_init", update_symbols)

        # Remove all the modules that are not marked as present
        clean_non_present_modules(0, 0)

        if symbol_cache_must_be_saved:
            from vmi import save_symbols_to_cache_file
            save_symbols_to_cache_file()
            symbol_cache_must_be_saved = False

        return list_entry_regions

    # If pgd != 0 was requested
    
    tasks_to_update = plugin.get_task_from_pgd(pgd)

    # List entries are returned, so that
    # we can monitor memory writes to these
    # entries and detect when a module is added
    # or removed
    list_entry_size = None
    list_entry_regions = []

    for task in tasks_to_update:
        #phys_pgd = conf_m.addr_space.vtop(task.mm.pgd) or task.mm.pgd
        phys_pgd = pgd

        # Mark all modules as non-present
        set_modules_non_present(int(task.pid), phys_pgd)

        # Add the initial list pointer as a list entry
        list_entry_regions.append((plugin.get_object_offset(task.mm.mmap), plugin.get_object_offset(task.mm.mmap),
                                   plugin.get_type_size("vm_area_struct")))

        for vma in task.mm.get_mmap_iter():
            start = int(vma.vm_start)
            end = int(vma.vm_end)

            # If heap: continue
            if (start <= task.mm.brk and end >= task.mm.start_brk):
                continue

            entry = (plugin.get_object_offset(vma), plugin.get_object_offset(vma.vm_next), list_entry_size)
            if entry not in list_entry_regions:
                list_entry_regions.append(entry)

            fname = vma.get_name(plugin.context, task)
            linux_insert_module(task, int(task.pid),
                                phys_pgd,
                                start,
                                end - start,
                                os.path.basename(fname),
                                fname,
                                update_symbols)

        # Remove all the modules that are not marked as present
        clean_non_present_modules(int(task.pid), phys_pgd)

        if symbol_cache_must_be_saved:
            from vmi import save_symbols_to_cache_file
            save_symbols_to_cache_file()
            symbol_cache_must_be_saved = False

    return list_entry_regions

def linux_read_paged_out_memory(pgd, addr, size):
    raise NotImplementedError()
