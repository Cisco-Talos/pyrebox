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
from volatility.renderers.basic import Address

from utils import pp_print
from utils import pp_debug
from utils import pp_warning
from utils import pp_error

def linux_get_offsets():
    from utils import ConfigurationManager as conf_m
    import volatility.obj as obj
    import volatility.registry as registry
    try:
        profs = registry.get_plugin_classes(obj.Profile)
        profile = profs[conf_m.vol_profile]()
        init_task_offset = profile.get_symbol("init_task")
        comm_offset = profile.get_obj_offset("task_struct", "comm")
        pid_offset = profile.get_obj_offset("task_struct", "pid")
        tasks_offset = profile.get_obj_offset("task_struct", "tasks")
        mm_offset = profile.get_obj_offset("task_struct", "mm")
        pgd_offset = profile.get_obj_offset("mm_struct", "pgd")
        parent_offset = profile.get_obj_offset("task_struct", "parent")
        exit_state_offset = profile.get_obj_offset("task_struct", "exit_state")
        thread_stack_size = profile.get_obj_offset(
            "pyrebox_thread_stack_size_info", "offset")

        # new process
        proc_exec_connector_offset = profile.get_symbol("proc_exec_connector")
        # new kernel module
        trim_init_extable_offset = profile.get_symbol("trim_init_extable")
        # process exit
        proc_exit_connector_offset = profile.get_symbol("proc_exit_connector")

        return (long(init_task_offset),
                long(comm_offset),
                long(pid_offset),
                long(tasks_offset),
                long(mm_offset),
                long(pgd_offset),
                long(parent_offset),
                long(exit_state_offset),
                long(thread_stack_size),
                long(proc_exec_connector_offset),
                long(trim_init_extable_offset),
                long(proc_exit_connector_offset))

    except Exception as e:
        pp_error("Could not retrieve symbols for profile initialization %s" %
                 str(e))
        return None


def linux_init_address_space():
    from utils import ConfigurationManager as conf_m
    import volatility.utils as utils
    try:
        config = conf_m.vol_conf
        try:
            addr_space = utils.load_as(config)
        except BaseException as e:
            # Return silently
            print (str(e))
            conf_m.addr_space = None
            return False
        conf_m.addr_space = addr_space
        return True
    except Exception as e:
        pp_error("Could not load volatility address space: %s" % str(e))


def linux_insert_module(task, pid, pgd, base, size, basename, fullname, update_symbols=False):
    from utils import ConfigurationManager as conf_m
    import volatility.obj as obj
    from vmi import modules
    from vmi import symbols
    from vmi import Module
    from api_internal import dispatch_module_load_callback
    from api_internal import dispatch_module_remove_callback
    import api
    import hashlib

    pgd_for_memory_read = conf_m.addr_space.vtop(task.mm.pgd) or task.mm.pgd

    # Create module, use 0 as checksum as it is irrelevant here
    mod = Module(base, size, pid, pgd, 0, basename, fullname)

    # Add an entry in the module list, if necessary
    if (pid, pgd) not in modules:
        modules[(pid, pgd)] = {}

    #Module load/del notification
    if base in modules[(pid, pgd)]:
        if modules[(pid, pgd)][base].get_size() != size or \
           modules[(pid, pgd)][base].get_checksum() != checksum or \
           modules[(pid, pgd)][base].get_name() != basename or \
           modules[(pid, pgd)][base].get_fullname() != fullname:
            # Notify of module deletion and module load
            dispatch_module_remove_callback(pid, pgd, base,
                                            modules[(pid, pgd)][base].get_size(),
                                            modules[(pid, pgd)][base].get_name(),
                                            modules[(pid, pgd)][base].get_fullname())
            del modules[(pid, pgd)][base]
            dispatch_module_load_callback(pid, pgd, base, size, basename, fullname)
            modules[(pid, pgd)][base] = mod
    else:
        # Just notify of module load
        dispatch_module_load_callback(pid, pgd, base, size, basename, fullname)
        modules[(pid, pgd)][base] = mod

    # Mark the module as present
    modules[(pid, pgd)][base].set_present()

    if update_symbols:
        # Compute the checksum of the ELF Header, as a way to avoid name
        # collisions on the symbol cache. May extend this hash to other parts
        # of the binary if necessary in the future.
        elf_hdr = obj.Object(
            "elf_hdr", offset=base, vm=task.get_process_address_space())

        if elf_hdr.is_valid():
            elf_hdr_size = elf_hdr.elf_obj.size()
            buf = ""

            try:
                buf = api.r_va(pgd_for_memory_read, base, elf_hdr_size)
            except:
                pp_warning("Could not read ELF header at address %x" % base)

            h = hashlib.sha256()
            h.update(buf)
            checksum = h.hexdigest()

            if (checksum, fullname) not in symbols:
                symbols[(checksum, fullname)] = {}
                syms = symbols[(checksum, fullname)]
                # Fetch symbols
                for sym in elf_hdr.symbols():
                    if sym.st_value == 0 or (sym.st_info & 0xf) != 2:
                        continue

                    sym_name = elf_hdr.symbol_name(sym)
                    sym_offset = sym.st_value
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

            mod.set_symbols(symbols[(checksum, fullname)])

    return None


def linux_insert_kernel_module(module, base, size, basename, fullname, update_symbols=False):
    from vmi import modules
    from vmi import symbols
    from vmi import Module
    from api_internal import dispatch_module_load_callback
    from api_internal import dispatch_module_remove_callback

    # Create module, use 0 as checksum as it is irrelevant here
    mod = Module(base, size, 0, 0, 0, basename, fullname)

    # Add an entry in the module list, if necessary
    if (0, 0) not in modules:
        modules[(0, 0)] = {}

    #Module load/del notification
    if base in modules[(0, 0)]:
        if modules[(0, 0)][base].get_size() != size or \
           modules[(0, 0)][base].get_checksum() != checksum or \
           modules[(0, 0)][base].get_name() != basename or \
           modules[(0, 0)][base].get_fullname() != fullname:
            # Notify of module deletion and module load
            dispatch_module_remove_callback(0, 0, base,
                                            modules[(0, 0)][base].get_size(),
                                            modules[(0, 0)][base].get_name(),
                                            modules[(0, 0)][base].get_fullname())
            del modules[(0, 0)][base]
            dispatch_module_load_callback(0, 0, base, size, basename, fullname)
            modules[(0, 0)][base] = mod
    else:
        # Just notify of module load
        dispatch_module_load_callback(0, 0, base, size, basename, fullname)
        modules[(0, 0)][base] = mod

    # Mark the module as present
    modules[(0, 0)][base].set_present()

    if update_symbols:
        # Use 0 as a checksum, here we should not have name collision
        checksum = 0
        if (checksum, fullname) not in symbols:
            symbols[(checksum, fullname)] = {}
            syms = symbols[(checksum, fullname)]
            try:
                '''
                pp_debug("Processing symbols for module %s\n" % basename)
                '''
                for sym_name, sym_offset in module.get_symbols():
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
            except Exception as e:
                # Probably could not fetch the symbols for this module
                pp_error("%s" % str(e))
                pass

        mod.set_symbols(symbols[(checksum, fullname)])

    return None


def linux_update_modules(pgd, update_symbols=False):
    from utils import ConfigurationManager as conf_m
    import volatility.obj as obj
    from vmi import set_modules_non_present
    from vmi import clean_non_present_modules

    if conf_m.addr_space is None:
        linux_init_address_space()

    # pgd == 0 means that kernel modules have been requested
    if pgd == 0:

        # List entries are returned, so that
        # we can monitor memory writes to these
        # entries and detect when a module is added
        # or removed
        list_entry_size = None
        list_entry_regions = []

        # Now, update the kernel modules
        modules_addr = conf_m.addr_space.profile.get_symbol("modules")
        modules = obj.Object(
            "list_head", vm=conf_m.addr_space, offset=modules_addr)

        # Add the initial list pointer as a list entry
        # modules_addr is the offset of a list_head (2 pointers) that points to the
        # first entry of a module list of type module.
        list_entry_regions.append((modules_addr, modules_addr, modules.size()))

        # Mark all modules as non-present
        set_modules_non_present(0, 0)

        for module in modules.list_of_type("module", "list"):
            """
            pp_debug("Module: %s - %x - %x - %x - %x - %x\n" % (module.name,
                                                                module.obj_offset,
                                                                module.module_init,
                                                                module.init_size,
                                                                module.module_core,
                                                                module.core_size))

            secs = []
            for section in module.get_sections():
                secs.append({"name": section.sect_name, "addr": section.address })

            for section in sorted(secs, key = lambda k: k["addr"]):
                pp_debug("    %s - %x\n" % (section["name"],section["addr"]))
            """

            if list_entry_size is None:
                list_entry_size = module.list.size()
            # The 'module' type has a field named list of type list_head, that points
            # to the next module in the linked list.
            entry = (module.obj_offset, module.list.obj_offset, list_entry_size)
            if entry not in list_entry_regions:
                list_entry_regions.append(entry)

            # First, create a module for the "module_core", that contains
            # .text, readonly data and writable data
            if module.module_core != 0 and module.core_size != 0:
                linux_insert_kernel_module(module, long(module.module_core.v()), long(
                    module.core_size.v()), str(module.name), str(module.name), update_symbols)
            # Now, check if there is "module_init" region, which will contain init sections such as .init.text , init
            # readonly and writable data...
            if module.module_init != 0 and module.init_size != 0:
                linux_insert_kernel_module(module, module.module_init.v(), module.init_size.v(),
                                           module.name + "/module_init", module.name + "/module_init",
                                           update_symbols)
            else:
                # If there is no module_init, check if there is any section
                # outside the module_core region
                secs = []
                for section in module.get_sections():
                    if section.address < module.module_core or section.address >= (module.module_core + module.core_size):
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
                                               module.name + "/module_init", module.name + "/module_init", update_symbols)

        # Remove all the modules that are not marked as present
        clean_non_present_modules(0, 0)
        return list_entry_regions

    # If pgd != 0 was requested
    
    tasks = []

    init_task_addr = conf_m.addr_space.profile.get_symbol("init_task")
    init_task = obj.Object(
        "task_struct", vm=conf_m.addr_space, offset=init_task_addr)

    # walk the ->tasks list, note that this will *not* display "swapper"
    for task in init_task.tasks:
        tasks.append(task)

    # List of tasks (threads) whose pgd is equal to the pgd to update
    tasks_to_update = []

    # First task in the list with a valid pgd
    for task in tasks:
        # Certain kernel threads do not have a memory map (they just take the pgd / memory map of
        # the thread that was previously executed, because the kernel is mapped
        # in all the threads.
        if task.mm:
            phys_pgd = conf_m.addr_space.vtop(task.mm.pgd) or task.mm.pgd
            if phys_pgd == pgd:
                tasks_to_update.append(task)

    # List entries are returned, so that
    # we can monitor memory writes to these
    # entries and detect when a module is added
    # or removed
    list_entry_size = None
    list_entry_regions = []

    for task in tasks_to_update:
        phys_pgd = conf_m.addr_space.vtop(task.mm.pgd) or task.mm.pgd

        # Mark all modules as non-present
        set_modules_non_present(task.pid.v(), phys_pgd)

        # Add the initial list pointer as a list entry
        list_entry_regions.append((task.mm.mmap.obj_offset, task.mm.mmap.obj_offset, task.mm.mmap.size()))

        for vma in task.get_proc_maps():
            if list_entry_size is None:
                list_entry_size = vma.vm_next.size()
            entry = (vma.obj_offset, vma.vm_next.obj_offset, list_entry_size)
            if entry not in list_entry_regions:
                list_entry_regions.append(entry)

            (fname, major, minor, ino, pgoff) = vma.info(task)
            # Only add the module if the inode is not 0 (it is an actual module
            # and not a heap region
            if ino != 0:
                # Checksum
                linux_insert_module(task, task.pid.v(),
                                    Address(phys_pgd),
                                    Address(vma.vm_start),
                                    Address(vma.vm_end) - Address(
                                        vma.vm_start),
                                    os.path.basename(fname),
                                    fname,
                                    update_symbols)

        # Remove all the modules that are not marked as present
        clean_non_present_modules(task.pid.v(), phys_pgd)

    return list_entry_regions
