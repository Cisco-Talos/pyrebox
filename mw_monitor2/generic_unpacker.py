# -------------------------------------------------------------------------------
#
#   Copyright (C) 2018 Cisco Talos Security Intelligence and Research Group
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
# -------------------------------------------------------------------------------

# -------------------------------------------------------------------------------
#                           PyREBox Generic Unpacker
#                           ========================
#
#   USAGE:  Configure the following environment variables.
#               GENERIC_UNPACKER_CONF_PATH= // The path to the json config file
#
#           The json config file must contain the following values
#               unpacker_log_path=""
#               unpacker_dump_path=""  // The path is appended with _1, _2, _3... 
#                                      // for every layer number. Existing contents 
#                                      // are deleted.
#
#           This script uses the mw_monitor2/interproc module. See the module's 
#           documentation for additional information.
#           
#
# -------------------------------------------------------------------------------

from __future__ import print_function
import os
import json
import functools

# Determine TARGET_LONG_SIZE
from api import get_os_bits
TARGET_LONG_SIZE = get_os_bits() / 8

# Our helpers, that leverage volatility
from vads import VADRegion, get_vads
from memory_dump import dump

# Script requirements
requirements = ["mw_monitor2.interproc"]

# Global variables
# Callback manager
cm = None
# Printer
pyrebox_print = None

# Memory page status
page_status_w = {}
page_status_x = {}
# Global var for current layer status
current_layer = 0

# Configuration values
UNPACKER_LOG_PATH = None
UNPACKER_DUMP_PATH = None

memory_dump_callbacks = []
written_files = []
section_maps = []

dump_counter = 0


def register_memory_dump_callback(cb):
    global memory_dump_callbacks
    memory_dump_callbacks.append(cb)


def remove_memory_dump_callback(cb):
    global memory_dump_callbacks
    memory_dump_callbacks.remove(cb)


def deliver_memory_dump_callback(params):
    global memory_dump_callbacks
    for cb in memory_dump_callbacks:
        cb(params)


def init_log():
    '''
        Initialize log (remove file if it exists)
    '''
    global UNPACKER_LOG_PATH
    global UNPACKER_DUMP_PATH

    if os.path.isfile(UNPACKER_LOG_PATH):
        os.remove(UNPACKER_LOG_PATH)


def append_log(line):
    '''
        Append line to log file, add line feed if necessary.
    '''
    global UNPACKER_LOG_PATH
    global UNPACKER_DUMP_PATH

    f = open(UNPACKER_LOG_PATH, "a")
    if line[-1] != "\n":
        line += "\n"
    f.write(line)
    f.close()


def generate_dump(pgd, reason):
    #Create dump
    global pyrebox_print
    global current_layer
    global dump_counter

    f = open(os.path.join(UNPACKER_DUMP_PATH, "dump_list.txt"), "a")
    f.write("DUMP %d - Layer %d - Reason: %s\n" % (dump_counter, current_layer, reason))
    dump([pgd], pyrebox_print, path = os.path.join(UNPACKER_DUMP_PATH, "dump_%d_layer-%d" % (dump_counter, current_layer)))
    dump_counter += 1
    f.close()


def mem_write(params):
    '''
        Callback for memory writes.
    '''
    global cm
    global page_status_x
    global page_status_w
    global current_layer
    global UNPACKER_LOG_PATH
    global UNPACKER_DUMP_PATH
    global section_maps
    global written_files

    import api
    from cpus import X64CPU, X86CPU

    # Get callback parameters
    cpu_index = params["cpu_index"]
    vaddr = params["vaddr"]
    size = params["size"]
    haddr = params["haddr"]
    data = params["data"]

    # Get running process, as well as CPU object
    pgd = api.get_running_process(cpu_index)
    cpu = api.r_cpu(cpu_index)

    if pgd not in page_status_w:
        page_status_w[pgd] = {}

    if not api.is_kernel_running(cpu_index):
        mask = 0xFFFFF000 if TARGET_LONG_SIZE == 4 else 0xFFFFFFFFFFFFF000
        page = vaddr & mask

        # Set page write status (update with current layer)
        page_status_w[pgd][page] = current_layer

        # Log the page write
        pc = cpu.RIP if isinstance(cpu, X64CPU) else cpu.EIP
        if TARGET_LONG_SIZE == 4:
            append_log("[W]  - PGD [%08x] - PAGE [%08x] - FROM [%08x]" % (pgd, page, pc))
        else:
            append_log("[W]  - PGD [%016x] - PAGE [%016x] - FROM [%016x]" % (pgd, page, pc))

        # Finally, check if the memory was mapped to file, so we record a file write for such file
        for base, size, file_name in section_maps:
            if page >= (base & mask) and page < (((base + size) & mask) + 0x1000):
                if file_name not in written_files:
                    written_files.append(file_name)
                    append_log("------> Section mapped, FILE [%s]" % (file_name))


def block_exec(params):
    '''
        Callback for memory execution.
    '''
    global cm
    global page_status_x
    global page_status_w
    global current_layer
    global UNPACKER_LOG_PATH
    global UNPACKER_DUMP_PATH

    import api

    # Get parameters
    cpu_index = params["cpu_index"]
    cpu = params["cpu"]
    pc, size, icount = params["tb"]

    # Get running process
    pgd = api.get_running_process(cpu_index)

    mask = 0xFFFFF000 if TARGET_LONG_SIZE == 4 else 0xFFFFFFFFFFFFF000
    page = pc & mask

    if pgd not in page_status_w:
        page_status_w[pgd] = {}
    if pgd not in page_status_x:
        page_status_x[pgd] = {}


    if page in page_status_w[pgd]:
        # Update page status, according to the layer
        # that wrote the page.
        page_status_x[pgd][page] = page_status_w[pgd][page] + 1

        if TARGET_LONG_SIZE == 4:
            append_log("[WX] - PGD [%08x] - PAGE [%08x] - EP   [%08x]" % (pgd, page, pc))
        else:
            append_log("[WX] - PGD [%016x] - PAGE [%016x] - EP   [%016x]" % (pgd, page, pc))

        # If we are jumping (for the first time), into a new layer:
        if page_status_x[pgd][page] > current_layer:
            # Report it on the log, and dump the list of VAD regions
            append_log("+----- LAYER %d -> LAYER %d" % (current_layer, page_status_x[pgd][page]))
            append_log("+----- VAD LIST")
            append_log("+----- ========")
            for vad in get_vads(pgd):
                append_log("+----- " + str(vad))

            # Update current layer
            current_layer = page_status_x[pgd][page]

            # Reset write cache on triggers
            cm.call_trigger_function("mem_write", "erase_vars")
            cm.call_trigger_function("block_begin", "erase_vars")

            generate_dump(pgd, "Transition to previously written memory page(s)")

            deliver_memory_dump_callback({"pgd": pgd, "page_status_x": page_status_x[pgd], "page_status_w": page_status_w[pgd]})
    else:
        # Update page status (execution)
        page_status_x[pgd][page] = current_layer


def module_entry_point(params):
    '''
        Callback on the entry point of the main module being monitored
    '''
    global cm
    global UNPACKER_LOG_PATH
    global UNPACKER_DUMP_PATH
    global pyrebox_print

    from api import CallbackManager
    import api

    # Get pameters
    cpu_index = params["cpu_index"]
    cpu = params["cpu"]

    # Get running process
    pgd = api.get_running_process(cpu_index)

    pyrebox_print("Reached entry point of new process: %x" % pgd)

    # Add memory write / memory execute callbacks, and their triggers
    cm.add_callback(CallbackManager.MEM_WRITE_CB, mem_write, name="mem_write")
    cm.add_callback(CallbackManager.BLOCK_BEGIN_CB, block_exec, name="block_begin")

    cm.add_trigger("mem_write", "triggers/trigger_memwrite_wx.so")
    cm.set_trigger_var("mem_write", "begin", 0x0)
    if TARGET_LONG_SIZE == 4:
        cm.set_trigger_var("mem_write", "end", 0x80000000)
    else:
        cm.set_trigger_var("mem_write", "end", 0x000007FFFFFFFFFF)
    cm.set_trigger_var("mem_write", "pgd", pgd)

    cm.add_trigger("block_begin", "triggers/trigger_blockbegin_wx.so")
    cm.set_trigger_var("block_begin", "begin", 0x0)
    if TARGET_LONG_SIZE == 4:
        cm.set_trigger_var("block_begin", "end", 0x80000000)
    else:
        cm.set_trigger_var("block_begin", "end", 0x000007FFFFFFFFFF)
    cm.set_trigger_var("block_begin", "pgd", pgd)

    # Start monitoring process
    api.start_monitoring_process(pgd)

    # Create a dump, on process entry point for every process
    generate_dump(pgd, "Dump at process entry point for PGD 0x%x" % pgd)

    pyrebox_print("Started monitoring process")

def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    global pyrebox_print
    global UNPACKER_LOG_PATH
    global UNPACKER_DUMP_PATH
    global interproc_data

    pyrebox_print("[*]    Cleaning module")
    interproc_data.remove_entry_point_callback(module_entry_point)
    cm.clean()
    pyrebox_print("[*]    Cleaned module")

def file_read(file_read):
    '''
        File read operations
    '''
    global written_files
    if file_read.get_file().get_file_name() in written_files:
        pgd = file_read.get_proc().get_pgd() 
        addr = file_read.get_offset()
        size = file_read.get_size()

        if pgd not in page_status_w:
            page_status_w[pgd] = {}

        mask = 0xFFFFF000 if TARGET_LONG_SIZE == 4 else 0xFFFFFFFFFFFFF000
        page = addr & mask

        while page < (addr + size):
            # Set page write status (update with current layer)
            page_status_w[pgd][page] = current_layer
            page += 0x1000

            # Log the page write
            if TARGET_LONG_SIZE == 4:
                append_log("[W]  - NtReadFile PGD [%08x] - PAGE [%08x] - FILE [%s]" % (pgd, page, file_read.get_file().get_file_name()))
            else:
                append_log("[W]  - NtReadFile PGD [%016x] - PAGE [%016x] - FILE [%s]" % (pgd, page, file_read.get_file().get_file_name()))


def file_write(file_write):
    '''
        File write operation
    '''
    global written_files
    if file_write.get_file().get_file_name() not in written_files:
        written_files.append(file_write.get_file().get_file_name())

def memory_read(injection):
    '''
        Callback on memory read.
    '''
    pgd = injection.get_local_proc().get_pgd()

    if pgd not in page_status_w:
        page_status_w[pgd] = {}

    mask = 0xFFFFF000 if TARGET_LONG_SIZE == 4 else 0xFFFFFFFFFFFFF000
    page = injection.get_local_addr() & mask

    while page < (injection.get_local_addr() + injection.get_size()):
        # Set page write status (update with current layer)
        page_status_w[pgd][page] = current_layer
        page += 0x1000

        # Log the page write
        if TARGET_LONG_SIZE == 4:
            append_log("[W]  - NtReadVirtualMemory PGD [%08x] - PAGE [%08x]" % (pgd, page))
        else:
            append_log("[W]  - NtReadVirtualMemory PGD [%016x] - PAGE [%016x]" % (pgd, page))

def memory_write(injection):
    '''
        Callback on memory write
    '''

    pgd = injection.get_remote_proc().get_pgd()

    if pgd not in page_status_w:
        page_status_w[pgd] = {}

    mask = 0xFFFFF000 if TARGET_LONG_SIZE == 4 else 0xFFFFFFFFFFFFF000
    page = injection.get_remote_addr() & mask

    while page < (injection.get_remote_addr() + injection.get_size()):
        # Set page write status (update with current layer)
        page_status_w[pgd][page] = current_layer
        page += 0x1000

        # Log the page write
        if TARGET_LONG_SIZE == 4:
            append_log("[W]  - NtWriteVirtualMemory PGD [%08x] - PAGE [%08x]" % (pgd, page))
        else:
            append_log("[W]  - NtWriteVirtualMemory PGD [%016x] - PAGE [%016x]" % (pgd, page))

def section_map(section_map):
    '''
        Callback on Section Map
    '''
    global section_maps
    if section_map.get_section().is_file_backed():
        file_name = section_map.get_section().get_backing_file().get_file_name()
        # 1) Add the entry to the list
        entry = (section_map.get_base(), 
                 section_map.get_size(), 
                 file_name)
        if entry not in section_maps:
            section_maps.append(entry)

        # 2) If the file had been previously written, mark memory as written
        if file_name in written_files: 
            pgd = section_map.get_pgd() 

            if pgd not in page_status_w:
                page_status_w[pgd] = {}

            mask = 0xFFFFF000 if TARGET_LONG_SIZE == 4 else 0xFFFFFFFFFFFFF000
            page = section_map.get_base() & mask

            while page < (section_map.get_base() + section_map.get_size()):
                # Set page write status (update with current layer)
                page_status_w[pgd][page] = current_layer
                page += 0x1000

                # Log the page write
                if TARGET_LONG_SIZE == 4:
                    append_log("[W]  - NtMapViewOfSection PGD [%08x] - PAGE [%08x] - FILE [%s]" % (pgd, page, file_name))
                else:
                    append_log("[W]  - NtMapViewOfSection PGD [%016x] - PAGE [%016x] - FILE [%s]" % (pgd, page, file_name))


def initialize_callbacks(module_hdl, printer):
    '''
    Initialize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    from api import CallbackManager
    from plugins.guest_agent import guest_agent
    from mw_monitor2.interproc import interproc_data

    global cm
    global pyrebox_print
    global UNPACKER_LOG_PATH
    global UNPACKER_DUMP_PATH
    global interproc_data


    pyrebox_print = printer

    # Set configuration values
    try:
        f = open(os.environ["GENERIC_UNPACKER_CONF_PATH"], "r")
        conf_data = json.load(f)
        f.close()
        UNPACKER_LOG_PATH = conf_data.get("unpacker_log_path", None)
        UNPACKER_DUMP_PATH = conf_data.get("unpacker_dump_path", None)
        if UNPACKER_LOG_PATH is None or UNPACKER_DUMP_PATH is None:
            raise ValueError("The json configuration file is not well-formed: fields missing?")
    except Exception as e:
        pyrebox_print("Could not read or correctly process the configuration file: %s" % str(e))
        return
    
    try:
        # Initialize log
        init_log()
        # Initialize process creation callback
        pyrebox_print("[*]    Initializing callbacks")
        interproc_data.register_entry_point_callback(module_entry_point)
        interproc_data.register_file_read_callback(file_read)
        interproc_data.register_file_write_callback(file_write)
        interproc_data.register_remote_memory_read_callback(memory_read)
        interproc_data.register_remote_memory_write_callback(memory_write)
        interproc_data.register_section_map_callback(section_map)
        cm = CallbackManager(module_hdl, new_style = True)
        pyrebox_print("[*]    Initialized callbacks")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
