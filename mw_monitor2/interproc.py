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
#                           Malware monitor - Interproc
#                           ===========================
#
#   USAGE:  
#           
#
# -------------------------------------------------------------------------------

from __future__ import print_function
import os
import json
import functools

# Determine TARGET_LONG_SIZE
from utils import pp_error
from utils import pp_debug
from utils import pp_warning
from utils import pp_print

from api import get_os_bits

TARGET_LONG_SIZE = get_os_bits() / 8

# Script requirements
requirements = ["autorun.autorun"]

# Global variables
# Callback manager
cm = None
# Printer
pyrebox_print = None

interproc_breakpoints = []
entry_point_bps = {}

breakpoints = {}
bp_funcs = {}


# Lists of exported callbacks

# Classes to hold module configuration and data

class InterprocData():
    '''
    Class that just holds all the data regarding procs, sections, files...
    '''
    def __init__(self):
        # Processes
        self.__procs = {}
        # Written/Read files
        self.__files = []
        # Mapped memory sections
        self.__sections = []

        # Callbacks
        self.__process_callbacks = []
        self.__file_read_callbacks = []
        self.__file_write_callbacks = []
        self.__remote_memory_read_callbacks = []
        self.__remote_memory_write_callbacks = []
        self.__section_map_callbacks = []
        self.__section_unmap_callbacks = []

        # More callbacks
        self.__load_module_callbacks = []
        self.__entry_point_callbacks = []

    # Callback adding functions

    def register_process_callback(self, cb):
        self.__process_callbacks.append(cb)

    def register_file_read_callback(self, cb):
        self.__file_read_callbacks.append(cb)

    def register_file_write_callback(self, cb):
        self.__file_write_callbacks.append(cb)

    def register_remote_memory_read_callback(self, cb):
        self.__remote_memory_read_callbacks.append(cb)

    def register_remote_memory_write_callback(self, cb):
        self.__remote_memory_write_callbacks.append(cb)

    def register_section_map_callback(self, cb):
        self.__section_map_callbacks.append(cb)

    def register_section_unmap_callback(self, cb):
        self.__section_unmap_callbacks.append(cb)
    
    def register_load_module_callback(self, cb):
        self.__load_module_callbacks.append(cb)

    def register_entry_point_callback(self, cb):
        self.__entry_point_callbacks.append(cb)


    def remove_process_callback(self, cb):
        self.__process_callbacks.remove(cb)

    def remove_file_read_callback(self, cb):
        self.__file_read_callbacks.remove(cb)

    def remove_file_write_callback(self, cb):
        self.__file_write_callbacks.remove(cb)

    def remove_remote_memory_read_callback(self, cb):
        self.__remote_memory_read_callbacks.remove(cb)

    def remove_remote_memory_write_callback(self, cb):
        self.__remote_memory_write_callbacks.remove(cb)

    def remove_section_map_callback(self, cb):
        self.__section_map_callbacks.remove(cb)

    def remove_section_unmap_callback(self, cb):
        self.__section_unmap_callbacks.remove(cb)

    def remove_load_module_callback(self, cb):
        self.__load_module_callbacks.remove(cb)

    def remove_entry_point_callback(self, cb):
        self.__entry_point_callbacks.remove(cb)




    def deliver_file_read_callback(self, file_read):
        for cb in self.__file_read_callbacks:
            cb(file_read)
    def deliver_file_write_callback(self, file_write):
        for cb in self.__file_write_callbacks:
            cb(file_write)
    def deliver_remote_memory_read_callback(self, remote_memory_read):
        for cb in self.__remote_memory_read_callbacks:
            cb(remote_memory_read)
    def deliver_remote_memory_write_callback(self, remote_memory_write):
        for cb in self.__remote_memory_write_callbacks:
            cb(remote_memory_write)
    def deliver_section_map_callback(self, section_map):
        for cb in self.__section_map_callbacks:
            cb(section_map)
    def deliver_section_unmap_callback(self, section_map):
        for cb in self.__section_unmap_callbacks:
            cb(section_map)


    def deliver_load_module_callback(self, param):
        for cb in self.__load_module_callbacks:
            cb(param)
    def deliver_entry_point_callback(self, param):
        for cb in self.__entry_point_callbacks:
            cb(param)



    # Object adding/getting functions

    # ---- Process

    def add_process(self, proc):
        self.__procs[proc.get_pid()] = proc
        for cb in self.__process_callbacks:
            cb(proc)

    def get_process(self, index):
        return self.__procs.values()[index]

    def get_process_by_pid(self, pid):
        if pid in self.__procs:
            return self.__procs[pid]
        else:
            return None

    def get_process_by_pgd(self, pgd):
        for p in self.__procs.values():
            if p.get_pgd() == pgd:
                return p
        else:
            return None

    def get_processes(self):
        return self.__procs.values()

    # ---- File 

    def add_file(self, f):
        self.__files.append(f)

    def get_file(self, index):
        return self.__files[i]

    def get_file_by_file_name(self, file_name):
        for fi in self.__files:
            if fi.get_file_name() == file_name:
                return fi
        return None

    # ---- Section

    def add_section(self, section):
        self.__sections.append(section)

    def get_section(self, index):
        return self.__sections[index]

    def get_section_by_offset(self, offset):
        for se in self.__sections:
            if se.get_offset() == offset:
                return se
        return None



class InterprocConfig(object):
    def __init__(self):
        self.interproc_bin_log = False
        self.interproc_text_log = False
        self.interproc_basic_stats = False
        self.interproc_text_log_name = "interproc.log"
        self.interproc_text_log_handle = None
        self.interproc_basic_stats_name = "basic_stats"
        self.interproc_bin_log_name = "interproc.bin"


# Globals
interproc_data = InterprocData()
interproc_config = InterprocConfig()

# Logging functions 

def serialize_interproc():
    global interproc_config
    global interproc_data
    import traceback
    import pickle
    try:
        f_out = open(interproc_config.interproc_bin_log_name, "w")
        pickle.dump(interproc_data, f_out)
        f_out.close()
    except Exception:
        traceback.print_exc()
        pp_error(traceback.print_stack())


def interproc_basic_stats():
    global interproc_config
    global interproc_data
    import traceback
    try:
        f = open(interproc_config.interproc_basic_stats_name, "w")
        for proc in interproc_data.get_processes():
            proc.print_stats(f)
        f.close()
    except Exception:
        traceback.print_exc()
        pp_error(traceback.print_stack())

def module_entry_point(proc, params):
    '''
        Callback on the entry point of the main module being monitored
    '''
    global cm
    global entry_point_bps
    global interproc_data

    from api import CallbackManager
    import api
    from utils import get_addr_space
    import volatility.win32.tasks as tasks

    # Get pameters
    cpu_index = params["cpu_index"]
    cpu = params["cpu"]

    # Get running process
    pgd = api.get_running_process(cpu_index)

    # Disable the entrypoint
    entry_point_bps[pgd].disable()

    # Call all our internal callbacks
    interproc_data.deliver_entry_point_callback(params)

    # Use volatility to check if it is a Wow64 process

    # Get volatility address space using the function in utils
    addr_space = get_addr_space(pgd)

    # Get list of Task objects using volatility (EPROCESS executive objects)
    eprocs = [t for t in tasks.pslist(
        addr_space) if t.Pcb.DirectoryTableBase.v() == pgd]

    if len(eprocs) > 0:
        proc.set_wow64(eprocs[0].IsWow64)


def add_module(proc, params):
    global cm
    global interproc_breakpoints
    global entry_point_bps
    global breakpoints
    global bp_funcs

    from utils import ConfigurationManager as conf_m
    import api

    pid = params["pid"]
    pgd = params["pgd"]
    base = params["base"]
    size = params["size"]
    name = params["name"]
    fullname = params["fullname"]

    pid = proc.get_pid()
    pgd = proc.get_pgd()

    # Update Process instance with module info
    proc.set_module(fullname, base, size)

    from interproc_callbacks import ntcreateprocess
    from interproc_callbacks import ntopenprocess
    from interproc_callbacks import ntwritevirtualmemory
    from interproc_callbacks import ntreadvirtualmemory
    from interproc_callbacks import ntreadfile
    from interproc_callbacks import ntwritefile
    from interproc_callbacks import ntmapviewofsection
    from interproc_callbacks import ntunmapviewofsection
    from interproc_callbacks import ntvirtualprotect
    from interproc_callbacks import ntallocatevirtualmemory


    # Add callbacks, if ntdll is loaded
    if "windows/syswow64/ntdll.dll" in fullname.lower():
        # breakpoints - Dictionary to store breakpoints for the following APIs:
        # bp_funcs - Dictionary that maps dll-function name to breakpoint callbacks and boolean
        # that tells whether the VAD list for the process must be updated after the call
        # or not.

        mod_name = "windows/syswow64/ntdll.dll"

        if (mod_name, "ZwOpenProcess") not in breakpoints:
            breakpoints[(mod_name, "ZwOpenProcess")] = None
            bp_funcs[(mod_name, "ZwOpenProcess")] = (ntopenprocess, True, 4)

        if (mod_name, "ZwReadFile") not in breakpoints:
            breakpoints[(mod_name, "ZwReadFile")] = None
            bp_funcs[(mod_name, "ZwReadFile")] = (ntreadfile, False, 4)

        if (mod_name, "ZwWriteFile") not in breakpoints:
            breakpoints[(mod_name, "ZwWriteFile")] = None
            bp_funcs[(mod_name, "ZwWriteFile")] = (ntwritefile, False, 4)

        if (mod_name, "ZwMapViewOfSection") not in breakpoints:
            breakpoints[(mod_name, "ZwMapViewOfSection")] = None
            bp_funcs[(mod_name, "ZwMapViewOfSection")] = (ntmapviewofsection, True, 4)

        if (mod_name, "ZwUnmapViewOfSection") not in breakpoints:
            breakpoints[(mod_name, "ZwUnmapViewOfSection")] = None
            bp_funcs[(mod_name, "ZwUnmapViewOfSection")] = (ntunmapviewofsection, True, 4)

        if (mod_name, "ZwWriteVirtualMemory") not in breakpoints:
            breakpoints[(mod_name, "ZwWriteVirtualMemory")] = None
            bp_funcs[(mod_name, "ZwWriteVirtualMemory")] = (ntwritevirtualmemory, False, 4)

        if (mod_name, "ZwReadVirtualMemory") not in breakpoints:
            breakpoints[(mod_name, "ZwReadVirtualMemory")] = None
            bp_funcs[(mod_name, "ZwReadVirtualMemory")] = (ntreadvirtualmemory, False, 4)

        if (mod_name, "ZwProtectVirtualMemory") not in breakpoints:
            breakpoints[(mod_name, "ZwProtectVirtualMemory")] = None
            bp_funcs[(mod_name, "ZwProtectVirtualMemory")] = (ntvirtualprotect, False, 4)

        if (mod_name, "NtAllocateVirtualMemory") not in breakpoints:
            breakpoints[(mod_name, "NtAllocateVirtualMemory")] = None
            bp_funcs[(mod_name, "NtAllocateVirtualMemory")] = (ntallocatevirtualmemory, True, 4)

        profile = conf_m.vol_profile

        if (mod_name, "ZwCreateProcessEx") not in breakpoints:
            # We hook both, because although Kernel32 calls the "Ex" version, a
            # program may call directy ZwCreateProcess
            breakpoints[(mod_name, "ZwCreateProcessEx")] = None
            bp_funcs[(mod_name, "ZwCreateProcessEx")] = (
                ntcreateprocess, True, 4)

        if (mod_name, "ZwCreateProcess") not in breakpoints:
            breakpoints[(mod_name, "ZwCreateProcess")] = None
            bp_funcs[(mod_name, "ZwCreateProcess")] = (
                ntcreateprocess, True, 4)

        if not ("WinXP" in profile or "Win2003" in profile):
            # On Vista (and onwards), kernel32.dll no longer uses
            # ZwCreateProcess/ZwCreateProcessEx (although these function remain
            # in ntdll.dll. It Uses ZwCreateUserProcess.
            if (mod_name, "ZwCreateUserProcess") not in breakpoints:
                breakpoints[(mod_name, "ZwCreateUserProcess")] = None
                bp_funcs[(mod_name, "ZwCreateUserProcess")] = (
                    ntcreateprocess, True, 4)

    elif "windows/system32/ntdll.dll" in fullname.lower():

        mod_name = "windows/system32/ntdll.dll"

        if (mod_name, "ZwOpenProcess") not in breakpoints:
            breakpoints[(mod_name, "ZwOpenProcess")] = None
            bp_funcs[(mod_name, "ZwOpenProcess")] = (ntopenprocess, True, TARGET_LONG_SIZE)

        if (mod_name, "ZwReadFile") not in breakpoints:
            breakpoints[(mod_name, "ZwReadFile")] = None
            bp_funcs[(mod_name, "ZwReadFile")] = (ntreadfile, False, TARGET_LONG_SIZE)

        if (mod_name, "ZwWriteFile") not in breakpoints:
            breakpoints[(mod_name, "ZwWriteFile")] = None
            bp_funcs[(mod_name, "ZwWriteFile")] = (ntwritefile, False, TARGET_LONG_SIZE)

        if (mod_name, "ZwMapViewOfSection") not in breakpoints:
            breakpoints[(mod_name, "ZwMapViewOfSection")] = None
            bp_funcs[(mod_name, "ZwMapViewOfSection")] = (ntmapviewofsection, True, TARGET_LONG_SIZE)

        if (mod_name, "ZwUnmapViewOfSection") not in breakpoints:
            breakpoints[(mod_name, "ZwUnmapViewOfSection")] = None
            bp_funcs[(mod_name, "ZwUnmapViewOfSection")] = (ntunmapviewofsection, True, TARGET_LONG_SIZE)

        if (mod_name, "ZwWriteVirtualMemory") not in breakpoints:
            breakpoints[(mod_name, "ZwWriteVirtualMemory")] = None
            bp_funcs[(mod_name, "ZwWriteVirtualMemory")] = (ntwritevirtualmemory, False, TARGET_LONG_SIZE)

        if (mod_name, "ZwReadVirtualMemory") not in breakpoints:
            breakpoints[(mod_name, "ZwReadVirtualMemory")] = None
            bp_funcs[(mod_name, "ZwReadVirtualMemory")] = (ntreadvirtualmemory, False, TARGET_LONG_SIZE)

        if (mod_name, "ZwProtectVirtualMemory") not in breakpoints:
            breakpoints[(mod_name, "ZwProtectVirtualMemory")] = None
            bp_funcs[(mod_name, "ZwProtectVirtualMemory")] = (ntvirtualprotect, False, TARGET_LONG_SIZE)

        if (mod_name, "NtAllocateVirtualMemory") not in breakpoints:
            breakpoints[(mod_name, "NtAllocateVirtualMemory")] = None
            bp_funcs[(mod_name, "NtAllocateVirtualMemory")] = (ntallocatevirtualmemory, True, TARGET_LONG_SIZE)


        profile = conf_m.vol_profile

        if (mod_name, "ZwCreateProcessEx") not in breakpoints:
            # We hook both, because although Kernel32 calls the "Ex" version, a
            # program may call directy ZwCreateProcess
            breakpoints[(mod_name, "ZwCreateProcessEx")] = None
            bp_funcs[(mod_name, "ZwCreateProcessEx")] = (
                ntcreateprocess, True, TARGET_LONG_SIZE)

        if (mod_name, "ZwCreateProcess") not in breakpoints:
            breakpoints[(mod_name, "ZwCreateProcess")] = None
            bp_funcs[(mod_name, "ZwCreateProcess")] = (
                ntcreateprocess, True, TARGET_LONG_SIZE)

        if not ("WinXP" in profile or "Win2003" in profile):
            # On Vista (and onwards), kernel32.dll no longer uses
            # ZwCreateProcess/ZwCreateProcessEx (although these function remain
            # in ntdll.dll. It Uses ZwCreateUserProcess.
            if (mod_name, "ZwCreateUserProcess") not in breakpoints:
                breakpoints[(mod_name, "ZwCreateUserProcess")] = None
                bp_funcs[(mod_name, "ZwCreateUserProcess")] = (
                    ntcreateprocess, True, TARGET_LONG_SIZE)

    # Add breakpoint if necessary
    for (mod, fun) in breakpoints:
        if breakpoints[(mod, fun)] is None:
            try:
                f_callback = bp_funcs[(mod, fun)][0]
                update_vads = bp_funcs[(mod, fun)][1]
                long_size = bp_funcs[(mod, fun)][2]
                callback = functools.partial(
                    f_callback, cm=cm, proc=proc, update_vads=update_vads, long_size = long_size)
                bp = api.BP(str("%s!%s" % (mod, fun)), pgd, func = callback, new_style = True)
                bp.enable()
                interproc_breakpoints.append(bp)
                breakpoints[(mod, fun)] = (bp, bp.get_addr())
                pp_print("Adding breakpoint at %s:%s %x:%x from process with PID %x\n" %
                              (mod, fun, bp.get_addr(), pgd, pid))
            except Exception as e:
                pyrebox_print("Could not set breakpoint on interproc: %s" % str(e))


    # Main module of the process. Only set entry point callback if it has not been set already.
    # In some cases the main module gets reloaded.
    if name.lower() == proc.get_proc_name() and pgd not in entry_point_bps:
        # Set a breakpoint on the EP
        entry_point_bps[pgd] = api.BP(base,
                                pgd,
                                size = size,
                                new_style = True,
                                func = functools.partial(module_entry_point, proc))

        entry_point_bps[pgd].enable()

    # Call all our internal callbacks
    interproc_data.deliver_load_module_callback(params)


def module_loaded(proc, params):
    '''
        LOADMODULE_CB, for every created process
    '''
    global pyrebox_print
    #pid = params["pid"]
    #pgd = params["pgd"]
    #base = params["base"]
    #size = params["size"]
    #name = params["name"]
    #fullname = params["fullname"]
    add_module(proc, params)

def tlb_exec(target_proc, params):
    '''
        TLB exec, that waits to set load module callback
    '''
    import api
    from api import CallbackManager
    global cm
    cpu = params["cpu"]
    pgd = api.get_running_process(cpu.CPU_INDEX)

    if pgd == target_proc.get_pgd():
        cm.rm_callback(("tlb_exec_%d" % pgd))
        cm.add_callback(CallbackManager.LOADMODULE_CB, 
                        functools.partial(module_loaded, target_proc), 
                        pgd = pgd, 
                        name = ("load_module_%x" % pgd))


def interproc_start_monitoring_process(params):
    '''
        Given a Process instance, do the magic
        to start monitoring the process for the
        interproc module
    '''
    global cm
    global interproc_data

    import api
    from core import Process
    from api import CallbackManager

    # Get parameters
    pid = params["pid"]
    pgd = params["pgd"]
    name = params["name"]

    proc = Process(name)
    proc.set_pgd(pgd)
    proc.set_pid(pid)

    # Append process to process list
    interproc_data.add_process(proc)

    # add_module, for every module loaded so far for this process. Because
    # this function might be triggered by a call to NtOpenProcess over
    # an already existing process
    try:
        for mod in api.get_module_list(pgd):
            add_module(proc, {"pid": pid,
                              "pgd": pgd,
                              "base": mod["base"],
                              "size": mod["size"],
                              "name": mod["name"],
                              "fullname": mod["fullname"]})
        # Callback for each module loaded
        cm.add_callback(CallbackManager.LOADMODULE_CB, 
                        functools.partial(module_loaded, proc), 
                        pgd = pgd, 
                        name = ("load_module_%x" % pgd))
    except ValueError:
        # Could happen that the process is still not on the list of
        # created processes
        pp_debug("Process still not in the list of created processes, setting CB on TLB exec.\n")
        cm.add_callback(CallbackManager.TLB_EXEC_CB, functools.partial(tlb_exec, proc), name=("tlb_exec_%d" % pgd))





# ============================== INITIALIZATION =================================

def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    global pyrebox_print
    global interproc_config
    global interproc_breakpoints

    from autorun.autorun import remove_autorun_create_proc_callback

    pyrebox_print("[*]    Cleaning module")
    remove_autorun_create_proc_callback(interproc_start_monitoring_process)
    cm.clean()

    for bp in interproc_breakpoints:
        bp.disable()

    if interproc_config.interproc_text_log_handle:
        interproc_config.interproc_text_log_handle.close()
        interproc_config.interproc_text_log_handle = None

    if interproc_config.interproc_basic_stats:
        interproc_basic_stats()

    if interproc_config.interproc_bin_log:
        serialize_interproc()

    pyrebox_print("[*]    Cleaned module")


def initialize_callbacks(module_hdl, printer):
    '''
    Initialize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    from api import CallbackManager
    from plugins.guest_agent import guest_agent
    from autorun.autorun import register_autorun_create_proc_callback
    global interproc_config

    global cm
    global pyrebox_print

    pyrebox_print = printer

    # Set configuration values
    try:
        pyrebox_print("[*]    Reading configuration file")
        #Read AutoRun configuration file (json)
        f = open(os.environ["MWMONITOR_INTERPROC_CONF_PATH"], "r")
        conf = json.load(f)
        f.close()
        interproc_config.interproc_bin_log = conf.get("bin_log", False)
        interproc_config.interproc_text_log = conf.get("text_log", False)
        interproc_config.interproc_basic_stats = conf.get("basic_stats", False)
        interproc_config.interproc_text_log_name = conf.get("text_log_path", "interproc.log")
        interproc_config.interproc_basic_stats_name = conf.get("basic_stats_path", "basic_stats")
        interproc_config.interproc_bin_log_name = conf.get("bin_log_path", "interproc.bin")

        
        interproc_config.interproc_text_log_handle = open(interproc_config.interproc_text_log_name, "w")

    except Exception as e:
        pyrebox_print("Could not read or correctly process the configuration file: %s" % str(e))
        return
    
    try:
        cm = CallbackManager(module_hdl, new_style = True)
        # Initialize process creation callback
        pyrebox_print("[*]    Initializing callbacks")
        register_autorun_create_proc_callback(interproc_start_monitoring_process)
        pyrebox_print("[*]    Initialized callbacks")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
