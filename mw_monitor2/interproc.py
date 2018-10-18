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

# Classes to hold module configuration and data

class InterprocData():
    '''
    Class that just holds all the data regarding procs, sections, files...
    '''
    def __init__(self):
        # Processes
        self.procs = []
        # Written/Read files
        self.files = []
        # Mapped memory sections
        self.sections = []


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
        for proc in interproc_data.procs:
            proc.print_stats(interproc_config.interproc_basic_stats_name)
    except Exception:
        traceback.print_exc()
        pp_error(traceback.print_stack())


def add_module(proc, name, base, size):
    global cm
    global interproc_breakpoints

    from utils import ConfigurationManager as conf_m
    import api

    pid = proc.get_pid()
    pgd = proc.get_pgd()

    # Update Process instance with module info
    proc.set_module(name, base, size)

    # Add callbacks, if ntdll is loaded
    if "ntdll.dll" in name.lower():
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

        # Dictionary to store breakpoints for the following APIs:
        breakpoints = {("ntdll.dll", "ZwOpenProcess"): None,
                            ("ntdll.dll", "ZwReadFile"): None,
                            ("ntdll.dll", "ZwWriteFile"): None,
                            ("ntdll.dll", "ZwMapViewOfSection"): None,
                            ("ntdll.dll", "ZwUnmapViewOfSection"): None,
                            ("ntdll.dll", "ZwWriteVirtualMemory"): None,
                            ("ntdll.dll", "ZwReadVirtualMemory"): None,
                            ("ntdll.dll", "ZwProtectVirtualMemory"): None,
                            ("ntdll.dll", "NtAllocateVirtualMemory"): None}

        # Dictionary that maps dll-function name to breakpoint callbacks and boolean
        # that tells whether the VAD list for the process must be updated after the call
        # or not.
        bp_funcs = {
            ("ntdll.dll", "ZwOpenProcess"): (ntopenprocess, True),
            ("ntdll.dll", "ZwReadFile"): (ntreadfile, False),
            ("ntdll.dll", "ZwWriteFile"): (ntwritefile, False),
            ("ntdll.dll", "ZwMapViewOfSection"): (ntmapviewofsection, True),
            ("ntdll.dll", "ZwUnmapViewOfSection"): (ntunmapviewofsection, True),
            ("ntdll.dll", "ZwWriteVirtualMemory"): (ntwritevirtualmemory, False),
            ("ntdll.dll", "ZwReadVirtualMemory"): (ntreadvirtualmemory, False),
            ("ntdll.dll", "ZwProtectVirtualMemory"): (ntvirtualprotect, False),
            ("ntdll.dll", "NtAllocateVirtualMemory"): (ntallocatevirtualmemory, True)}

        profile = conf_m.vol_profile

        # If before vista:
        if "WinXP" in profile or "Win2003" in profile:
            # We hook both, because although Kernel32 calls the "Ex" version, a
            # program may call directy ZwCreateProcess
            breakpoints[("ntdll.dll", "ZwCreateProcessEx")] = None
            bp_funcs[("ntdll.dll", "ZwCreateProcessEx")] = (
                ntcreateprocess, True)
            breakpoints[("ntdll.dll", "ZwCreateProcess")] = None
            bp_funcs[("ntdll.dll", "ZwCreateProcess")] = (
                ntcreateprocess, True)
        else:
            breakpoints[("ntdll.dll", "ZwCreateProcessEx")] = None
            bp_funcs[("ntdll.dll", "ZwCreateProcessEx")] = (
                ntcreateprocess, True)
            breakpoints[("ntdll.dll", "ZwCreateProcess")] = None
            bp_funcs[("ntdll.dll", "ZwCreateProcess")] = (
                ntcreateprocess, True)
            # On Vista (and onwards), kernel32.dll no longer uses
            # ZwCreateProcess/ZwCreateProcessEx (although these function remain
            # in ntdll.dll. It Uses ZwCreateUserProcess.
            breakpoints[("ntdll.dll", "ZwCreateUserProcess")] = None
            bp_funcs[("ntdll.dll", "ZwCreateUserProcess")] = (
                ntcreateprocess, True)

        # Add breakpoint if necessary
        for (mod, fun) in breakpoints:
            if breakpoints[(mod, fun)] is None:
                f_callback = bp_funcs[(mod, fun)][0]
                update_vads = bp_funcs[(mod, fun)][1]
                callback = functools.partial(
                    f_callback, cm=cm, proc=proc, update_vads=update_vads)
                bp = api.BP(str("%s!%s" % (mod, fun)), pgd, func = callback, new_style = True)
                bp.enable()
                interproc_breakpoints.append(bp)
                breakpoints[(mod, fun)] = (bp, bp.get_addr()) 
                pp_print("Adding breakpoint at %s:%s %x:%x from process with PID %x\n" %
                              (mod, fun, bp.get_addr(), pgd, pid))


def module_loaded(proc, params):
    '''
        LOADMODULE_CB, for every created process
    '''
    pid = params["pid"]
    pgd = params["pgd"]
    base = params["base"]
    size = params["size"]
    name = params["name"]
    fullname = params["fullname"]

    add_module(proc, name, base, size)

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
    interproc_data.procs.append(proc)

    # add_module, for every module loaded so far for this process
    try:
        for mod in api.get_module_list(pgd):
            add_module(proc, mod["name"], mod["base"], mod["size"])
        # Callback for each module loaded
        cm.add_callback(CallbackManager.LOADMODULE_CB, 
                        functools.partial(module_loaded, proc), 
                        pgd = pgd, 
                        name = ("load_module_%x" % pgd))
    except ValueError:
        # Could happen that the process is still not on the list of
        # created processes
        pp_debug("Process still not in the list of created processes, setting CB on TLB exec.")
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
        f = open(os.environ["MW_MONITOR2_CONF_PATH"], "r")
        conf = json.load(f)
        f.close()
        if "interproc" in conf:
            interproc_config.interproc_bin_log = conf["interproc"].get("bin_log", False)
            interproc_config.interproc_text_log = conf["interproc"].get("text_log", False)
            interproc_config.interproc_basic_stats = conf["interproc"].get("basic_stats", False)
            interproc_config.interproc_text_log_name = conf["interproc"].get("text_log_path", "interproc.log")
            interproc_config.interproc_basic_stats_name = conf["interproc"].get("basic_stats_path", "basic_stats")
            interproc_config.interproc_bin_log_name = conf["interproc"].get("bin_log_path", "interproc.bin")
        else:
            interproc_config.interproc_bin_log = False
            interproc_config.interproc_text_log = False
            interproc_config.interproc_basic_stats = False
            interproc_config.interproc_text_log_name = "interproc.log"
            interproc_config.interproc_basic_stats_name = "basic_stats"
            interproc_config.interproc_bin_log_name = "interproc.bin"

        
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
