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
#                                PyREBox AutoRun 
#                                ===============
#
#   USAGE:  Configure the following environment variables.
#               AUTORUN_CONF_PATH = ...
#
#           Where the configuration file must be a json file with, at least, 
#           the following fields:
#
#               container_path: "" (Path of the tar.gz file containing the 
#                                   files to copy to the VM.)
#
#               main_executable_file: "" (Name of the main executable file.)
#
#               extract_path: "" (Path where we want the files to be 
#                                 extracted on the VM.)
#
#               temp_path: "" (Temporary path where we can extract the tar.gz 
#                              before copying it to the VM.)
#
#               preserve_filenames: ""
#
# -------------------------------------------------------------------------------


import os
import shutil
import json
import tarfile
import tempfile
import functools

# Determine TARGET_LONG_SIZE
from api import get_os_bits
TARGET_LONG_SIZE = get_os_bits() / 8

# Script requirements
requirements = ["plugins.guest_agent"]

# Global variables
# Callback manager
cm = None
# Printer
pyrebox_print = None
# Target process name
target_procname = None
target_pgd = None
# Breakpoint for entry point
entry_point_bp = None

autorun_module_handle = None

create_proc_callbacks = []
load_module_callbacks = []
entry_point_callbacks = []

def unload_all_modules():
    '''
        Unload all modules except this one
    '''
    from api import get_loaded_modules
    from api import unload_module
    global autorun_module_handle
    for d in get_loaded_modules():
        module_name = d["module_name"]
        module_handle = d["module_handle"]
        is_loaded = d["is_loaded"]
        if module_handle != autorun_module_handle: 
            unload_module(module_handle)
    pyrebox_print("All modules unloaded")

def register_autorun_create_proc_callback(callback):
    ''' Internal callback for modules 
        that import this module.
    '''
    global create_proc_callbacks
    create_proc_callbacks.append(callback)

def register_autorun_load_module_callback(callback):
    ''' Internal callback for modules 
        that import this module.
    '''
    global load_module_callbacks
    load_module_callbacks.append(callback)

def register_autorun_entry_point_callback(callback):
    ''' Internal callback for modules 
        that import this module.
    '''
    global entry_point_callbacks
    entry_point_callbacks.append(callback)

def remove_autorun_create_proc_callback(callback):
    ''' Internal callback for modules 
        that import this module.
    '''
    global create_proc_callbacks
    if callback in create_proc_callbacks:
        create_proc_callbacks.remove(callback)
    else:
        pyrebox_print("Could not remove callback %s from create_proc_callbacks: Not in list" % str(callback))

def remove_autorun_load_module_callback(callback):
    ''' Internal callback for modules 
        that import this module.
    '''
    global load_module_callbacks
    if callback in load_module_callbacks:
        load_module_callbacks.remove(callback)
    else:
        pyrebox_print("Could not remove callback %s from load_module_callbacks: Not in list" % str(callback))

def remove_autorun_entry_point_callback(callback):
    ''' Internal callback for modules 
        that import this module.
    '''
    global entry_point_callbacks
    if callback in entry_point_callbacks:
        entry_point_callbacks.remove(callback)
    else:
        pyrebox_print("Could not remove callback %s from entry_point_callbacks: Not in list" % str(callback))

def module_entry_point(params):
    '''
        Callback on the entry point of the main module being monitored
    '''
    global cm
    global entry_point_bp
    from api import CallbackManager
    import api

    # Get pameters
    cpu_index = params["cpu_index"]
    cpu = params["cpu"]

    # Disable the entrypoint
    entry_point_bp.disable()

    # Get running process
    pgd = api.get_running_process(cpu_index)

    # Start monitoring process
    api.start_monitoring_process(pgd)

    pyrebox_print("Started monitoring process")

    # Call all our internal callbacks
    for cb in entry_point_callbacks:
        cb(params)


def load_module(params):
    '''
        Callback trigger for every module loaded.
    '''
    global cm
    global pyrebox_print
    global entry_point_bp
    global target_pgd
    global target_procname
    import pefile
    import api
    from api import BP

    pid = params["pid"]
    pgd = params["pgd"]
    base = params["base"]
    size = params["size"]
    name = params["name"]
    fullname = params["fullname"]

    if pgd == target_pgd and target_procname.lower().startswith(name.lower()):
        cm.rm_callback("load_module")
        # Set a breakpoint on the EP, that will start a shell
        entry_point_bp = BP(base, pgd, size = size, new_style = True, func = module_entry_point)
        entry_point_bp.enable()
        # Call all our internal callbacks
        for cb in load_module_callbacks:
            cb(params)


def new_proc(params):
    '''
        Callback for new process creation.
    '''
    global cm
    global target_procname
    global target_pgd
    global pyrebox_print
    from api import CallbackManager
    import api

    # Get parameters
    pid = params["pid"]
    pgd = params["pgd"]
    name = params["name"]

    # Log process creation
    pyrebox_print("Created process %s - PID: %016x - PGD: %016x" % (name, pid, pgd))

    # Add module load callback
    if target_procname is not None and target_procname in name.lower():
        # Set target PGD
        target_pgd = pgd
        pyrebox_print("Adding module load callback on PGD %x" % pgd)
        cm.add_callback(CallbackManager.LOADMODULE_CB, load_module, pgd = pgd, name="load_module")
        pyrebox_print("Removing create process callback")
        cm.rm_callback("vmi_new_proc")
        # Call all our internal callbacks
        for cb in create_proc_callbacks:
            cb(params)


def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    global pyrebox_print
    pyrebox_print("[*]    Cleaning module")
    if cm is not None:
        cm.clean()
    unload_all_modules()
    pyrebox_print("[*]    Cleaned module")

def files_copied_callback(directories_to_remove):
    '''
    Remove the directories containing the temporary
    files.
    '''
    for d in directories_to_remove:
        pyrebox_print("Deleting temporary directory: %s" % d)
        shutil.rmtree(d)

def initialize_callbacks(module_hdl, printer):
    '''
    Initialize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    from api import CallbackManager
    from plugins.guest_agent import guest_agent

    global cm
    global pyrebox_print
    global target_procname
    global autorun_module_handle

    autorun_module_handle = module_hdl

    pyrebox_print = printer

    pyrebox_print("[*]    Reading configuration file")
    #Read AutoRun configuration file (json)
    f = open(os.environ["AUTORUN_CONF_PATH"], "r")
    conf = json.load(f)
    f.close()
    kws = ["container_path", "main_executable_file", "extract_path", "temp_path", "preserve_filenames"]
    for k in kws:
        if k not in conf:
            pyrebox_print("The configuration file does not contain the necessary keywords")
            return

    # Initialize process creation callback
    pyrebox_print("[*]    Initializing callbacks")
    cm = CallbackManager(module_hdl, new_style = True)
    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="vmi_new_proc")
    pyrebox_print("[*]    Initialized callbacks")

    # Copy target file to guest, and execute it
    pyrebox_print("Copying host file to guest, using agent...")

    temp_dnames = []
    if "container_path" in conf and tarfile.is_tarfile(conf["container_path"]):
        # For each file in the tar file, extract to a temporary file,
        # and copy to the VM with the appropriate file name.
        extracted_files = {}
        tar = tarfile.open(conf["container_path"], "r:gz")
        # Get file names inside the tar file
        for tarinfo in tar:
            extracted_files[tarinfo.name] = None

        # Extract each file into a temporary file
        for fname in list(extracted_files.keys()):
            temp_dname = tempfile.mkdtemp(dir=conf["temp_path"])
            temp_dnames.append(temp_dname)
            tar.extract(fname, path=temp_dname)
            extracted_files[fname] = os.path.join(temp_dname, fname)

        tar.close()
        
        # Copy files to the VM
        for fname, temp_fname in extracted_files.items():
            # Copy the specified file to C:\\temp.exe in the guest
            if conf["preserve_filenames"]:
                guest_agent.copy_file(temp_fname, conf["extract_path"] + fname)
            else:
                guest_agent.copy_file(temp_fname, conf["extract_path"] + "file.exe")
                conf["main_executable_file"] = "file.exe"

    # Execute the file. We set a callback to signal this script that 
    # the files have already been copied and can be deleted
    f = functools.partial(files_copied_callback, temp_dnames)
    guest_agent.execute_file(conf["extract_path"] + conf["main_executable_file"], callback = f)
    # stop_agent() does not only kill the agent, but it also
    # disables the agent plugin. Invalid opcodes
    # are not treated as agent commands any more, so this call
    # improves transparency.
    guest_agent.stop_agent()

    # Set target proc name:
    target_procname = conf["main_executable_file"]
    pyrebox_print("Waiting for process %s to start\n" % target_procname)
    pyrebox_print("Module loaded: %d" % module_hdl)

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
