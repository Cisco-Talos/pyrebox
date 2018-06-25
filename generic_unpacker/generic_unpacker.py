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
#               UNPACKER_LOG_PATH=
#               UNPACKER_DUMP_PATH=  // The path is appended with _1, _2, _3... 
#                                    // for every layer number. Existing contents 
#                                    // are deleted.
#               UNPACKER_FILE_PATH=
#
# -------------------------------------------------------------------------------


from __future__ import print_function
import os

# Determine TARGET_LONG_SIZE
from api import get_os_bits
TARGET_LONG_SIZE = get_os_bits() / 8

# Our helpers, that leverage volatility
from vads import VADRegion, get_vads
from memory_dump import dump

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

# Memory page status
page_status_w = {}
page_status_x = {}
# Global var for current layer status
current_layer = 0

def init_log():
    '''
        Initialize log (remove file if it exists)
    '''
    if os.path.isfile(os.environ["UNPACKER_LOG_PATH"]):
        os.remove(os.environ["UNPACKER_LOG_PATH"])


def append_log(line):
    '''
        Append line to log file, add line feed if necessary.
    '''
    f = open(os.environ["UNPACKER_LOG_PATH"], "a")
    if line[-1] != "\n":
        line += "\n"
    f.write(line)
    f.close()


def mem_write(params):
    '''
        Callback for memory writes.
    '''
    global cm
    global page_status
    global current_layer
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

    if not api.is_kernel_running(cpu_index):
        mask = 0xFFFFF000 if TARGET_LONG_SIZE == 4 else 0xFFFFFFFFFFFFF000
        page = vaddr & mask

        # Set page write status (update with current layer)
        page_status_w[page] = current_layer

        # Log the page write
        pc = cpu.RIP if isinstance(cpu, X64CPU) else cpu.EIP
        if TARGET_LONG_SIZE == 4:
            append_log("[W]  - PGD [%08x] - PAGE [%08x] - FROM [%08x]" % (pgd, page, pc))
        else:
            append_log("[W]  - PGD [%016x] - PAGE [%016x] - FROM [%016x]" % (pgd, page, pc))


def block_exec(params):
    '''
        Callback for memory execution.
    '''
    global cm
    global page_status
    global current_layer
    import api

    # Get parameters
    cpu_index = params["cpu_index"]
    cpu = params["cpu"]
    pc, size, icount = params["tb"]

    # Get running process
    pgd = api.get_running_process(cpu_index)

    mask = 0xFFFFF000 if TARGET_LONG_SIZE == 4 else 0xFFFFFFFFFFFFF000
    page = pc & mask

    if page in page_status_w:
        # Update page status, according to the layer
        # that wrote the page.
        page_status_x[page] = page_status_w[page] + 1

        if TARGET_LONG_SIZE == 4:
            append_log("[WX] - PGD [%08x] - PAGE [%08x] - EP   [%08x]" % (pgd, page, pc))
        else:
            append_log("[WX] - PGD [%016x] - PAGE [%016x] - EP   [%016x]" % (pgd, page, pc))

        # If we are jumping (for the first time), into a new layer:
        if page_status_x[page] > current_layer:
            # Report it on the log, and dump the list of VAD regions
            append_log("+----- LAYER %d -> LAYER %d" % (current_layer, page_status_x[page]))
            append_log("+----- VAD LIST")
            append_log("+----- ========")
            for vad in get_vads(pgd):
                append_log("+----- " + str(vad))

            # Update current layer
            current_layer = page_status_x[page]

            # Reset write cache on triggers
            cm.call_trigger_function("mem_write", "erase_vars")
            cm.call_trigger_function("block_begin", "erase_vars")

            #Create dump
            dump([pgd], path = os.path.join(os.environ["UNPACKER_DUMP_PATH"] + "_%d" % (current_layer)))
    else:
        # Update page status (execution)
        page_status_x[page] = current_layer 


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

    pyrebox_print("Started monitoring process")

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
        # Loaded main module, try to read EP
        ep = None
        try:
            pe_data = api.r_va(pgd, base, 0x1000)
            pe = pefile.PE(data=pe_data)
            ep = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except Exception as e:
            print(e)
            pyrebox_print("Could not read EP from module %s on load" % name)

        # If we have the EP, put a breakpoint there
        if ep is not None:
            pyrebox_print("The entry point for %s is 0x%x\n" % (target_procname, ep))

            cm.rm_callback("load_module")
            # Set a breakpoint on the EP, that will start a shell
            entry_point_bp = BP(ep, pgd, new_style = True, func = module_entry_point)
            entry_point_bp.enable()

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


def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    global pyrebox_print
    pyrebox_print("[*]    Cleaning module")
    cm.clean()
    pyrebox_print("[*]    Cleaned module")


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

    pyrebox_print = printer

    # Initialize log
    init_log()
    # Initialize process creation callback
    pyrebox_print("[*]    Initializing callbacks")
    cm = CallbackManager(module_hdl, new_style = True)
    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="vmi_new_proc")
    pyrebox_print("[*]    Initialized callbacks")

    # Copy target file to guest, and execute it
    pyrebox_print("Copying host file to guest, using agent...")

    # Copy the specified file to C:\\temp.exe in the guest
    guest_agent.copy_file(os.environ["UNPACKER_FILE_PATH"], "C:\\temp.exe")
    # Execute the file
    guest_agent.execute_file("C:\\temp.exe")
    # stop_agent() does not only kill the agent, but it also
    # disables the agent plugin. Invalid opcodes
    # are not treated as agent commands any more, so this call
    # improves transparency.
    guest_agent.stop_agent()

    # Set target proc name:
    target_procname = "temp.exe"
    pyrebox_print("Waiting for process %s to start\n" % target_procname)

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
