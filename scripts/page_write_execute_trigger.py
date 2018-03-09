# -------------------------------------------------------------------------------
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
# -------------------------------------------------------------------------------

from __future__ import print_function
from api import CallbackManager

# Callback manager
cm = None
pyrebox_print = None
target_procname = None
page_status = {}


def mem_write(cpu_index, vaddr, size, haddr, data):
    global cm
    global page_status
    import api
    if not api.is_kernel_running(cpu_index):
        page = vaddr & 0xFFFFF000
        page_status[page] = "w"


def block_exec(cpu_index, cpu, tb):
    global cm
    global page_status
    import api
    if not api.is_kernel_running(cpu_index):
        pc, size, icount = tb
        page = pc & 0xFFFFF000
        if page in page_status:
            if page_status[page] == "w":
                proc = api.get_running_process(cpu_index)
                pyrebox_print("Written & Executed page PID: %08x PAGE: %08x" % (proc, page))
        page_status[page] = "x"


def new_proc(pid, pgd, name):
    global cm
    global target_procname
    global pyrebox_print
    import api
    if target_procname is not None and target_procname in name.lower():
        pyrebox_print("Started monitoring process %s" % name)
        cm.add_trigger("mem_write", "triggers/trigger_memwrite_wx.so")
        cm.set_trigger_var("mem_write", "begin", 0x0)
        cm.set_trigger_var("mem_write", "end", 0x80000000)
        cm.set_trigger_var("mem_write", "pgd", pgd)

        cm.add_trigger("block_begin", "triggers/trigger_blockbegin_wx.so")
        cm.set_trigger_var("block_begin", "begin", 0x0)
        cm.set_trigger_var("block_begin", "end", 0x80000000)
        cm.set_trigger_var("block_begin", "pgd", pgd)

        api.start_monitoring_process(pgd)


def do_set_target(line):
    '''Set target process - Custom command

       Set a target process name. When a process with this name is created,
       the script will start monitoring context changes and retrieve
       the module entry point as soon as it is available in memory. Then
       it will place a breakpoint on the entry point.
    '''
    global pyrebox_print
    global target_procname
    target_procname = line.strip()
    pyrebox_print("Waiting for process %s to start\n" % target_procname)


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
    Initilize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    global cm
    global pyrebox_print
    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    cm = CallbackManager(module_hdl)
    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="vmi_new_proc")
    cm.add_callback(CallbackManager.MEM_WRITE_CB, mem_write, name="mem_write")
    cm.add_callback(CallbackManager.BLOCK_BEGIN_CB, block_exec, name="block_begin")
    pyrebox_print("[*]    Initialized callbacks")


if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
