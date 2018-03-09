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
from api import BP
from api import CallbackManager
from ipython_shell import start_shell


# Callback manager
cm = None
counter = 0
pyrebox_print = None
memwrite_breakpoint = None
target_procname = ""


def mem_write(cpu_index, addr, size, haddr, data):
    global cm
    global counter
    global memwrite_breakpoint
    pyrebox_print("Mem write at cpu %x, addr %x size %x\n" % (cpu_index, addr, size))
    counter += 1
    # Remove the callback after 5 writes
    if counter >= 5:
        pyrebox_print("Breakpoint hit 5 times, disabling breakpoint...\n")
        memwrite_breakpoint.disable()
        start_shell()


def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    pyrebox_print("[*]    Cleaning module\n")
    cm.clean()
    pyrebox_print("[*]    Cleaned module\n")


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


def new_proc(pid, pgd, name):
    '''
    Process creation callback. Receives 3 parameters:
        :param pid: The pid of the process
        :type pid: int
        :param pgd: The PGD of the process
        :type pgd: int
        :param name: The name of the process
        :type name: str
    '''
    global pyrebox_print
    global target_procname
    global cm
    global memwrite_breakpoint

    pyrebox_print("New process created! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))
    # For instance, we can start the shell whenever a process is created
    if target_procname != "" and target_procname.lower() in name.lower():
        pyrebox_print("Creating memory write callback for this process on user address space")
        memwrite_breakpoint = BP(0x0, pgd, size=0x80000000, typ=BP.MEM_WRITE, func=mem_write)
        memwrite_breakpoint.enable()


def initialize_callbacks(module_hdl, printer):
    '''
    Initilize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    global cm
    global pyrebox_print
    # Initialize printer function (global var), that we can use to print
    # text that is associated to our script
    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    # Initialize the callback manager, and register a couple of named
    # callbacks.
    cm = CallbackManager(module_hdl)
    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="vmi_new_proc")
    pyrebox_print("[*]    Initialized callbacks")


if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
