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

# Callback manager
cm = None
pyrebox_print = None
counter = 0


def my_function(cpu_index, cpu, tb):
    global cm
    global counter
    import api
    pgd = api.get_running_process(cpu_index)
    pyrebox_print("Process %x hit the callback at %x\n" % (pgd, cpu.PC))
    counter = counter + 1
    if counter >= 100:
        api.stop_monitoring_process(pgd)
        pyrebox_print("Stopped monitoring process\n")
        cm.rm_callback("block_begin")
        pyrebox_print("Unregistered callback\n")


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


def initialize_callbacks(module_hdl, printer):
    '''
    Initilize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    global cm
    global pyrebox_print
    from api import CallbackManager
    # Initialize printer
    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks\n")
    cm = CallbackManager(module_hdl)
    cm.add_callback(CallbackManager.BLOCK_BEGIN_CB, my_function, name="block_begin")
    pyrebox_print("[*]    Initialized callbacks\n")
    pyrebox_print("[!]    In order to perform the test, start monitoring some process")


if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
