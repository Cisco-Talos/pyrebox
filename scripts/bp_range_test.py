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
import api
from api import CallbackManager

# Callback manager
cm = None
pyrebox_print = None


def insn_begin(cpu_index, cpu):
    global cm
    global pyrebox_print
    if cpu.PC == 0x100218f and cm.callback_exists("insn_begin"):
        pgd = api.get_running_process(cpu_index)
        pyrebox_print("Process %x hit the callback at 0x100218f" % pgd)
        api.stop_monitoring_process(pgd)
        pyrebox_print("Stopped monitoring process")
        cm.rm_callback("insn_begin")
    else:
        print("This message should never be printed")


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
    cm.add_callback(CallbackManager.INSN_BEGIN_CB, insn_begin, name="insn_begin")
    # Add a trigger so that the callback is only triggered
    # for a certain range of addresses
    cm.add_trigger("insn_begin", "triggers/trigger_bp_memrange.so")
    cm.set_trigger_var("insn_begin", "begin", 0x100218f)
    cm.set_trigger_var("insn_begin", "end", 0x1002190)
    cm.set_trigger_var("insn_begin", "pgd", 0xFFFFFFFF)

    pyrebox_print("[*]    Initialized callbacks")


if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
