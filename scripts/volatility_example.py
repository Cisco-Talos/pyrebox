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
from utils import get_addr_space
from api import CallbackManager

# Volatility imports that may be needed

# import volatility.conf as volconf
# import volatility.registry as registry
# import volatility.commands as commands
# import volatility.addrspace as addrspace
# import volatility.constants as constants
# import volatility.exceptions as exceptions
# import volatility.obj as obj
# import volatility.scan as scan
# import volatility.utils as utils

import volatility.win32.tasks as tasks

# Callback manager
cm = None
pyrebox_print = None


def new_proc(pid, pgd, name):
    global cm
    pyrebox_print("Process %x started with pgd: %x. Name: %s" % (pid, pgd, name))
    # Get the volatility address space, adjusted for our current pgd
    addr_space = get_addr_space(pgd)
    # Use the pslist function to retrieve the process list with volatility
    procs = [t for t in tasks.pslist(addr_space)]
    # Just print the process list
    for p in procs:
        pyrebox_print("Process %s PID:%x" % (p.ImageFileName, p.UniqueProcessId))


def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
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
    pyrebox_print("[*]    Initialized callbacks")


if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
