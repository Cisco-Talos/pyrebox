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


def my_createproc(pid, pgd, name):
    global cm
    global pyrebox_print
    cm.set_trigger_var("createproc", "var1", pid)
    cm.set_trigger_var("createproc", "var2", pgd)
    cm.set_trigger_var("createproc", "var3", name)

    pyrebox_print("Printing list...\n")
    list_ = cm.get_trigger_var("createproc", "list0")
    for el in list_:
        pyrebox_print("%x - %x" % (el[0], el[1]))

    pyrebox_print("Created process %x with pgd %x and name %s" % (pid, pgd, name))


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
    cm.add_callback(CallbackManager.CREATEPROC_CB, my_createproc, name="createproc")
    cm.add_trigger("createproc", "triggers/trigger_getset_var_example.so")
    cm.set_trigger_var("createproc", "var1", 0)
    cm.set_trigger_var("createproc", "var2", 100)
    cm.set_trigger_var("createproc", "var3", "Hello world")
    pyrebox_print("[*]    Initialized callbacks")


if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
