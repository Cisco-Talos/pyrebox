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
#               GENERIC_UNPACKER_CONF_PATH= // The path to the json config file
#
#           The json config file must contain the following values
#               unpacker_log_path=""
#               unpacker_dump_path=""  // The path is appended with _1, _2, _3... 
#                                      // for every layer number. Existing contents 
#                                      // are deleted.
#
#           This script uses the mw_monitor2/interproc module. See the module's 
#           documentation for additional information.
#           
#
# -------------------------------------------------------------------------------


import os
import json

# Determine TARGET_LONG_SIZE
from api import get_os_bits
TARGET_LONG_SIZE = get_os_bits() / 8

# Script requirements
requirements = ["mw_monitor2.generic_unpacker"]

# Global variables
# Callback manager
cm = None
# Printer
pyrebox_print = None

def memory_dump_callback(params):
    global pyrebox_print
    pgd = params["pgd"]
    page_status_w = params["page_status_w"]
    page_status_x = params["page_status_x"]
    dump_path = params["dump_path"]

    pyrebox_print("On memory dump callback...")


def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    from mw_monitor2.generic_unpacker import remove_memory_dump_callback

    global cm
    global pyrebox_print

    pyrebox_print("[*]    Cleaning module")
    remove_memory_dump_callback(memory_dump_callback)
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
    from mw_monitor2.generic_unpacker import register_memory_dump_callback

    global cm
    global pyrebox_print

    pyrebox_print = printer

    try:
        # Initialize process creation callback
        pyrebox_print("[*]    Initializing callbacks")
        # Add memory dump callback 
        register_memory_dump_callback(memory_dump_callback)
        cm = CallbackManager(module_hdl, new_style = True)
        pyrebox_print("[*]    Initialized callbacks")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
