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
# Printer
pyrebox_print = None


if __name__ == "__main__":
    # This message will be displayed when the script is loaded in memory
    print("[*] Loading python module %s" % (__file__))


def initialize_callbacks(module_hdl, printer):
    '''
    Initilize callbacks for this module.
    '''
    global cm
    global pyrebox_print
    # Initialize printer function
    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    # Initialize the callback manager
    cm = CallbackManager(module_hdl)

    # TODO: Register some callback

    pyrebox_print("[*]    Initialized callbacks")


def clean():
    '''
    Clean up everything.
    '''
    global cm
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")

# def do_my_command(line):
#     ''' Short description of the custom command.
#
#         Long description of the custom command
#     '''
#     global pyrebox_print
#     global cm
#     # TODO: Implement some functionality
