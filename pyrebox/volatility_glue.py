# -------------------------------------------------------------------------
#
#   Copyright (C) 2019 Cisco Talos Security Intelligence and Research Group
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
# -------------------------------------------------------------------------

import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli import text_renderer
from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, configuration
from volatility.framework.configuration import requirements
from typing import Any, Dict, List, Optional, Tuple, Union, Type
from volatility.framework import interfaces, constants
from volatility.framework.configuration import requirements
from volatility.plugins.windows import pslist

plugin_class = None
context = None
automagics = None
base_config_path= "plugins"
# Instance of the plugin
volatility_interface = None

class PyREBoxAccess(interfaces.plugins.PluginInterface):
    """Environment to directly interact with a memory image."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"])
        ]

    def run(self, additional_locals: Dict[str, Any] = None) -> interfaces.renderers.TreeGrid:
        """Runs the plugin.

        Returns:
            Return a TreeGrid but this is always empty since the point of this plugin is to run interactively
        """

        return renderers.TreeGrid([("Terminating", str)], None)


class PyREBoxAccessWindows(PyREBoxAccess):
    """Environment to directly interact with a windows memory image."""

    def __init__(self, *args, **kwargs):
        """ Constructor, pass arguments to parent """
        super(PyREBoxAccessWindows, self).__init__(*args, **kwargs)
        self.__layer_name = self.config["primary"]
        self.__symbol_table = self.config["nt_symbols"]
        self.__kernel_virtual_offset = self.context.layers[self.__layer_name].config['kernel_virtual_offset']

    @classmethod
    def get_requirements(cls):
        return (super().get_requirements() + [
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'pid', description = "Process ID", optional = True)
        ])

    def change_process(self, pid = None):
        """Change the current process and layer, based on a process ID"""
        processes = self.list_processes()
        for process in processes:
            if process.UniqueProcessId == pid:
                process_layer = process.add_process_layer()
                self.change_layer(process_layer)
                return
        print("No process with process ID {} found".format(pid))

    def list_processes(self):
        """Returns a list of EPROCESS objects from the primary layer"""
        # We always use the main kernel memory and associated symbols
        return list(pslist.PsList.list_processes(self.context, self.config['primary'], self.config['nt_symbols']))

    def get_kernel_module(self):
        return self.context.module(self.__symbol_table,
                              layer_name = self.__layer_name,
                              offset = self.__kernel_virtual_offset)

    @property
    def PsActiveProcessHeadAddr(self):
        ntkrnlmp = self.get_kernel_module()
        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        return ps_aph_offset

    @property
    def PsLoadedModuleListAddr(self):
        ntkrnlmp = self.get_kernel_module()
        ps_aph_offset = ntkrnlmp.get_symbol("PsLoadedModuleList").address
        return ps_aph_offset

    def get_type_size(self, the_type):
        return self.context.symbol_space.get_type(self.__symbol_table + constants.BANG + the_type).size

    def get_object_offset(self, obj):
        return obj.vol.offset

    def get_eprocess(self, addr):
        ntkrnlmp = self.get_kernel_module()
        eproc = ntkrnlmp.object(object_type = "_EPROCESS", offset = addr, absolute = True)
        if eproc.is_valid():
            return eproc
        else:
            return None

    def get_peb_from_eprocess(self, eproc):
        proc_layer_name = eproc.add_process_layer()
        proc_layer = self.context.layers[proc_layer_name]
        if not proc_layer.is_valid(eproc.Peb):
            result = None
        else:
            result = eproc.Peb
        self.context.layers.del_layer(proc_layer_name)
        return result

    def get_ldr_from_eprocess(self, eproc):
        proc_layer_name = eproc.add_process_layer()
        proc_layer = self.context.layers[proc_layer_name]
        if not proc_layer.is_valid(eproc.Peb):
            result = None
        elif not proc_layer.is_valid(eproc.Peb.Ldr):
            results = None
        else:
            result = eproc.Peb.Ldr
        self.context.layers.del_layer(proc_layer_name)
        return result

    def get_kernel_module_list(self):
        ntkrnlmp = self.get_kernel_module() 
        try:
            # use this type if its available (starting with windows 10)
            ldr_entry_type = ntkrnlmp.get_type("_KLDR_DATA_TABLE_ENTRY")
        except exceptions.SymbolError:
            ldr_entry_type = ntkrnlmp.get_type("_LDR_DATA_TABLE_ENTRY")

        type_name = ldr_entry_type.type_name.split(constants.BANG)[1]

        list_head = self.PsLoadedModuleListAddr
        list_entry = ntkrnlmp.object(object_type = "_LIST_ENTRY", offset = list_head)
        reloff = ldr_entry_type.relative_child_offset("InLoadOrderLinks")

        # Get the first LDR_MODULE
        module = ntkrnlmp.object(object_type = type_name, offset = list_entry.vol.offset - reloff, absolute = True)

        for mod in module.InLoadOrderLinks:
            yield mod

class PyREBoxAccessLinux(PyREBoxAccess):
    """Environment to directly interact with a linux memory image."""

    @classmethod
    def get_requirements(cls):
        return (super().get_requirements() + [
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'pid', description = "Process ID", optional = True)
        ])

    def change_task(self, pid = None):
        """Change the current process and layer, based on a process ID"""
        tasks = self.list_tasks()
        for task in tasks:
            if task.pid == pid:
                process_layer = task.add_process_layer()
                if process_layer is not None:
                    self.change_layer(process_layer)
                    return
                print("Layer for task ID {} could not be constructed".format(pid))
                return
        print("No task with task ID {} found".format(pid))

    def list_tasks(self):
        """Returns a list of task objects from the primary layer"""
        # We always use the main kernel memory and associated symbols
        return list(pslist.PsList.list_tasks(self.context, self.config['primary'], self.config['vmlinux']))


def initialize_volatility(plugin):
    global context
    global plugin_class
    global automagics

    plugin_class = plugin

    # First, check if we imported the correct volatility
    try:
        import volatility.framework.layers.pyrebox
    except Exception as e:
        print(e)
        raise ImportError("Imported wrong volatility version")

    volatility.framework.require_interface_version(1, 0, 0)
    # Set the PARALLELISM
    #constants.PARALLELISM = constants.Parallelism.Multiprocessing
    #constants.PARALLELISM = constants.Parallelism.Threading
    constants.PARALLELISM = constants.Parallelism.Off

    # Do the initialization
    ctx = contexts.Context()  # Construct a blank context
    failures = framework.import_files(volatility.plugins,
                                      True)  # Will not log as console's default level is WARNING

    automagics = automagic.available(ctx)
    # Initialize the list of plugins in case the plugin needs it 
    plugin_list = framework.list_plugins()

    single_location = "::PyREBox memory::" 
    ctx.config['automagic.LayerStacker.single_location'] = single_location

    automagics = automagic.choose_automagic(automagics, plugin_class)
    context = ctx

    return True

def volatility_scan_ps_active_process_head():
    '''
        Scans the memory image, locates PsActiveProcessList,
        creates the process, and saves it.
    '''
    global context
    global plugin_class
    global automagics
    global base_config_path
    global volatility_interface

    errors = automagic.run(automagics, context, plugin_class, base_config_path)

    if len(errors) > 0:
        return None
    else:
        volatility_interface = plugins.construct_plugin(ctx, automagics, plugin, base_config_path, None, None)
        return volatility_interface.PsActiveProcessHeadAddr

def get_volatility_interface():
    global volatility_interface
    return volatility_interface

def initialize_volatility_windows():
    return initialize_volatility(PyREBoxAccessWindows)

def initialize_volatility_linux():
    return initialize_volatility(PyREBoxAccessLinux)
