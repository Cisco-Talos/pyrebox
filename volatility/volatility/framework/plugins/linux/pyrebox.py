import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli import text_renderer
from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, configuration
from volatility.framework.configuration import requirements
from typing import Any, Dict, List, Optional, Tuple, Union, Type
from volatility.framework import interfaces, constants, objects
from volatility.framework.configuration import requirements
from volatility.plugins.windows import pslist
from volatility.framework.objects import StructType
from volatility.framework.objects import Pointer 

class PyREBoxAccessLinux(interfaces.plugins.PluginInterface):
    """Environment to directly interact with a linux memory image."""

    @classmethod
    def get_requirements(cls):
        return (super().get_requirements() + [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
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

