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
from volatility.framework.objects import StructType
from volatility.framework.objects import Pointer 

class StructTypePyREBoxWrapper():
    def __init__(self, obj, context, layer_name):
        self._wrapped_obj = obj
        self._context = context
        self._layer_name = layer_name
    def __getattr__(self, attr):
        if attr in self.__dict__:
            return getattr(self, attr)
        return getattr(self._wrapped_obj, attr)
    def __del__(self):
        if self._layer_name is not None:
            self._context.layers.del_layer(self._layer_name)

class PointerPyREBoxWrapper():
    def __init__(self, obj, context, layer_name):
        self._wrapped_obj = obj
        self._context
        self._layer_name = layer_name
    def __getattr__(self, attr):
        if attr in self.__dict__:
            return getattr(self, attr)
        return getattr(self._wrapped_obj, attr)
    def __del__(self):
        if self._layer_name is not None:
            self._context.layers.del_layer(self._layer_name)


class PyREBoxAccessWindows(interfaces.plugins.PluginInterface):
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
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'pid', description = "Process ID", optional = True)
        ])

    def run(self, additional_locals: Dict[str, Any] = None) -> interfaces.renderers.TreeGrid:
        """Runs the plugin.

        Returns:
            Return a TreeGrid but this is always empty since the point of this plugin is to run interactively
        """

        return renderers.TreeGrid([("Terminating", str)], None)

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

    def get_kernel_module(self, use_layer_name = None):
        return self.context.module(self.__symbol_table,
                              layer_name = use_layer_name if use_layer_name is not None else self.__layer_name,
                              offset = self.__kernel_virtual_offset)

    @property
    def PsActiveProcessHeadAddr(self):
        ntkrnlmp = self.get_kernel_module()
        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        if ps_aph_offset != 0 and ps_aph_offset != 0xffffffff and ps_aph_offset != 0xffffffffffffffff:
            return self.__kernel_virtual_offset + ps_aph_offset
        else:
            return None

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
            result = (None, self.get_object_offset(eproc.Peb))
            self.context.layers.del_layer(proc_layer_name)
        else:
            ntkrnlmp = self.get_kernel_module(proc_layer_name)
            peb = StructTypePyREBoxWrapper(ntkrnlmp.object(object_type = "_PEB", offset = eproc.Peb, absolute = True),
                                           self.context, 
                                           proc_layer_name)
            result = (peb, self.get_object_offset(eproc.Peb))
        return result

    def get_ldr_from_eprocess(self, eproc, peb):
        proc_layer_name = eproc.add_process_layer()
        proc_layer = self.context.layers[proc_layer_name]
        # peb must be valid
        if not proc_layer.is_valid(peb.Ldr):
            result = (None, self.get_object_offset(peb.Ldr))
            self.context.layers.del_layer(proc_layer_name)
        else:
            result = (PointerPyREBoxWrapper(peb.Ldr, self.context, proc_layer_name), self.get_object_offset(peb.Ldr))
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

    def get_kuser_shared_data(self):
        ntkrnlmp = self.get_kernel_module()
        # this is a hard-coded address in the Windows OS
        if self.context.layers[self.__layer_name].bits_per_register == 32:
            kuser_addr = 0xFFDF0000
        else:
            kuser_addr = 0xFFFFF78000000000

        kuser = ntkrnlmp.object(object_type = "_KUSER_SHARED_DATA",
                                layer_name = self.__layer_name,
                                offset = kuser_addr,
                                absolute = True)
        return kuser

