import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli import text_renderer
from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, configuration
from volatility.framework.configuration import requirements
from typing import Any, Dict, List, Optional, Tuple, Union, Type
from volatility.framework import interfaces, constants, objects
from volatility.framework.configuration import requirements
from volatility.plugins.linux import pslist
from volatility.framework.objects import StructType
from volatility.framework.objects import Pointer 
from volatility.framework.automagic import linux
from volatility.framework.layers import linear
from volatility.framework.plugins.pyrebox_common import get_layer_from_task, get_layer_from_pgd


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
        ])

    def run(self, additional_locals: Dict[str, Any] = None) -> interfaces.renderers.TreeGrid:
        """Runs the plugin.

        Returns:
            Return a TreeGrid but this is always empty since the point of this plugin is to run interactively
        """

        return renderers.TreeGrid([("Terminating", str)], None)

    def mask_symbol_table(self):
        linux.LinuxUtilities.aslr_mask_symbol_table(self.context, self.config['vmlinux'], self.config['primary'])

    def __init__(self, *args, **kwargs):
        """ Constructor, pass arguments to parent """

        super(PyREBoxAccessLinux, self).__init__(*args, **kwargs)
        self.__layer_name = self.config["primary"]
        self.__symbol_table = self.config["vmlinux"]
        vmlinux = self.get_kernel_module()
        self.mask_symbol_table()

    def get_type(self, the_type):
        return self.context.symbol_space.get_type(self.__symbol_table + constants.BANG + the_type)

    def get_type_size(self, the_type):
        return self.context.symbol_space.get_type(self.__symbol_table + constants.BANG + the_type).size

    def relative_child_offset(self, obj_name, field_name):
        t = self.get_type(obj_name)
        if t:
            if field_name in t.members:
                # First element in tuple is the offset, the second one is the type itself.
                return t.members[field_name][0]
        return None

    def get_kernel_module(self, use_layer_name = None):
        return self.context.module(self.__symbol_table,
                                   layer_name = use_layer_name if use_layer_name is not None else self.__layer_name,
                                   offset = 0)

    def get_layer_name(self):
        return self.__layer_name

    def get_symbol(self, sym):
        krnl = self.get_kernel_module()
        sym_obj = krnl.get_symbol(sym)
        if sym_obj:
            return sym_obj.address

        return None 

    def get_symbol_size(self, sym):
        krnl = self.get_kernel_module()
        sym_obj = krnl.get_symbol(sym)
        if sym_obj:
            return self.context.symbol_space.get_type(sym_obj.type_name).size

    def get_object_offset(self, obj):
        return obj.vol.offset

    def get_pgd_from_task(self, task):
        parent_layer = self.context.layers[self.__layer_name]
        try:
            pgd = task.mm.pgd
        except exceptions.InvalidAddressException:
            return None
       
        if not isinstance(parent_layer, linear.LinearlyMappedLayer):
            raise TypeError("Parent layer is not a translation layer, unable to construct layer")
         
        dtb, layer_name = parent_layer.translate(pgd)

        return dtb

    def list_processes(self):
        return pslist.PsList.list_tasks(self.context,
                    self.config['primary'],
                    self.config['vmlinux'])

    def list_kernel_modules(self):
        modules = self.get_kernel_module().object_from_symbol(symbol_name = "modules").cast("list_head")
        table_name = modules.vol.type_name.split(constants.BANG)[0]
        for module in modules.to_list(table_name + constants.BANG + "module", "list"):
           yield module

    def get_task_from_pgd(self, pgd):
        processes = self.list_processes()
        for process in processes:
            dtb = self.get_pgd_from_task(process)
            if dtb == pgd:
                # More than one task struct can have the same PGD
                yield process
        return None

    def get_elf(self, task, base):
        from volatility.framework.symbols.linux.elf import ElfIntermedSymbols
        elf_table_name = ElfIntermedSymbols.create(self.context, self.config_path, "linux", "elf")
        layer_name = get_layer_from_task(self, task)[0]
        try:
            return self.context.object(elf_table_name + "!" + "Elf", layer_name, base)
        except:
            return None

