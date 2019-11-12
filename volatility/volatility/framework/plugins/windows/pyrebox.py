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
from volatility.framework.plugins.pyrebox_common import get_layer_from_task, get_layer_from_pgd


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

    def get_type(self, the_type):
        return self.context.symbol_space.get_type(self.__symbol_table + constants.BANG + the_type)

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
        proc_layer_name, proc_layer = get_layer_from_task(self, eproc)

        if not proc_layer.is_valid(eproc.Peb):
            result = (None, self.get_object_offset(eproc.Peb))
        else:
            ntkrnlmp = self.get_kernel_module(proc_layer_name)
            peb = ntkrnlmp.object(object_type = "_PEB", offset = eproc.Peb, absolute = True)
            result = (peb, self.get_object_offset(eproc.Peb))
        return result

    def get_ldr_from_eprocess(self, eproc, peb):
        proc_layer_name, proc_layer = get_layer_from_task(self, eproc)
        # peb must be valid
        if not proc_layer.is_valid(peb.Ldr):
            result = (None, self.get_object_offset(peb.Ldr))
        else:
            result = (peb.Ldr, self.get_object_offset(peb.Ldr))
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

    def get_pgd_from_task(self, task):
        dtb = 0
        if isinstance(task.Pcb.DirectoryTableBase, objects.Array):
            dtb = task.Pcb.DirectoryTableBase.cast("unsigned long long")
        else:
            dtb = task.Pcb.DirectoryTableBase
        dtb = dtb & ((1 << self.context.layers[self.__layer_name].bits_per_register) - 1)
        return dtb


    def get_task_from_pgd(self, pgd):
        processes = self.list_processes()
        for process in processes:
            dtb = self.get_pgd_from_task(process)
            if dtb == pgd:
                return process
        return None


    def get_control_area_and_subsection_from_vad(self, eproc, vad):
        '''
        Validates the ControlArea, and returns None if invalid
        '''
        proc_layer_name, proc_layer = get_layer_from_task(self, eproc)
        ca = None
        subsect = None

        if (vad.has_member("ControlArea")) and \
            vad.ControlArea and \
            proc_layer.is_valid(vad.ControlArea):
            ca = vad.ControlArea
            # Get offset of subsection, to validate the ControlArea
            try: 
                # Just try to dereference a field to make sure it doesnt
                # throw an exception
                number_subsections = ca.NumberOfSubsections 
                if vad.has_member("Subsection"):
                    # This is for vista through Win7 and onwards
                    subsect = vad.Subsection
                else:
                    # There is no Subsection pointer in VAD
                    # structure, so we just read after the ControlArea.
                    # Note: See Windows Internals Sixth Edition, Part 2, page 288 
                    offset = int(ca) + vad.get_symbol_table().get_type("_CONTROL_AREA").size
                    subsect = self.context.object(self.config["nt_symbols"] + constants.BANG  + "_SUBSECTION", 
                                                    proc_layer_name, offset)
                ca_bis = subsect.ControlArea
            except Exception as e: 
                return None

            if int(ca_bis) != int(ca):
                return None
        else:
            return None

        return (ca, subsect)


    def get_segment_from_vad(self, eproc, vad):
        proc_layer_name, proc_layer = get_layer_from_task(self, eproc)

        _res  = self.get_control_area_and_subsection_from_vad(eproc, vad)
        if _res:
            ctl, subsect = _res
        else:
            return None
        if ctl and ctl.has_member("Segment") and \
            ctl.Segment and proc_layer.is_valid(ctl.Segment):
            return ctl.Segment

        return None 

    def list_process_threads(self, eproc):
        """ List process threads """

        ntkrnlmp = self.get_kernel_module()

        if int(eproc.ThreadListHead.Flink) == 0:
            return []

        reloff = ntkrnlmp.get_type("_ETHREAD").relative_child_offset("ThreadListEntry")
        ethread = ntkrnlmp.object(object_type = "_ETHREAD", offset = eproc.ThreadListHead.Flink - reloff, absolute = True)

        for e in ethread.ThreadListEntry:
            yield e


    def get_kpcr(self, kpcr_addr):
        """ Given its adress, return a KPCR structure, check if it is valid """
        ntkrnlmp = self.get_kernel_module()
        kpcr = ntkrnlmp.object(object_type = "_KPCR", offset = kpcr_addr, absolute = True)
        if int(kpcr.SelfPcr) == kpcr.vol.offset:
            return kpcr
        else:
            return None

    def get_ktrap_frame_from_ethread(self, ethread_addr):
        """ Ethread address """
        ntkrnlmp = self.get_kernel_module()
        try:
            thread = ntkrnlmp.object(object_type = "_ETHREAD", offset = ethread_addr, absolute = True)
            trap_frame_addr = thread.Tcb.TrapFrame
            if trap_frame_addr == 0:
                return None
            trap = trap_frame_addr.dereference().cast("_KTRAP_FRAME")
            return trap
        except:
            return None



