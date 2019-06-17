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

from __future__ import print_function
from api import CallbackManager
import os

# Just a class to hold VAD region attributes
# and an __str__ function implementation
class VADRegion(object):
    def __init__(self, start,
                       end,
                       file_name,
                       tag,
                       type,
                       private,
                       protection):
        self.start = start
        self.end = end
        self.file_name = file_name
        self.tag = tag
        self.type = type
        self.private = private
        self.protection = protection

    def __str__(self):
        return "[%s] [%016x - %016x] [%s][%s][%s] - %s" % (self.tag,
                                                       self.start,
                                                       self.end,
                                                       self.type,
                                                       "P" if self.private else " ",
                                                       self.protection + " " * max(0, 22 - len(self.protection)),
                                                       self.file_name)

def get_vads(pgd):
    '''
        Get list of VAD regions using volatility
    '''
    import volatility.obj as obj
    import volatility.win32.tasks as tasks
    import volatility.plugins.vadinfo as vadinfo
    from utils import get_addr_space

    # Get volatility address space using the function in utils
    addr_space = get_addr_space(pgd)

    # Get list of Task objects using volatility (EPROCESS executive objects)
    eprocs = [t for t in tasks.pslist(
        addr_space) if t.Pcb.DirectoryTableBase.v() == pgd]

    # Traverse the list of selected EPROCESSes
    for task in eprocs:
        # Get heap base for every process HEAP
        heaps = task.Peb.ProcessHeaps.dereference()

        # Get base for every DLL
        modules = [mod.DllBase for mod in task.get_load_modules()]

        # Get Stack base for every THREAD 
        stacks = []
        for thread in task.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
            teb = obj.Object("_TEB",
                             offset=thread.Tcb.Teb,
                             vm=task.get_process_address_space())
            if teb:
                stacks.append(teb.NtTib.StackBase)

        # Traverse VAD tree 
        for vad in task.VadRoot.traverse():
            if vad is not None:
                # Determine if the VAD is a HEAP, STACK, or MODULE
                vad_type = ""
                if vad.Start in heaps:
                    # Heaps
                    vad_type = "H"
                elif vad.Start in modules:
                    # Module
                    vad_type = "M"
                elif vad.Start in stacks:
                    # Stacks
                    vad_type = "S"
                else:
                    vad_type = "-"
                
                # Get protection flags
                try:
                    protection = vadinfo.PROTECT_FLAGS.get(
                        vad.VadFlags.Protection.v(), "")
                except Exception:
                    traceback.print_exc()

                # Get mapped file
                file_name = ""
                try:
                    control_area = vad.ControlArea
                    # even if the ControlArea is not NULL, it is only meaningful
                    # for shared (non private) memory sections.
                    if vad.VadFlags.PrivateMemory != 1 and control_area:
                        if control_area:
                            file_object = vad.FileObject
                            if file_object:
                                file_name = file_object.file_name_with_device()
                except AttributeError:
                    pass

                # Return VAD regions
                yield VADRegion(vad.Start,
                                vad.End,
                                file_name,
                                str(vad.Tag),
                                vad_type,
                                (vad.VadFlags.PrivateMemory == 1),
                                protection)
