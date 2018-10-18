# -------------------------------------------------------------------------
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
# -------------------------------------------------------------------------

#!/usr/bin/python
import bisect
import functools
import struct
import traceback

from interproc import interproc_data
from interproc import interproc_config

# Memory protection constants (virtualprotect)
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08

# TODO: Replace, put this on the rest of individual modules
class MwMonitor():
    '''
    Class that holds all the main structures to monitor the execution of the sample
    '''
    def __init__(self):
        # Callback manager
        self.cm = None
        # Plugin printer
        self.printer = None
        # API doc database
        self.db = None
        # BP counter used to hook API call returns
        self.bp_counter = 0

        # Output bundle name
        self.output_bundle_name = None

        # Module activation status
        self.api_tracer = False
        self.interproc = False
        self.coverage = False
        self.dumper = False
        self.api_tracer_text_log = False
        self.api_tracer_bin_log = False

        self.api_tracer_text_log_name = "function_calls.log"
        self.api_tracer_bin_log_name = "function_calls.bin"
        self.api_tracer_procs = None

        self.coverage_log_name = "coverage.bin"
        self.coverage_procs = None

        self.dumper_onexit = True
        self.dumper_dumpat = None
        self.dumper_path = "./"

        # List of API calls to trace
        self.include_apis = None
        self.exclude_apis = None
        self.exclude_modules = None
        self.include_apis_addrs = None
        self.exclude_apis_addrs = None
        self.exclude_modules_addrs = None
        self.exclude_origin_modules = None
        self.exclude_origin_modules_addrs = None

        # data
        self.data = InterprocData()

# ======================================     CLASSES       ===============


class VADRegion(object):
    '''
    VAD container
    '''
    PAGE_SIZE = 0x1000

    def __init__(self, start, size, proc, mapped_file, tag, vad_type, private, protection):
        self.start = start
        self.size = size
        # flags
        self.vad_type = vad_type
        self.private = private
        self.protection = protection
        # Proc to which the VAD is associated
        self.proc = proc
        # Mapped file and tag
        self.mapped_file = mapped_file
        self.tag = tag

        # Map for page permissions
        self.permissions = []

        initial_page_prot = 0

        self.page_permission_modified = False

        # Initialize page permissions for all the pages.
        if 'PAGE_NOACCESS' in protection:
            initial_page_prot = PAGE_NOACCESS
        elif 'PAGE_READONLY' in protection:
            initial_page_prot = PAGE_READONLY
        elif 'PAGE_EXECUTE' in protection:
            initial_page_prot = PAGE_EXECUTE
        elif 'PAGE_EXECUTE_READ' in protection:
            initial_page_prot = PAGE_EXECUTE_READ
        elif 'PAGE_READWRITE' in protection:
            initial_page_prot = PAGE_READWRITE
        elif 'PAGE_WRITECOPY' in protection:
            initial_page_prot = PAGE_WRITECOPY
        elif 'PAGE_EXECUTE_READWRITE' in protection:
            initial_page_prot = PAGE_EXECUTE_READWRITE
        elif 'PAGE_EXECUTE_WRITECOPY' in protection:
            initial_page_prot = PAGE_EXECUTE_WRITECOPY
        else:
            initial_page_prot = 0

        nb_pages = self.size / VADRegion.PAGE_SIZE
        for i in range(0, nb_pages):
            self.permissions.append(initial_page_prot)

        self.potentially_injected = False

        # Taken from volatility, (vadinfo plugin).
        # Identify VAD Regions potentially created to hold shellcode.
        write_exec = "EXECUTE" in protection and "WRITE" in protection
        if write_exec and self.private is True and self.tag == "VadS":
            self.potentially_injected = True
        if write_exec and (self.private is True and protection != "PAGE_EXECUTE_WRITECOPY"):
            self.potentially_injected = True

    def update_page_access(self, base_addr, size, new_access):
        '''
            Updates the page access permissions.
        '''
        offset = (base_addr - self.start) / VADRegion.PAGE_SIZE
        nb_pages = (size / VADRegion.PAGE_SIZE) if (size %
                                                    VADRegion.PAGE_SIZE == 0) else ((size / VADRegion.PAGE_SIZE) + 1)
        for i in range(offset, offset + nb_pages):
            # Check we do not access the list out of its boundaries
            if i < 0 or i >= len(self.permissions):
                break
            if self.permissions[i] != new_access:
                self.page_permission_modified = True
            self.permissions[i] = new_access

    def __eq__(self, other):
        return (self.start == other.start and self.size == other.size)

    def __lt__(self, other):
        return (self.start < other.start)

    def __le__(self, other):
        return (self.start <= other.start)

    def __gt__(self, other):
        return (self.start > other.start)

    def __ge__(self, other):
        return (self.start >= other.start)

    def __len__(self):
        return self.size

    def __str__(self):
        res = ""
        try:
            res = "[%s][%s][%s][%s] %08x(%08x) - %s - %s" % (self.vad_type,
                                                             "P" if self.private else " ",
                                                             "I" if self.potentially_injected else " ",
                                                             "M" if self.page_permission_modified else " ",
                                                             self.start,
                                                             self.size,
                                                             self.protection,
                                                             "" if self.mapped_file is None else self.mapped_file)
        except Exception:
            traceback.print_exc()
        return res

    def __hash__(self):
        return hash(tuple(self))

class Process:
    proc_counter = 0

    def __init__(self, proc_name):
        import api
        self.TARGET_LONG_SIZE = api.get_os_bits() / 8
        self.proc_num = Process.proc_counter
        Process.proc_counter += 1
        self.proc_name = proc_name
        self.pgd = 0
        self.pid = 0
        self.modules = {}

        # Record of API calls (related to VADs, and others
        self.vads = []
        # Chunks of memory injected to other processes
        self.injections = []
        self.file_operations = []
        self.section_maps = []

        # Indicates that this instance is a result of unpicking a serialized
        # object
        self.unpickled = False

        # Exited. Indicates that process has already exited.
        self.exited = False


    def set_pgd(self, pgd):
        self.pgd = pgd

    def set_pid(self, pid):
        self.pid = pid

    def set_name(self, name):
        self.proc_name = name

    def get_pgd(self):
        return self.pgd

    def get_pid(self):
        return self.pid

    def has_exited(self):
        return self.exited

    def set_exited(self):
        self.exited = True

    def get_proc_name(self):
        return self.proc_name

    def __str__(self):
        return "%x" % self.pid

    def set_module(self, name, base, size):
        if name not in self.modules:
            self.modules[name] = [(base, size)]
        elif (base, size) not in self.modules[name]:
            self.modules[name].append((base, size))

    def get_overlapping_vad(self, addr):
        '''
        Get the VAD overlapping the address
        '''
        for vad in self.vads:
            if vad.start <= addr and (vad.start + vad.size) > addr:
                return vad
        return None

    def add_injection(self, inj):
        self.injections.append(inj)

    def update_from_peb(self):
        '''
        Update several variables based on info extracted from peb
        '''
        import volatility.win32.tasks as tasks
        from utils import get_addr_space

        addr_space = get_addr_space(self.get_pgd())

        eprocs = [t for t in tasks.pslist(
            addr_space) if t.UniqueProcessId == self.pid]
        if len(eprocs) != 1:
            self.commandline = None
            self.current_directory = None
            self.image_path = None
        else:
            task = eprocs[0]
            self.commandline = str(
                task.Peb.ProcessParameters.CommandLine or '')
            self.current_directory = str(
                task.Peb.ProcessParameters.CurrentDirectory.DosPath or '')
            self.image_path = str(
                task.Peb.ProcessParameters.ImagePathName or '')

    def update_vads(self):
        '''
        Call volatility to obtain VADS.
        '''
        if self.unpickled:
            return
        import volatility.obj as obj
        import volatility.win32.tasks as tasks
        import volatility.plugins.vadinfo as vadinfo
        from utils import get_addr_space

        addr_space = get_addr_space(self.get_pgd())

        eprocs = [t for t in tasks.pslist(
            addr_space) if t.UniqueProcessId == self.pid]
        for task in eprocs:
            heaps = task.Peb.ProcessHeaps.dereference()
            modules = [mod.DllBase for mod in task.get_load_modules()]
            stacks = []
            for thread in task.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
                teb = obj.Object("_TEB",
                                 offset=thread.Tcb.Teb,
                                 vm=task.get_process_address_space())
                if teb:
                    stacks.append(teb.NtTib.StackBase)
            for vad in task.VadRoot.traverse():
                if vad is not None:
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

                    try:
                        protection = vadinfo.PROTECT_FLAGS.get(
                            vad.VadFlags.Protection.v(), "")
                    except Exception:
                        traceback.print_exc()

                    fileNameWithDevice = ""
                    try:
                        control_area = vad.ControlArea
                        # even if the ControlArea is not NULL, it is only meaningful
                        # for shared (non private) memory sections.
                        if vad.VadFlags.PrivateMemory != 1 and control_area:
                            if control_area:
                                file_object = vad.FileObject
                                if file_object:
                                    fileNameWithDevice = file_object.file_name_with_device(
                                    )
                    except AttributeError:
                        pass

                    try:
                        new_vad = VADRegion(vad.Start, (vad.End - vad.Start), self, fileNameWithDevice, str(
                            vad.Tag), vad_type, (vad.VadFlags.PrivateMemory == 1), protection)
                    except Exception:
                        traceback.print_exc()

                    if new_vad not in self.vads:
                        self.vads.append(new_vad)

    def __getstate__(self):
        '''
            Returns objects to be pickled.
        '''
        return (self.proc_num,
                self.proc_name,
                self.pgd,
                self.pid,
                self.modules,
                #self.min_mod_addr,
                #self.max_mod_addr,
                #self.symbols,
                self.vads,
                #self.other_calls,
                self.injections,
                self.file_operations,
                self.section_maps)

    def __setstate__(self, state):
        '''
            Sets pickled objects when unpickling
        '''
        (self.proc_num,
         self.proc_name,
         self.pgd,
         self.pid,
         self.modules,
         #self.min_mod_addr,
         #self.max_mod_addr,
         #self.symbols,
         self.vads,
         #self.other_calls,
         self.injections,
         self.file_operations,
         self.section_maps) = state

        self.unpickled = True

    def print_stats(self, file_name):
        '''
            Prints some basic statistics about processes.
        '''
        self.update_from_peb()

        f = open("%s_%x" % (file_name, self.pid), "w")

        f.write("BASIC INFORMATION\n")
        f.write("=================\n\n")

        f.write("Process name: %s\n" % self.proc_name)
        f.write("CR3: %x\n" % self.pgd)
        f.write("PID: %x\n" % self.pid)
        f.write("Nb of modules: %d\n" % len(self.modules))
        f.write("Commandline: %s\n" % self.commandline)
        f.write("Current directory: %s\n" % self.current_directory)
        f.write("Image path: %s\n" % self.image_path)
        f.write("Target long size: %d\n" % self.TARGET_LONG_SIZE)

        f.write("\nMODULE LIST\n")
        f.write("===========\n\n")

        vads = self.vads
        #syms = self.symbols
        included_vads = []
        for mod in self.modules:
            f.write("\n%s\n" % mod)
            f.write(("-" * len(mod)) + "\n")
            mod_vads = []
            #mod_syms = []
            for addr_s in self.modules[mod]:
                if self.TARGET_LONG_SIZE == 4:
                    f.write("0x%08x - %08x\n" % addr_s)
                elif self.TARGET_LONG_SIZE == 8:
                    f.write("0x%016x - %016x\n" % addr_s)
                mod_vads.extend(
                    filter(lambda x: x.start >= addr_s[0] and (x.start < (addr_s[0] + addr_s[1])), vads))
                #mod_syms.extend(
                #    filter(lambda x: x.addr >= addr_s[0] and (x.addr < (addr_s[0] + addr_s[1])), syms))
            for v in mod_vads:
                f.write("    %s\n" % (str(v)))
                included_vads.append(v)
            #f.write("    Nb of symbols: %d\n" % len(mod_syms))

        f.write("\nOTHER VADS\n")
        f.write("===========\n\n")

        for v in vads:
            if v not in included_vads:
                f.write("    %s\n" % (str(v)))

        f.write("\nINJECTIONS\n")
        f.write("==========\n\n")

        f.write("Nb of injections: %d\n\n" % (len(self.injections)))

        for inj in self.injections:
            f.write(str(inj) + "\n")

        f.write("\nFILE OPERATIONS\n")
        f.write("===============\n\n")

        f.write("Nb of file operations: %d\n\n" % (len(self.file_operations)))

        for op in self.file_operations:
            f.write(str(op) + "\n")

        f.write("\nSECTION MAPS\n")
        f.write("============\n\n")

        f.write("Nb of section maps: %d\n\n" % (len(self.section_maps)))

        for smap in self.section_maps:
            if self.TARGET_LONG_SIZE == 4:
                out_str = "%08x(%08x)" % (smap.base, smap.size)
            elif self.TARGET_LONG_SIZE == 8:
                out_str = "%16x(%16x)" % (smap.base, smap.size)

            if smap.section.backing_file is not None:
                out_str += " %s" % (str(smap.section.backing_file))
            out_str += "\n"
            f.write(out_str)
        f.close()


class Injection:

    def __init__(self, remote_proc, remote_addr, local_proc, local_addr, size, data, reverse):
        self.remote_proc = remote_proc
        self.local_proc = local_proc
        self.remote_addr = remote_addr
        self.local_addr = local_addr
        self.size = size
        self.data = data
        self.reverse = reverse

    def __str__(self):
        return "Remote injection: PID %x - %x -> PID %x - %x (%x)" % (self.local_proc.pid,
                                                                      self.local_addr,
                                                                      self.remote_proc.pid,
                                                                      self.remote_addr,
                                                                      self.size)

class FileOperation(object):

    def __init__(self, file_inst, proc, offset, size, data):
        self.file_inst = file_inst
        self.proc = proc
        self.offset = offset
        self.size = size
        self.data = data

    def __str__(self):
        return "%s:%s - %08x(%08x bytes)" % (str(self.proc), str(self.file_inst), self.offset, self.size)


class FileRead(FileOperation, object):

    def __init__(self, file_inst, proc, offset, size, data):
        super(FileRead, self).__init__(file_inst, proc, offset, size, data)

    def __str__(self):
        res = "File Read: %s" % super(FileRead, self).__str__()
        return res


class FileWrite(FileOperation, object):

    def __init__(self, file_inst, proc, offset, size, data):
        super(FileWrite, self).__init__(file_inst, proc, offset, size, data)

    def __str__(self):
        res = "File Write: %s" % super(FileWrite, self).__str__()
        return res


class File:

    def __init__(self, file_name):
        self.file_name = file_name
        self.file_operations = []

    def add_operation(self, op):
        self.file_operations.append(op)

    def __str__(self):
        return self.file_name


class Section:

    def __init__(self, pgd, section_object):
        import api
        global interproc_data

        TARGET_LONG_SIZE = api.get_os_bits() / 8

        # Volatility object representing the section
        self.section_object = section_object

        # Volatility lacks the vtype for _SECTION, which
        # has scarce documentation:

        # http://forum.sysinternals.com/section-object_topic24975.html

        #   These structures seem to remain consistent
        #   across different Windows versions.

        #   typedef struct _MMADDRESS_NODE {
        #   union {
        #       LONG_PTR Balance : 2;
        #       struct _MMADDRESS_NODE *Parent;
        #   } u1;
        #   struct _MMADDRESS_NODE *LeftChild;
        #   struct _MMADDRESS_NODE *RightChild;
        #   ULONG_PTR StartingVpn;
        #   ULONG_PTR EndingVpn;
        #   } MMADDRESS_NODE, *PMMADDRESS_NODE;

        #   typedef struct _SECTION {
        #    MMADDRESS_NODE Address;
        #    PSEGMENT Segment;
        #    LARGE_INTEGER SizeOfSection;
        #    union {
        #     ULONG LongFlags;
        #     MMSECTION_FLAGS Flags;
        #    } u;
        #    MM_PROTECTION_MASK InitialPageProtection;
        #    } SECTION, *PSECTION;

        # As we can see, Volatility has instead a _SECTION_OBJECT
        # vtype, which, consistently across Windows versions,
        # has at the beginning of the structure, 5 pointers, just
        # like the MMADDRESS_NODE for _SECTION. Therefore, the Segment
        # field seems to be at the same offset on both structures:
        # _SECTION and _SECTION_OBJECT, both for 32 and 64 bits.

        # Flags are located after Segment (PSEGMENT) + LARGE_INTEGER (64 bits independently of arch)
        # --> The offset should be the size of 6 pointers + size of LARGE_INTEGER

        # Flags are always 4 bytes

        # Compute FileBacked and  CopyOnWrite
        try:
            self.flags = struct.unpack(
                "I", api.r_va(pgd, self.section_object.obj_offset + ((TARGET_LONG_SIZE * 6) + 8), 0x4))[0]
        except:
            self.flags = 0x00000000
            pp_print("Could not read flags in Section __init__\n")
        self.cow = ((self.flags & 0x00000800) != 0)
        self.file_backed = ((self.flags & 0x00000080) != 0)

        self.backing_file = None

        # If so, get corresponding file.
        if self.file_backed:
            # Dereference as _SEGMENT, that is different from _SEGMENT_OBJECT
            # This is because the volatility profile lacks the _SECTION object,
            # and instead has the _SECTION_OBJECT. Since the Segment field
            # of _SECTION and _SECTION_OBJECT are aligned, we can just dereference
            # that offset. Nevertheless, _SECTION_OBJECT has a _SEGMENT_OBJECT type
            # Segment, while _SECTION has a _SEGMENT type Segment...

            # http://forum.sysinternals.com/section-object_topic24975.html

            self.segment = self.section_object.Segment.dereference_as(
                "_SEGMENT")
            file_obj = self.segment.ControlArea.FilePointer


            from volatility.plugins.overlays.windows.windows import _FILE_OBJECT
            from volatility.obj import Pointer

            # on winxp file_obj is volatility.obj.Pointer with .target being _FILE_OBJECT
            if not (type(file_obj) is Pointer and type(file_obj.dereference()) is _FILE_OBJECT):
                from volatility.plugins.overlays.windows.windows import _EX_FAST_REF
                if type(file_obj) is _EX_FAST_REF:
                    # on newer volatility profiles, FilePointer is _EX_FAST_REF, needs deref
                    file_obj = file_obj.dereference_as("_FILE_OBJECT")
                else:
                    raise TypeError("The type for self.segment.ControlArea.FilePointer in Section" + \
                                    "class does not match _FILE_OBJECT or _EX_FAST_REF: %r (type %r)" % (file_obj, type(file_obj)))

            for fi in interproc_data.files:
                if fi.file_name == str(file_obj.FileName):
                    self.backing_file = fi
                    break

            # If we have still not recorded the file, add it to files record
            if self.backing_file is None:
                self.backing_file = File(str(file_obj.FileName))
                interproc_data.files.append(self.backing_file)
        
        self.unpickled = False
        self.offset = self.section_object.obj_offset

    def __getstate__(self):
        '''
            Returns objects to be pickled.
        '''
        return (self.flags, self.cow, self.file_backed, self.backing_file, self.offset)

    def __setstate__(self, state):
        '''
            Sets pickled objects when unpickling
        '''
        self.flags, self.cow, self.file_backed, self.backing_file, self.offset = state
        self.section_object = None
        self.unpickled = True

    def get_object(self):
        if self.unpickled:
            return None
        else:
            return self.section_object

    def get_offset(self):
        if self.unpickled:
            return self.offset
        else:
            return self.section_object.obj_offset

    def is_cow(self):
        return self.is_cow


class SectionMap:

    def __init__(self, section, base, size, section_offset):
        self.section = section
        self.base = base
        self.size = size
        self.section_offset = section_offset
        # This flag indicates if the map is still active (created and not yet unmapped).
        # When a map is unmapped, instead of deleting our record, we deactivate it to keep
        # a list of all the mapped memory.
        self.active = True

    def is_active(self):
        return self.active

    def deactivate(self):
        self.active = False
