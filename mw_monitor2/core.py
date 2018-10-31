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

# ======================================     CLASSES       ===============

class VADRegion(object):
    '''
    VAD container
    '''
    PAGE_SIZE = 0x1000

    def __init__(self, start, size, proc, mapped_file, tag, vad_type, private, protection):
        self.__start = start
        self.__size = size
        # flags
        self.__vad_type = vad_type
        self.__private = private
        self.__protection = protection
        # Proc to which the VAD is associated
        self.__proc = proc
        # Mapped file and tag
        self.__mapped_file = mapped_file
        self.__tag = tag

        # Map for page permissions
        self.__permissions = []

        # API calls from the VAD. Only populated by the api_tracer plugin
        self.__calls = []

        initial_page_prot = 0

        self.__page_permission_modified = False

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

        nb_pages = self.__size / VADRegion.PAGE_SIZE
        for i in range(0, nb_pages):
            self.__permissions.append(initial_page_prot)

        self.__potentially_injected = False

        # Taken from volatility, (vadinfo plugin).
        # Identify VAD Regions potentially created to hold shellcode.
        write_exec = "EXECUTE" in protection and "WRITE" in protection
        if write_exec and self.__private is True and self.__tag == "VadS":
            self.__potentially_injected = True
        if write_exec and (self.__private is True and protection != "PAGE_EXECUTE_WRITECOPY"):
            self.__potentially_injected = True

    def update_page_access(self, base_addr, size, new_access):
        '''
            Updates the page access permissions.
        '''
        offset = (base_addr - self.__start) / VADRegion.PAGE_SIZE
        nb_pages = (size / VADRegion.PAGE_SIZE) if (size %
                                                    VADRegion.PAGE_SIZE == 0) else ((size / VADRegion.PAGE_SIZE) + 1)
        for i in range(offset, offset + nb_pages):
            # Check we do not access the list out of its boundaries
            if i < 0 or i >= len(self.__permissions):
                break
            if self.__permissions[i] != new_access:
                self.__page_permission_modified = True
            self.__permissions[i] = new_access

    def get_start(self):
        return self.__start

    def get_size(self):
        return self.__size

    def get_vad_type(self):
        return self.__vad_type

    def get_private(self):
        return self.__private

    def get_protection(self):
        return self.__protection

    def get_proc(self):
        return self.__proc

    def get_mapped_file(self):
        return self.__mapped_file

    def get_tag(self):
        return self.__tag

    def get_permissions(self):
        return self.__permissions

    def get_page_permission_modified(self):
        return self.__page_permission_modified

    def get_potentially_injected(self):
        return self.__potentially_injected

    def get_calls(self):
        return self.__calls

    def add_call(self, call):
        self.__calls.append(call)

    def __eq__(self, other):
        return (self.__start == other.__start and self.__size == other.__size)

    def __lt__(self, other):
        return (self.__start < other.__start)

    def __le__(self, other):
        return (self.__start <= other.__start)

    def __gt__(self, other):
        return (self.__start > other.__start)

    def __ge__(self, other):
        return (self.__start >= other.__start)

    def __len__(self):
        return self.__size

    def __str__(self):
        res = ""
        try:
            res = "[%s][%s][%s][%s] %08x(%08x) - %s - %s" % (self.__vad_type,
                                                             "P" if self.__private else " ",
                                                             "I" if self.__potentially_injected else " ",
                                                             "M" if self.__page_permission_modified else " ",
                                                             self.__start,
                                                             self.__size,
                                                             self.__protection,
                                                             "" if self.__mapped_file is None else self.__mapped_file)
        except Exception:
            traceback.print_exc()
        return res

    def __hash__(self):
        return hash(tuple(self))

class Symbol:

    def __init__(self, mod, fun, addr):
        self.__mod = mod
        self.__fun = fun
        self.__addr = addr

    def get_mod(self):
        return self.__mod

    def get_fun(self):
        return self.__fun

    def get_addr(self):
        return self.__addr

    def __lt__(self, other):
        return self.__addr < other.get_addr()

    def __le__(self, other):
        return self.__addr <= other.get_addr()

    def __eq__(self, other):
        return self.__addr == other.get_addr()

    def __ne__(self, other):
        return self.__addr != other.get_addr()

    def __gt__(self, other):
        return self.__addr > other.get_addr()

    def __ge__(self, other):
        return self.__addr >= other.get_addr()


class Process:
    proc_counter = 0

    def __init__(self, proc_name):
        import api
        self.TARGET_LONG_SIZE = api.get_os_bits() / 8
        self.__proc_num = Process.proc_counter
        Process.proc_counter += 1
        self.__proc_name = proc_name
        self.__pgd = 0
        self.__pid = 0
        self.__modules = {}

        # Record of API calls (related to VADs, and others
        self.__vads = []
        # Chunks of memory injected to other processes
        self.__injections = []
        self.__file_operations = []
        self.__section_maps = []

        # Indicates that this instance is a result of unpicking a serialized
        # object
        self.__unpickled = False

        # Exited. Indicates that process has already exited.
        self.__exited = False

        self.__symbols = []
        self.__other_calls = []
        self.__all_calls = []


    def get_symbols(self):
        return self.__symbols

    def get_all_calls(self):
        return self.__all_calls

    def get_other_calls(self):
        return self.__other_calls

    def set_pgd(self, pgd):
        self.__pgd = pgd

    def set_pid(self, pid):
        self.__pid = pid

    def set_name(self, name):
        self.__proc_name = name

    def get_proc_num(self):
        return self.__proc_num
    def get_pgd(self):
        return self.__pgd

    def get_pid(self):
        return self.__pid

    def has_exited(self):
        return self.__exited

    def set_exited(self):
        self.__exited = True

    def get_proc_name(self):
        return self.__proc_name

    def get_modules(self):
        return self.__modules

    def get_vads(self):
        return self.__vads

    def get_injections(self):
        return self.__injections

    def get_file_operations(self):
        return self.__file_operations

    def get_section_maps(self):
        return self.__section_maps

    def add_section_map(self, section_map):
        global interproc_data
        self.__section_maps.append(section_map)
        interproc_data.deliver_section_map_callback(section_map)

    def add_file_operation(self, operation):
        global interproc_data
        self.__file_operations.append(operation)
        if isinstance(operation, FileRead):
            interproc_data.deliver_file_read_callback(operation)
        elif isinstance(operation, FileWrite):
            interproc_data.deliver_file_write_callback(operation)

    def __str__(self):
        return "%x" % self.__pid

    def set_module(self, name, base, size):
        if name not in self.__modules:
            self.__modules[name] = [(base, size)]
        elif (base, size) not in self.__modules[name]:
            self.__modules[name].append((base, size))

    def get_overlapping_module(self, addr):
        for mod_name in self.__modules:
            for base,size in self.__modules[mod_name]:
                if base >= addr and addr < (base + size):
                    return mod_name
        return None

    def get_overlapping_vad(self, addr):
        '''
        Get the VAD overlapping the address
        '''
        for vad in self.__vads:
            if vad.get_start() <= addr and (vad.get_start() + vad.get_size()) > addr:
                return vad
        return None

    def add_injection(self, inj):
        global interproc_data
        self.__injections.append(inj)
        if inj.is_reverse():
            interproc_data.deliver_remote_memory_read_callback(inj)
        else:
            interproc_data.deliver_remote_memory_write_callback(inj)

    def update_from_peb(self):
        '''
        Update several variables based on info extracted from peb
        '''
        import volatility.win32.tasks as tasks
        from utils import get_addr_space

        addr_space = get_addr_space(self.get_pgd())

        eprocs = [t for t in tasks.pslist(
            addr_space) if t.UniqueProcessId == self.__pid]
        if len(eprocs) != 1:
            self.__commandline = None
            self.__current_directory = None
            self.__image_path = None
        else:
            task = eprocs[0]
            self.__commandline = str(
                task.Peb.ProcessParameters.CommandLine or '')
            self.__current_directory = str(
                task.Peb.ProcessParameters.CurrentDirectory.DosPath or '')
            self.__image_path = str(
                task.Peb.ProcessParameters.ImagePathName or '')

    def update_symbols(self):
        import api
        from api import CallbackManager

        if self.__unpickled:
            return

        syms = api.get_symbol_list()

        for d in syms:
            mod = d["mod"]
            fun = d["name"]
            addr = d["addr"]

            pos = bisect.bisect_left(self.__symbols, Symbol("", "", addr))
            if pos >= 0 and pos < len(self.__symbols) and self.__symbols[pos].get_addr() == addr:
                continue
            if mod in self.__modules:
                for pair in self.__modules[mod]:
                    bisect.insort(
                        self.__symbols, Symbol(mod, fun, pair[0] + addr))

    def update_vads(self):
        '''
        Call volatility to obtain VADS.
        '''
        if self.__unpickled:
            return
        import volatility.obj as obj
        import volatility.win32.tasks as tasks
        import volatility.plugins.vadinfo as vadinfo
        from utils import get_addr_space

        addr_space = get_addr_space(self.get_pgd())

        eprocs = [t for t in tasks.pslist(
            addr_space) if t.UniqueProcessId == self.__pid]
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

                    if new_vad not in self.__vads:
                        self.__vads.append(new_vad)

    def add_call(self, addr_from, addr_to, data):
        '''
        Add a function call to the corresponding VAD
        '''
        if self.__unpickled:
            return
        vad = self.get_overlapping_vad(addr_from)
        if vad is None:
            self.update_vads()
            vad = self.get_overlapping_vad(addr_from)
            if vad is None:
                self.__other_calls.append((addr_from, addr_to, data))
                return
        vad.add_call((addr_from, addr_to, data))
        self.__all_calls.append((addr_from, addr_to, data))


    def locate_nearest_symbol(self, addr):
        pos = bisect.bisect_left(self.__symbols, Symbol("", "", addr))
        if pos < 0 or pos >= len(self.__symbols):
            return None
        # If the exact match is not located, go to the nearest (lower) address
        if self.__symbols[pos].get_addr() != addr:
            pos -= 1
        if (addr - self.__symbols[pos].get_addr()) < 0x32 and (addr - self.__symbols[pos].get_addr()) >= 0:
            return self.__symbols[pos]
        else:
            return None

    def __getstate__(self):
        '''
            Returns objects to be pickled.
        '''
        return (self.__proc_num,
                self.__proc_name,
                self.__pgd,
                self.__pid,
                self.__modules,
                self.__symbols,
                self.__vads,
                self.__other_calls,
                self.__injections,
                self.__file_operations,
                self.__section_maps)

    def __setstate__(self, state):
        '''
            Sets pickled objects when unpickling
        '''
        (self.__proc_num,
         self.__proc_name,
         self.__pgd,
         self.__pid,
         self.__modules,
         self.__symbols,
         self.__vads,
         self.__other_calls,
         self.__injections,
         self.__file_operations,
         self.__section_maps) = state

        self.__unpickled = True

    def print_stats(self, f):
        '''
            Prints some basic statistics about processes.
        '''
        self.update_from_peb()

        f.write("BASIC INFORMATION\n")
        f.write("=================\n\n")

        f.write("Process name: %s\n" % self.__proc_name)
        f.write("CR3: %x\n" % self.__pgd)
        f.write("PID: %x\n" % self.__pid)
        f.write("Nb of modules: %d\n" % len(self.__modules))
        f.write("Commandline: %s\n" % self.__commandline)
        f.write("Current directory: %s\n" % self.__current_directory)
        f.write("Image path: %s\n" % self.__image_path)
        f.write("Target long size: %d\n" % self.TARGET_LONG_SIZE)

        f.write("\nMODULE LIST\n")
        f.write("===========\n\n")

        vads = self.__vads
        #syms = self.symbols
        included_vads = []
        for mod in self.__modules:
            f.write("\n%s\n" % mod)
            f.write(("-" * len(mod)) + "\n")
            mod_vads = []
            #mod_syms = []
            for addr_s in self.__modules[mod]:
                if self.TARGET_LONG_SIZE == 4:
                    f.write("0x%08x - %08x\n" % addr_s)
                elif self.TARGET_LONG_SIZE == 8:
                    f.write("0x%016x - %016x\n" % addr_s)
                mod_vads.extend(
                    filter(lambda x: x.get_start() >= addr_s[0] and (x.get_start() < (addr_s[0] + addr_s[1])), vads))
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

        f.write("Nb of injections: %d\n\n" % (len(self.__injections)))

        for inj in self.__injections:
            f.write(str(inj) + "\n")

        f.write("\nFILE OPERATIONS\n")
        f.write("===============\n\n")

        f.write("Nb of file operations: %d\n\n" % (len(self.__file_operations)))

        for op in self.__file_operations:
            f.write(str(op) + "\n")

        f.write("\nSECTION MAPS\n")
        f.write("============\n\n")

        f.write("Nb of section maps: %d\n\n" % (len(self.__section_maps)))

        for smap in self.__section_maps:
            if self.TARGET_LONG_SIZE == 4:
                out_str = "%08x(%08x)" % (smap.get_base(), smap.get_size())
            elif self.TARGET_LONG_SIZE == 8:
                out_str = "%16x(%16x)" % (smap.get_base(), smap.get_size())

            if smap.get_section().get_backing_file() is not None:
                out_str += " %s" % (str(smap.get_section().get_backing_file()))
            out_str += "\n"
            f.write(out_str)

        f.write("\n" * 8)


class Injection:

    def __init__(self, remote_proc, remote_addr, local_proc, local_addr, size, data, reverse):
        self.__remote_proc = remote_proc
        self.__local_proc = local_proc
        self.__remote_addr = remote_addr
        self.__local_addr = local_addr
        self.__size = size
        self.__data = data
        self.__reverse = reverse

    def get_remote_proc(self):
        return self.__remote_proc

    def get_local_proc(self):
        return self.__local_proc

    def get_remote_addr(self):
        return self.__remote_addr

    def get_local_addr(self):
        return self.__local_addr

    def get_size(self):
        return self.__size

    def get_data(self):
        return self.__data

    def get_reverse(self):
        return self.__reverse

    def is_reverse(self):
        return self.__reverse

    def __str__(self):
        return "Remote injection: PID %x - %x -> PID %x - %x (%x)" % (self.__local_proc.get_pid(),
                                                                      self.__local_addr,
                                                                      self.__remote_proc.get_pid(),
                                                                      self.__remote_addr,
                                                                      self.__size)

class FileOperation(object):

    def __init__(self, file_inst, proc, buffer_addr, offset, size, data):
        self.__file_inst = file_inst
        self.__proc = proc
        self.__offset = offset
        self.__size = size
        self.__data = data
        self.__buffer_addr = buffer_addr

    def get_file(self):
        return self.__file_inst

    def get_proc(self):
        return self.__proc

    def get_offset(self):
        return self.__offset

    def get_size(self):
        return self.__size

    def get_data(self):
        return self.__data

    def get_buffer_addr(self):
        return self.__buffer_addr

    def __str__(self):
        return "%s:%s - %08x(%08x bytes)" % (str(self.__proc), str(self.__file_inst), self.__offset, self.__size)


class FileRead(FileOperation, object):

    def __init__(self, file_inst, proc, buffer_addr, offset, size, data):
        super(FileRead, self).__init__(file_inst, proc, buffer_addr,  offset, size, data)

    def __str__(self):
        res = "File Read: %s" % super(FileRead, self).__str__()
        return res


class FileWrite(FileOperation, object):

    def __init__(self, file_inst, proc, buffer_addr, offset, size, data):
        super(FileWrite, self).__init__(file_inst, proc, buffer_addr, offset, size, data)

    def __str__(self):
        res = "File Write: %s" % super(FileWrite, self).__str__()
        return res


class File:

    def __init__(self, file_name):
        self.__file_name = file_name
        self.__file_operations = []

    def add_operation(self, op):
        self.__file_operations.append(op)

    def get_file_name(self):
        return self.__file_name

    def get_file_operations(self):
        return self.__file_operations

    def __str__(self):
        return self.__file_name


class Section:

    def __init__(self, pgd, section_object):
        import api
        global interproc_data

        TARGET_LONG_SIZE = api.get_os_bits() / 8

        # Volatility object representing the section
        self.__section_object = section_object

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
            self.__flags = struct.unpack(
                "I", api.r_va(pgd, self.__section_object.obj_offset + ((TARGET_LONG_SIZE * 6) + 8), 0x4))[0]
        except:
            self.__flags = 0x00000000
            pp_print("Could not read flags in Section __init__\n")
        self.__cow = ((self.__flags & 0x00000800) != 0)
        self.__file_backed = ((self.__flags & 0x00000080) != 0)

        self.__backing_file = None

        # If so, get corresponding file.
        if self.__file_backed:
            # Dereference as _SEGMENT, that is different from _SEGMENT_OBJECT
            # This is because the volatility profile lacks the _SECTION object,
            # and instead has the _SECTION_OBJECT. Since the Segment field
            # of _SECTION and _SECTION_OBJECT are aligned, we can just dereference
            # that offset. Nevertheless, _SECTION_OBJECT has a _SEGMENT_OBJECT type
            # Segment, while _SECTION has a _SEGMENT type Segment...

            # http://forum.sysinternals.com/section-object_topic24975.html

            self.__segment = self.__section_object.Segment.dereference_as(
                "_SEGMENT")
            file_obj = self.__segment.ControlArea.FilePointer


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

            self.__backing_file = interproc_data.get_file_by_file_name(str(file_obj.FileName))

            # If we have still not recorded the file, add it to files record
            if self.__backing_file is None:
                self.__backing_file = File(str(file_obj.FileName))
                interproc_data.add_file(self.__backing_file)
        
        self.__unpickled = False
        self.__offset = self.__section_object.obj_offset

    def __getstate__(self):
        '''
            Returns objects to be pickled.
        '''
        return (self.__flags, self.__cow, self.__file_backed, self.__backing_file, self.__offset)

    def __setstate__(self, state):
        '''
            Sets pickled objects when unpickling
        '''
        self.__flags, self.__cow, self.__file_backed, self.__backing_file, self.__offset = state
        self.__section_object = None
        self.__unpickled = True

    def get_object(self):
        if self.__unpickled:
            return None
        else:
            return self.__section_object

    def get_offset(self):
        if self.__unpickled:
            return self.__offset
        else:
            return self.__section_object.obj_offset

    def is_cow(self):
        return self.__is_cow

    def get_flags(self):
        return self.__flags

    def is_file_backed(self):
        return self.__file_backed

    def get_backing_file(self):
        return self.__backing_file

    def get_offset(self):
        return self.__offset


class SectionMap:

    def __init__(self, section, pgd, base, size, section_offset):
        self.__section = section
        self.__pgd = pgd
        self.__base = base
        self.__size = size
        self.__section_offset = section_offset
        # This flag indicates if the map is still active (created and not yet unmapped).
        # When a map is unmapped, instead of deleting our record, we deactivate it to keep
        # a list of all the mapped memory.
        self.__active = True

    def get_section(self):
        return self.__section

    def get_base(self):
        return self.__base

    def get_size(self):
        return self.__size

    def get_section_offset(self):
        return self.__section_offset

    def is_active(self):
        return self.__active

    def get_pgd(self):
        return self.__pgd

    def deactivate(self):
        self.__active = False
        interproc_data.deliver_section_unmap_callback(self)
