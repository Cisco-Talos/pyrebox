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

# Memory protection constants (virtualprotect)
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08


class InterprocData():
    '''
    Class that just holds all the data regarding procs, sections, files...
    '''
    def __init__(self):
        # Processes
        self.procs = []
        # Written/Read files
        self.files = []
        # Mapped memory sections
        self.sections = []


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
        self.interproc_bin_log = False
        self.interproc_text_log = False
        self.interproc_basic_stats = False

        self.api_tracer_text_log_name = "function_calls.log"
        self.api_tracer_bin_log_name = "function_calls.bin"
        self.api_tracer_procs = None

        self.interproc_text_log_name = "interproc.log"
        self.interproc_text_log_handle = None
        self.interproc_basic_stats_name = "basic_stats"

        self.interproc_bin_log_name = "interproc.bin"

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

# ====================================== GLOBAL VARIABLES ================


mwmon = MwMonitor()

# Whenever there is a call to a module
# in this list, try to resolve symbols, and once resolved,
# remove it from the list.
# Dictionary PGD -> (name, Dict('base': 0, 'size': 0))
mods_pending_symbol_resolution = {} 
ntdll_breakpoint = {}

# ======================================     HELPERS      ================

def is_in_pending_resolution(pgd, address):
    global mods_pending_symbol_resolution
    if pgd in mods_pending_symbol_resolution:
        for name,m in mods_pending_symbol_resolution[pgd].iteritems():
            if address >= m['base'] and address < (m['base'] + m['size']):
                return True
    return False

def module_loaded(pid, pgd, base, size, name, fullname):
    import api
    from mw_monitor_classes import mwmon
    from api import CallbackManager
    from functools import partial
    global mods_pending_symbol_resolution

    for proc in mwmon.data.procs:
        if pid == proc.get_pid():
            if pgd not in mods_pending_symbol_resolution:
                mods_pending_symbol_resolution[pgd] = {}
            mods_pending_symbol_resolution[pgd][name] = {'base': base, 'size': size}

            proc.set_module(name, base, size)

def find_ep(proc, proc_name):
    '''Given an address space and a process name, uses pefile module
       to get its entry point
    '''
    import api
    import pefile
    from mw_monitor_classes import mwmon

    try:
        for m in api.get_module_list(proc.get_pgd()):
            name = m["name"]
            base = m["base"]
            # size = m["size"]
            if name == proc_name:
                    pe_data = api.r_va(proc.get_pgd(), base, 0x1000)
                    pe = pefile.PE(data=pe_data)
                    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    return (base + ep)
    except Exception as e:
        mwmon.printer("Unable to run pefile on loaded module %s (%s)" % (proc_name, str(e)))
        pass
    return None

def ntdll_breakpoint_func(proc, cpu_index, cpu):
    ''' 
        Breakpoint for the first instruction executed in the main module
    '''
    global ntdll_breakpoint
    from mw_monitor_classes import mwmon
    import api

    ntdll_breakpoint[proc.get_pgd()].disable()
    TARGET_LONG_SIZE = api.get_os_bits() / 8
    if TARGET_LONG_SIZE == 4:
        mwmon.printer("Executed first instruction for pgd %x at %x" % (cpu.CR3, cpu.EIP))
    elif TARGET_LONG_SIZE == 8:
        mwmon.printer("Executed first instruction for pgd %x at %x" % (cpu.CR3, cpu.RIP))

    proc.update_symbols()


def context_change(new_proc, target_mod_name, old_pgd, new_pgd):
    '''Callback triggered for every context change'''
    global ntdll_breakpoint
    from mw_monitor_classes import mwmon
    from api import BP
    import api
    from api import CallbackManager
    from functools import partial

    if new_proc.get_pgd() == new_pgd:
        ep = find_ep(new_proc, target_mod_name)
        if ep is not None:
            mwmon.printer("The entry point for %s is %x\n" % (target_mod_name, ep))
            mwmon.cm.rm_callback("context_change_%x" % new_proc.get_pgd())

            try:
                # Load modules and symbols for the process
                mods = api.get_module_list(new_proc.get_pgd())
                if mods is not None:
                    for m in mods:
                        name = m["name"]
                        base = m["base"]
                        size = m["size"]
                        new_proc.set_module(name, base, size)
                        # NTDLL is a special case, and we set a breakpoint
                        # on the code of the main module to trigger the symbol resolution
                        # as soon as we execute one instruction in its 
                        # region
                        if target_mod_name in name:
                            ntdll_breakpoint[new_proc.get_pgd()] = BP(base, 
                                                  new_proc.get_pgd(), 
                                                  size = size,
                                                  func = partial(ntdll_breakpoint_func, new_proc))
                            ntdll_breakpoint[new_proc.get_pgd()].enable()

            except ValueError as e:
                # The process has not been created yet, so we need to 
                # wait for symbol resolution
                pass

            # Callback for each module loaded
            mwmon.cm.add_callback(CallbackManager.LOADMODULE_CB, 
                                  module_loaded, 
                                  pgd = new_proc.get_pgd(), 
                                  name = ("load_module_%x" % new_proc.get_pgd()))

def mw_monitor_start_monitoring_process(new_proc, insert_proc=True):
    '''
        This function sets up all the callbacks and structures
        necessary to monitor a process.

        :param new_proc: The process to start monitoring as a instance of Process
        :type new_proc: Process

        :param insert_proc: (Optional) Whether to insert the process in the list of
                            monitored processes (internal to this script).
        :type insert_proc: bool
    '''
    from coverage import block_executed
    from api_tracer import apitracer_start_monitoring_process
    from dumper import dumper_start_monitoring_process
    from api import CallbackManager
    import api

    # Insert the process, if necessary
    if insert_proc:
        mwmon.data.procs.append(new_proc)
    # Start monitoring the process
    api.start_monitoring_process(new_proc.get_pgd())
    mwmon.printer("Started monitoring process with PGD %x and name %s" %
                  (new_proc.get_pgd(),
                   new_proc.get_proc_name()))

    # coverage module
    # Create a callback and trigger for each process
    if mwmon.coverage and (mwmon.coverage_procs is None or new_proc.proc_name in mwmon.coverage_procs):
        mwmon.cm.add_callback(CallbackManager.BLOCK_BEGIN_CB, functools.partial(
            block_executed, proc=new_proc), name="block_begin_coverage_%d" % new_proc.proc_num)
        mwmon.cm.add_trigger("block_begin_coverage_%d" %
                             new_proc.proc_num, "triggers/trigger_block_user_only_coverage.so")
        mwmon.cm.set_trigger_var("block_begin_coverage_%d" %
                                 (new_proc.proc_num), "cr3", new_proc.get_pgd())
        mwmon.cm.set_trigger_var("block_begin_coverage_%d" %
                                 (new_proc.proc_num), "proc_num", new_proc.proc_num)
        # Output file name, with pid
        mwmon.cm.set_trigger_var("block_begin_coverage_%d" %
                                 (new_proc.proc_num), "log_name", mwmon.coverage_log_name + ".%x" % (new_proc.pid))

    # api tracer module
    if mwmon.api_tracer and (mwmon.api_tracer_procs is None or new_proc.proc_name in mwmon.api_tracer_procs):
        apitracer_start_monitoring_process(new_proc)

    # dumper module
    if mwmon.dumper:
        dumper_start_monitoring_process(new_proc)        

    mwmon.cm.add_callback(CallbackManager.CONTEXTCHANGE_CB,
                          functools.partial(context_change, new_proc, new_proc.get_proc_name()),
                          name="context_change_%x" % new_proc.get_pgd())


# ======================================     CLASSES       ===============


class VADRegion(object):

    '''
    VAD container
    '''
    PAGE_SIZE = 0x1000

    def __init__(self, start, size, proc, mapped_file, tag, vad_type, private, protection):
        self.start = start
        self.size = size
        self.calls = []
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

    def add_call(self, call):
        self.calls.append(call)

    def get_calls(self):
        return self.calls

    def __hash__(self):
        return hash(tuple(self))


class Symbol:

    def __init__(self, mod, fun, addr):
        self.mod = mod
        self.fun = fun
        self.addr = addr

    def get_mod(self):
        return self.mod

    def get_fun(self):
        return self.fun

    def get_addr(self):
        return self.addr

    def __lt__(self, other):
        return self.addr < other.addr

    def __le__(self, other):
        return self.addr <= other.addr

    def __eq__(self, other):
        return self.addr == other.addr

    def __ne__(self, other):
        return self.addr != other.addr

    def __gt__(self, other):
        return self.addr > other.addr

    def __ge__(self, other):
        return self.addr >= other.addr


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
        if self.TARGET_LONG_SIZE == 4:
            self.min_mod_addr = 0xFFFFFFFF
        elif self.TARGET_LONG_SIZE == 8:
            self.min_mod_addr = 0xFFFFFFFFFFFFFFFF
        else:
            raise Exception(
                "[Process::init()] Unsupported TARGET_LONG_SIZE: %d" % self.TARGET_LONG_SIZE)
        self.max_mod_addr = 0x0
        self.symbols = []
        # Record of API calls (related to VADs, and others
        self.vads = []
        self.other_calls = []
        # Chunks of memory injected to other processes
        self.injections = []
        self.file_operations = []
        self.section_maps = []
        # Keep a list with all the calls ordered
        self.all_calls = []

        # Indicates that this instance is a result of unpicking a serialized
        # object
        self.unpickled = False

        # Exited. Indicates that process has already exited.
        self.exited = False

        from interproc import ntcreateprocess
        from interproc import ntopenprocess
        from interproc import ntwritevirtualmemory
        from interproc import ntreadvirtualmemory
        from interproc import ntreadfile
        from interproc import ntwritefile
        from interproc import ntmapviewofsection
        from interproc import ntunmapviewofsection
        from interproc import ntvirtualprotect
        from interproc import ntallocatevirtualmemory
        from utils import ConfigurationManager as conf_m

        if mwmon.interproc:

            # Dictionary to store breakpoints for the following APIs:
            self.breakpoints = {("ntdll.dll", "ZwOpenProcess"): None,
                                ("ntdll.dll", "ZwReadFile"): None,
                                ("ntdll.dll", "ZwWriteFile"): None,
                                ("ntdll.dll", "ZwMapViewOfSection"): None,
                                ("ntdll.dll", "ZwUnmapViewOfSection"): None,
                                ("ntdll.dll", "ZwWriteVirtualMemory"): None,
                                ("ntdll.dll", "ZwReadVirtualMemory"): None,
                                ("ntdll.dll", "ZwProtectVirtualMemory"): None,
                                ("ntdll.dll", "NtAllocateVirtualMemory"): None}

            self.bp_funcs = {
                ("ntdll.dll", "ZwOpenProcess"): (ntopenprocess,
                                                 True and not mwmon.api_tracer and not mwmon.coverage),
                ("ntdll.dll", "ZwReadFile"): (ntreadfile,
                                              False and not mwmon.api_tracer and not mwmon.coverage),
                ("ntdll.dll", "ZwWriteFile"): (ntwritefile,
                                               False and not mwmon.api_tracer and not mwmon.coverage),
                ("ntdll.dll", "ZwMapViewOfSection"): (ntmapviewofsection,
                                                      True and not mwmon.api_tracer and not mwmon.coverage),
                ("ntdll.dll", "ZwUnmapViewOfSection"): (ntunmapviewofsection,
                                                        True and not mwmon.api_tracer and not mwmon.coverage),
                ("ntdll.dll", "ZwWriteVirtualMemory"): (ntwritevirtualmemory,
                                                        False and not mwmon.api_tracer and not mwmon.coverage),
                ("ntdll.dll", "ZwReadVirtualMemory"): (ntreadvirtualmemory,
                                                       False and not mwmon.api_tracer and not mwmon.coverage),
                ("ntdll.dll", "ZwProtectVirtualMemory"): (ntvirtualprotect,
                                                          False and not mwmon.api_tracer and not mwmon.coverage),
                ("ntdll.dll", "NtAllocateVirtualMemory"): (ntallocatevirtualmemory,
                                                           True and not mwmon.api_tracer and not mwmon.coverage)}

            profile = conf_m.vol_profile

            # If before vista:
            if "WinXP" in profile or "Win2003" in profile:
                # We hook both, because although Kernel32 calls the "Ex" version, a
                # program may call directy ZwCreateProcess
                self.breakpoints[("ntdll.dll", "ZwCreateProcessEx")] = None
                self.bp_funcs[("ntdll.dll", "ZwCreateProcessEx")] = (
                    ntcreateprocess, True and not mwmon.api_tracer and not mwmon.coverage)
                self.breakpoints[("ntdll.dll", "ZwCreateProcess")] = None
                self.bp_funcs[("ntdll.dll", "ZwCreateProcess")] = (
                    ntcreateprocess, True and not mwmon.api_tracer and not mwmon.coverage)
            else:
                self.breakpoints[("ntdll.dll", "ZwCreateProcessEx")] = None
                self.bp_funcs[("ntdll.dll", "ZwCreateProcessEx")] = (
                    ntcreateprocess, True and not mwmon.api_tracer and not mwmon.coverage)
                self.breakpoints[("ntdll.dll", "ZwCreateProcess")] = None
                self.bp_funcs[("ntdll.dll", "ZwCreateProcess")] = (
                    ntcreateprocess, True and not mwmon.api_tracer and not mwmon.coverage)
                # On Vista (and onwards), kernel32.dll no longer uses
                # ZwCreateProcess/ZwCreateProcessEx (although these function remain
                # in ntdll.dll. It Uses ZwCreateUserProcess.
                self.breakpoints[("ntdll.dll", "ZwCreateUserProcess")] = None
                self.bp_funcs[("ntdll.dll", "ZwCreateUserProcess")] = (
                    ntcreateprocess, True and not mwmon.api_tracer and not mwmon.coverage)
        else:
            self.breakpoints = {}
            self.bp_funcs = {}

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

    def in_mod_boundaries(self, addr):
        return (addr >= self.min_mod_addr and addr < self.max_mod_addr)

    def set_module(self, name, base, size):
        # Set boundaries for loaded modules
        if base < self.min_mod_addr:
            self.min_mod_addr = base
        if (base + size) > self.max_mod_addr:
            self.max_mod_addr = (base + size)
        if name not in self.modules:
            self.modules[name] = [(base, size)]
        elif (base, size) not in self.modules[name]:
            self.modules[name].append((base, size))
        # Update the (include/exclude addresses in apitracer)
        if mwmon.exclude_modules is not None:
            if name.lower() in mwmon.exclude_modules:
                if (base, size) not in mwmon.exclude_modules_addrs:
                    mwmon.exclude_modules_addrs.append((base, size))
        if mwmon.exclude_origin_modules is not None:
            if name.lower() in mwmon.exclude_origin_modules:
                if (base, size) not in mwmon.exclude_origin_modules_addrs:
                    mwmon.exclude_origin_modules_addrs.append((base, size))

    def locate_nearest_symbol(self, addr):
        pos = bisect.bisect_left(self.symbols, Symbol("", "", addr))
        if pos < 0 or pos >= len(self.symbols):
            return None
        # If the exact match is not located, go to the nearest (lower) address
        if self.symbols[pos].addr != addr:
            pos -= 1
        if (addr - self.symbols[pos].addr) < 0x32 and (addr - self.symbols[pos].addr) >= 0:
            return self.symbols[pos]
        else:
            return None

    def get_overlapping_vad(self, addr):
        '''
        Get the VAD overlapping the call address
        '''
        for vad in self.vads:
            if vad.start <= addr and (vad.start + vad.size) > addr:
                return vad
        return None

    def add_call(self, addr_from, addr_to, data):
        '''
        Add a function call to the corresponding VAD
        '''
        if self.unpickled:
            return
        vad = self.get_overlapping_vad(addr_from)
        if vad is None:
            self.update_vads()
            vad = self.get_overlapping_vad(addr_from)
            if vad is None:
                self.other_calls.append((addr_from, addr_to, data))
                return
        vad.add_call((addr_from, addr_to, data))
        self.all_calls.append((addr_from, addr_to, data))

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

    def update_symbols(self):
        import api
        from api import CallbackManager
        global mods_pending_symbol_resolution

        if self.unpickled:
            return

        syms = api.get_symbol_list()

        # Check if we can remove the module from the list of modules with
        # pending symbol resolution
        for mod in api.get_module_list(self.get_pgd()):
            if mod["symbols_resolved"] and mod["name"] in mods_pending_symbol_resolution[self.get_pgd()]:
                del mods_pending_symbol_resolution[self.get_pgd()][mod["name"]]

        for d in syms:
            mod = d["mod"]
            fun = d["name"]
            addr = d["addr"]

            pos = bisect.bisect_left(self.symbols, Symbol("", "", addr))
            if pos >= 0 and pos < len(self.symbols) and self.symbols[pos].get_addr() == addr:
                continue
            if mod in self.modules:
                for pair in self.modules[mod]:
                    # Update the (include/exclude addresses in apitracer)
                    if mwmon.include_apis is not None:
                        if (mod.lower(), fun.lower()) in mwmon.include_apis:
                            if (pair[0] + addr) not in mwmon.include_apis_addrs:
                                mwmon.include_apis_addrs.append(pair[0] + addr)

                    if mwmon.exclude_apis is not None:
                        if (mod.lower(), fun.lower()) in mwmon.exclude_apis:
                            if (pair[0] + addr) not in mwmon.exclude_apis_addrs:
                                mwmon.exclude_apis_addrs.append(pair[0] + addr)

                    bisect.insort(
                        self.symbols, Symbol(mod, fun, pair[0] + addr))
                    if mwmon.interproc or mwmon.api_tracer or mwmon.dumper:
                        # Add breakpoint if necessary
                        if (mod, fun) in self.breakpoints and self.breakpoints[(mod, fun)] is None:
                            f_callback = self.bp_funcs[(mod, fun)][0]
                            update_vads = self.bp_funcs[(mod, fun)][1]
                            callback = functools.partial(
                                f_callback, pid=self.pid, proc=self, update_vads=update_vads)
                            bp = mwmon.cm.add_callback(CallbackManager.INSN_BEGIN_CB,
                                                       callback,
                                                       name="api_bp_%x_%s" % (self.pid, fun),
                                                       addr=pair[0] + addr,
                                                       pgd=self.pgd)
                            self.breakpoints[(mod, fun)] = (bp, pair[0] + addr)
                            mwmon.printer("Adding breakpoint at %s:%s %x:%x from process with PID %x" %
                                          (mod, fun, pair[0] + addr, self.pgd, self.pid))

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
                self.min_mod_addr,
                self.max_mod_addr,
                self.symbols,
                self.vads,
                self.other_calls,
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
         self.min_mod_addr,
         self.max_mod_addr,
         self.symbols,
         self.vads,
         self.other_calls,
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
        syms = self.symbols
        included_vads = []
        for mod in self.modules:
            f.write("\n%s\n" % mod)
            f.write(("-" * len(mod)) + "\n")
            mod_vads = []
            mod_syms = []
            for addr_s in self.modules[mod]:
                if self.TARGET_LONG_SIZE == 4:
                    f.write("0x%08x - %08x\n" % addr_s)
                elif self.TARGET_LONG_SIZE == 8:
                    f.write("0x%016x - %016x\n" % addr_s)
                mod_vads.extend(
                    filter(lambda x: x.start >= addr_s[0] and (x.start < (addr_s[0] + addr_s[1])), vads))
                mod_syms.extend(
                    filter(lambda x: x.addr >= addr_s[0] and (x.addr < (addr_s[0] + addr_s[1])), syms))
            for v in mod_vads:
                f.write("    %s\n" % (str(v)))
                included_vads.append(v)
            f.write("    Nb of symbols: %d\n" % len(mod_syms))

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
            mwmon.printer("Could not read flags in Section __init__")
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

            for fi in mwmon.data.files:
                if fi.file_name == str(file_obj.FileName):
                    self.backing_file = fi
                    break

            # If we have still not recorded the file, add it to files record
            if self.backing_file is None:
                self.backing_file = File(str(file_obj.FileName))
                mwmon.data.files.append(self.backing_file)
        
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
