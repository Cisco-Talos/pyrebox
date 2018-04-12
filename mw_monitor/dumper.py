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

import functools
import traceback
import os
import struct

breakpoints = []

def dump_command(line):
    '''
    Dump process memory with its modules and rest of VADS. Specify process name,
    pid or cr3 (in hex).
    '''
    from mw_monitor_classes import mwmon
    from utils import find_procs

    if line == "":
        dump()
    else:
        param = line.split()[0].strip()
        found = find_procs(param)
        if len(found) == 0:
            mwmon.printer("Process %s not found" % param)
        elif len(found) == 1 or (len(found) == 2 and found[0][1] == found[1][1]):
            if found[0][0] == 0:
                # kernel process
                pass
            else:
                pid, pgd, pname = found[0]
                dump(pid=pid)
        else:
            mwmon.printer("Please specify a valid (and unique) process")


def dumper_start_monitoring_process(new_proc):
    '''
    Initialization function called for every new process created.
    '''
    from mw_monitor_classes import mwmon
    from api import CallbackManager

    if mwmon.dumper_onexit:
        dll, fun = ("ntdll.dll", "ZwTerminateProcess")
        # Add a bp to the list of symbol based breakpoints for the process
        new_proc.breakpoints[(dll, fun)] = None
        new_proc.bp_funcs[(dll, fun)] = (
            functools.partial(dump, terminate_process=True), False)
        mwmon.printer("Deferring dumper breakpoint at %s:%s (PGD: %x)" %
                      (dll, fun, new_proc.get_pgd()))

    dump_at = mwmon.dumper_dumpat
    if dump_at is not None:
        # Possible formats for dump_at:
        # 0x00400000
        # user32.dll!CharNextW
        # user32.dll!CharNextW!0x00400000
        terms = dump_at.split("!")
        if len(terms) == 1:
            try:
                addr = int(terms[0], 16)
            except Exception as e:
                mwmon.printer(
                    "Dumper - dump_at: Wrong address value, must specify an hex number")
                return
            cb_name = "dumper_bp_%x_%x" % (new_proc.get_pid(), addr)
            bp = mwmon.cm.add_callback(CallbackManager.INSN_BEGIN_CB, functools.partial(
                dump, pid=new_proc.pid, callback_name=cb_name), name=cb_name, addr=addr, pgd=new_proc.get_pgd())
            breakpoints.append(bp)
            mwmon.printer("Adding dumper breakpoint at %x (CR3: %x)" %
                          (addr, new_proc.get_pgd()))
        elif len(terms) == 2:
            dll = terms[0]
            fun = terms[1]
            # Add a bp to the list of symbol based breakpoints for the process
            if (dll, fun) in new_proc.breakpoints:
                mwmon.printer(
                    "Cannot set dump callback on standard function %s" % fun)
                return
            new_proc.breakpoints[(dll, fun)] = None
            new_proc.bp_funcs[(dll, fun)] = (dump, False)
            mwmon.printer("Deferring dumper breakpoint at %s:%s (PGD: %x)" %
                          (dll, fun, new_proc.get_pgd()))
        elif len(terms) == 3:
            dll = terms[0]
            fun = terms[1]
            try:
                from_addr = int(terms[2], 16)
            except Exception as e:
                mwmon.printer(
                    "Dumper - dump_at: Wrong address value, must specify an hex number : %s" % str(e))
                return
            # Add a bp to the list of symbol based breakpoints for the process
            if (dll, fun) in new_proc.breakpoints:
                mwmon.printer(
                    "Cannot set dump callback on standard function %s" % fun)
                return
            new_proc.breakpoints[(dll, fun)] = None
            new_proc.bp_funcs[(dll, fun)] = (
                functools.partial(dump, from_addr=from_addr), False)
            mwmon.printer("Deferring dumper breakpoint at %s:%s from %x (PGD: %x)" % (dll,
                                                                                      fun, from_addr,
                                                                                      new_proc.get_pgd()))
        else:
            mwmon.printer("Incorrect format for dumper dump_at parameter. No hook will be created")


def dump(cpu_index=None,
         cpu=None,
         pid=None,
         proc=None,
         update_vads=None,
         from_addr=None,
         callback_name=None,
         terminate_process=False):
    '''
    Dump the process, modules, vads...
    '''
    import volatility.constants as constants
    import volatility.exceptions as exceptions
    import volatility.obj as obj
    import volatility.win32.tasks as tasks
    from mw_monitor_classes import mwmon
    from utils import get_addr_space
    import api

    TARGET_LONG_SIZE = api.get_os_bits() / 8

    mwmon.printer("Dumping process...")

    proc_hdl = None
    if terminate_process:
        if TARGET_LONG_SIZE == 4:
            # ret, proc_hdl, exit_status
            try:
                _, proc_hdl, _ = struct.unpack(
                    "<III", api.r_va(api.get_running_process(cpu_index), cpu.ESP, 4 * 3))
            except:
                proc_hdl = 0
                mwmon.printer("Could not dereference process handle in dumper.py")
        elif TARGET_LONG_SIZE == 8:
            # We don't need the return address
            # ret = struct.unpack("<Q",
            # api.r_va(api.get_running_process(cpu_index), cpu.ESP, 8))[0]
            proc_hdl = cpu.RCX
            # We don't need the exit status
            # exit_status = cpu.RDX

        # It seems there are usually 2 calls, when a process terminates itself.
        # First, ZwTerminateProcess is called with 0 as proc_hdl, and afterwards
        # -1.
        if proc_hdl == 0:
            return

    if callback_name is not None:
        # First, remove callback
        mwmon.cm.rm_callback(callback_name)

    # Check if we have been called from the right from_addr
    if from_addr is not None:
        if TARGET_LONG_SIZE == 4:
            try:
                buff = api.r_va(api.get_running_process(cpu_index), cpu.ESP, 4)
                ret_addr = struct.unpack("<I", buff)[0]
            except:
                ret_addr = 0
                mwmon.printer("Could not dereference return address on dumper.py")
        elif TARGET_LONG_SIZE == 8:
            try:
                buff = api.r_va(api.get_running_process(cpu_index), cpu.RSP, 8)
                ret_addr = struct.unpack("<Q", buff)[0]
            except:
                ret_addr = 0
                mwmon.printer("Could not dereference return address on dumper.py")
        if from_addr != ret_addr:
            return

    # We have been called from the right point, now, dump.
    path = mwmon.dumper_path
    # Dump a file with the VAD info, etc, and a filename for each dumped file,
    # so that we can import feed IDA with it
    try:
        # Dump main executable.
        addr_space = get_addr_space()

        # If 1 handle is specified, get the pid for that handle instead
        # of the calling PID.
        if proc_hdl is not None:
            if (TARGET_LONG_SIZE == 4 and proc_hdl == 0xFFFFFFFF) or \
               (TARGET_LONG_SIZE == 8 and proc_hdl == 0xFFFFFFFFFFFFFFFF):
                # If the handle is 0xFFFFFFFF, then the process is the caller.
                pass
            else:
                eprocs = [t for t in tasks.pslist(
                    addr_space) if t.UniqueProcessId == pid]
                proc_obj = None
                # Search handle table for the new created process
                for task in eprocs:
                    if task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
                        for handle in task.ObjectTable.handles():
                            if handle.is_valid() and handle.HandleValue == proc_hdl and handle.get_object_type() == "Process":
                                proc_obj = handle.dereference_as("_EPROCESS")
                                break
                        break
                if proc_obj is not None:
                    # If we found the handle to which it referred, update the
                    # corresponding pid
                    pid = int(proc_obj.UniqueProcessId)
                else:
                    return

        # Case when no PID is specified, just dump everything
        if pid is None:
            pids = [p.pid for p in mwmon.data.procs]
        # When one pid is specified, dump that PID
        else:
            pids = [pid]

        eprocs = [t for t in tasks.pslist(
            addr_space) if t.UniqueProcessId in pids]
        for task in eprocs:
            mwmon.printer("Dumping process %x" % (task.UniqueProcessId))
            # Code adapted from procdump (volatility)
            task_space = task.get_process_address_space()
            if task_space is None:
                mwmon.printer("Error: Cannot acquire process AS")
                return
            elif task.Peb is None:
                # we must use m() here, because any other attempt to
                # reference task.Peb will try to instantiate the _PEB
                mwmon.printer(
                    "Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(task.m('Peb')))
                return
            elif task_space.vtop(task.Peb.ImageBaseAddress) is None:
                mwmon.printer(
                    "Error: ImageBaseAddress at {0:#x} is unavailable" +
                    "(possibly due to paging)".format(task.Peb.ImageBaseAddress))
                return
            else:
                mwmon.printer(
                    "Dumping executable for %x" % (task.UniqueProcessId))
                dump_file = os.path.join(
                    path, "executable.%x.exe" % (task.UniqueProcessId))
                of = open(dump_file, 'wb')
                pe_file = obj.Object(
                    "_IMAGE_DOS_HEADER", offset=task.Peb.ImageBaseAddress, vm=task_space)
                try:
                    for offset, code in pe_file.get_image(unsafe=True,
                                                          memory=False,
                                                          fix=True):
                        of.seek(offset)
                        of.write(code)
                except ValueError, ve:
                    mwmon.printer("Error: {0}".format(ve))
                    return
                except exceptions.SanityCheckException, ve:
                    mwmon.printer("Error: {0} Try -u/--unsafe".format(ve))
                    return
                finally:
                    of.close()

                # Dump every dll.
                mods = dict((mod.DllBase.v(), mod)
                            for mod in task.get_load_modules())

                # List of covered_ranges contains all the address ranges already dumped, to avoid
                # dumping them as vads.
                covered_ranges = [task.Peb.ImageBaseAddress]

                for mod in mods.values():
                    mod_base = mod.DllBase.v()
                    mod_name = mod.BaseDllName
                    if not task_space.is_valid_address(mod_base):
                        mwmon.printer(
                            "Error: DllBase is unavailable (possibly due to paging)")
                        continue
                    else:
                        mwmon.printer("Dumping module %s for %x" %
                                      (mod_name, task.UniqueProcessId))
                        dump_file = os.path.join(
                            path, "module.{0:x}.{1:x}.dll".format(task.UniqueProcessId, mod_base))
                        of = open(dump_file, 'wb')
                        pe_file = obj.Object(
                            "_IMAGE_DOS_HEADER", offset=mod_base, vm=task_space)
                        covered_ranges.append(mod_base)
                        try:
                            for offset, code in pe_file.get_image(unsafe=True,
                                                                  memory=False,
                                                                  fix=True):
                                of.seek(offset)
                                of.write(code)
                        except ValueError, ve:
                            mwmon.printer("Error: {0}".format(ve))
                            return
                        except exceptions.SanityCheckException, ve:
                            mwmon.printer(
                                "Error: {0} Try -u/--unsafe".format(ve))
                            return
                        finally:
                            of.close()

                # Dump every vad
                for vad, _addrspace in task.get_vads(skip_max_commit=True):
                    # Check if the vad has already been dumped as the main
                    # executable or dlls.
                    already_covered = False
                    for covered_addr in covered_ranges:
                        if covered_addr >= vad.Start and covered_addr < vad.End:
                            already_covered = True
                            break
                    if already_covered:
                        continue

                    dump_file = os.path.join(
                        path, "vad.{0:x}.{1:x}-{2:x}.dmp".format(task.UniqueProcessId, vad.Start, vad.End))
                    mwmon.printer("Dumping vad %x:%x for %x" %
                                  (vad.Start, vad.End, task.UniqueProcessId))

                    fh = open(dump_file, "wb")
                    if fh:
                        offset = vad.Start
                        out_of_range = vad.Start + vad.Length
                        while offset < out_of_range:
                            to_read = min(
                                constants.SCAN_BLOCKSIZE, out_of_range - offset)
                            data = task_space.zread(offset, to_read)
                            if not data:
                                break
                            fh.write(data)
                            offset += to_read
                        fh.close()
                    else:
                        mwmon.printer(
                            "Cannot open {0} for writing".format(path))
                        continue
    except Exception as e:
        mwmon.printer("Exception produced: %s" % str(e))
        traceback.print_exc()
