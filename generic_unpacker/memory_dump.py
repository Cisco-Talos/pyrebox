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
import shutil
import os

def dump(pgd_list, pyrebox_print, path = "/tmp/"):
    '''
    Dump the process, modules, vads..., given a list of process address spaces and a path.
    '''
    import volatility.constants as constants
    import volatility.exceptions as exceptions
    import volatility.obj as obj
    import volatility.win32.tasks as tasks
    from utils import get_addr_space
    import api

    # Delete contents, and create directory under path
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.mkdir(path)

    try:
        # Get volatility address space
        addr_space = get_addr_space()

        # Get list of processes (tasks) from volatility
        eprocs = [t for t in tasks.pslist(
            addr_space) if t.Pcb.DirectoryTableBase.v() in pgd_list]

        # For every selected task
        for task in eprocs:
            # Code adapted from procdump (volatility)
            task_space = task.get_process_address_space()
            if task_space is None:
                pyrebox_print("Error: Cannot acquire process AS")
                return
            elif task.Peb is None:
                # we must use m() here, because any other attempt to
                # reference task.Peb will try to instantiate the _PEB
                pyrebox_print(
                    "Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(task.m('Peb')))
                return
            elif task_space.vtop(task.Peb.ImageBaseAddress) is None:
                pyrebox_print(
                    "Error: ImageBaseAddress at {0:#x} is unavailable" +
                    "(possibly due to paging)".format(task.Peb.ImageBaseAddress))
                return
            else:
                dump_file = os.path.join(
                    path, "PID_%x.executable.ex_" % (task.UniqueProcessId))
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
                    pyrebox_print("Error: {0}".format(ve))
                    return
                except exceptions.SanityCheckException, ve:
                    pyrebox_print("Error: {0} Try -u/--unsafe".format(ve))
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
                        pyrebox_print(
                            "Error: DllBase is unavailable (possibly due to paging)")
                        continue
                    else:
                        pyrebox_print("Dumping module %s for %x" %
                                      (mod_name, task.UniqueProcessId))
                        dump_file = os.path.join(
                            path, "PID_{0:x}.module.{1:x}.dll".format(task.UniqueProcessId, mod_base))
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
                            pyrebox_print("Error: {0}".format(ve))
                            return
                        except exceptions.SanityCheckException, ve:
                            pyrebox_print(
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
                        path, "PID_{0:x}.vad.{1:x}-{2:x}.dmp".format(task.UniqueProcessId, vad.Start, vad.End))

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
                        pyrebox_print(
                            "Cannot open {0} for writing".format(path))
                        continue
    except Exception as e:
        pyrebox_print("Exception produced: %s" % str(e))
        traceback.print_exc()
