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

import pickle
import os
import traceback
import struct


def serialize_calls():
    from mw_monitor_classes import mwmon
    try:
        f_out = open(mwmon.api_tracer_bin_log_name, "w")
        pickle.dump(mwmon.data.procs, f_out)
        f_out.close()
    except Exception:
        traceback.print_exc()
        mwmon.printer(traceback.print_stack())


def serialize_interproc():
    from mw_monitor_classes import mwmon
    try:
        f_out = open(mwmon.interproc_bin_log_name, "w")
        pickle.dump(mwmon.data, f_out)
        f_out.close()
    except Exception:
        traceback.print_exc()
        mwmon.printer(traceback.print_stack())


def interproc_basic_stats():
    from mw_monitor_classes import mwmon
    try:
        for proc in mwmon.data.procs:
            proc.print_stats(mwmon.interproc_basic_stats_name)
    except Exception:
        traceback.print_exc()
        mwmon.printer(traceback.print_stack())


def log_coverage():
    from mw_monitor_classes import mwmon
    import api
    import ntpath
    # Address and size will have as many bytes as an address
    # in the target architecture
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    for proc in mwmon.data.procs:
        if mwmon.coverage_procs is None or proc.proc_name in mwmon.coverage_procs:
            if os.path.isfile(mwmon.coverage_log_name + (".%x" % proc.pid)):
                try:
                    current_vad = None
                    f = open(
                        mwmon.coverage_text_name + (".%x" % proc.pid), "w")
                    f_in = open(
                        mwmon.coverage_log_name + (".%x" % proc.pid), "rb")

                    data = f_in.read(TARGET_LONG_SIZE + TARGET_LONG_SIZE)
                    last_pc = 0
                    while data is not None and len(data) == 8:

                        if TARGET_LONG_SIZE == 4:
                            pc, size = struct.unpack("<II", data)
                        elif TARGET_LONG_SIZE == 8:
                            pc, size = struct.unpack("<QQ", data)
                        else:
                            raise Exception(
                                "[log_coverage()] Unsupported TARGET_LONG_SIZE: %d" % TARGET_LONG_SIZE)

                        # Locate nearest lower symbol
                        sym = proc.locate_nearest_symbol(pc)
                        sym_text = ""
                        if sym is not None:
                            # mod = sym.get_mod()
                            fun = sym.get_fun()
                            real_api_addr = sym.get_addr()
                            if real_api_addr == pc:
                                sym_text = " - %s" % fun
                            else:
                                sym_text = " - %s(+%x)" % (
                                    fun, (pc - real_api_addr))

                        if current_vad is None:
                            current_vad = proc.get_overlapping_vad(pc)
                            if current_vad is not None:
                                if TARGET_LONG_SIZE == 4:
                                    f.write("VAD: %08x(%08x) %08x --> %08x [%s%s]\n" % (
                                        current_vad.start,
                                        current_vad.size,
                                        last_pc,
                                        pc,
                                        ntpath.basename(current_vad.mapped_file), sym_text))
                                elif TARGET_LONG_SIZE == 8:
                                    f.write("VAD: %16x(%16x) %16x --> %16x [%s%s]\n" % (
                                        current_vad.start,
                                        current_vad.size,
                                        last_pc,
                                        pc,
                                        ntpath.basename(current_vad.mapped_file),
                                        sym_text))
                                else:
                                    raise Exception(
                                        "[log_coverage()] Unsupported TARGET_LONG_SIZE: %d" % TARGET_LONG_SIZE)
                        else:
                            new_vad = proc.get_overlapping_vad(pc)
                            if new_vad != current_vad:
                                current_vad = new_vad
                                if TARGET_LONG_SIZE == 4:
                                    f.write("VAD: %08x(%08x) %08x --> %08x [%s%s]\n" % (
                                        current_vad.start,
                                        current_vad.size,
                                        last_pc,
                                        pc,
                                        ntpath.basename(current_vad.mapped_file), sym_text))
                                elif TARGET_LONG_SIZE == 8:
                                    f.write("VAD: %16x(%16x) %16x --> %16x [%s%s]\n" % (
                                        current_vad.start,
                                        current_vad.size,
                                        last_pc,
                                        pc,
                                        ntpath.basename(current_vad.mapped_file), sym_text))
                                else:
                                    raise Exception(
                                        "[log_coverage()] Unsupported TARGET_LONG_SIZE: %d" % TARGET_LONG_SIZE)

                        data = f_in.read(TARGET_LONG_SIZE + TARGET_LONG_SIZE)
                        # last_pc, last_size = pc, size
                        last_pc = pc
                    f_in.close()
                    f.close()
                except Exception:
                    traceback.print_exc()


def log_calls():
    from mw_monitor_classes import mwmon
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    f_out = open(mwmon.api_tracer_text_log_name, "w")
    try:
        for proc in mwmon.data.procs:
            if mwmon.api_tracer_procs is None or proc.proc_name in mwmon.api_tracer_procs:
                f_out.write("Process (PID: %x) %s\n" %
                            (proc.pid, proc.proc_name))
                for vad in proc.vads:
                    if len(vad.get_calls()) > 0:
                        if TARGET_LONG_SIZE == 4:
                            f_out.write(
                                "\n\nVAD [%08x - %08x]\n\n" % (vad.start, vad.size))
                        elif TARGET_LONG_SIZE == 8:
                            f_out.write(
                                "\n\nVAD [%016x - %016x]\n\n" % (vad.start, vad.size))
                        for data in vad.get_calls():
                            f_out.write("%s" % data[2].__str__())
                if len(proc.other_calls) > 0:
                    f_out.write("\n\n OTHER CALLS...\n\n")
                    for call in proc.other_calls:
                        f_out.write("%s" % data[2].__str__())
        if f_out is not None:
            f_out.close()
    except Exception as e:
        mwmon.printer(str(e))
        mwmon.printer(traceback.print_exc())

    # Output ordered calls
    f_out = open(mwmon.api_tracer_text_log_name + ".ordered", "w")
    try:
        for proc in mwmon.data.procs:
            if mwmon.api_tracer_procs is None or proc.proc_name in mwmon.api_tracer_procs:
                f_out.write("Process (PID: %x) %s\n" %
                            (proc.pid, proc.proc_name))
                for data in proc.all_calls:
                    f_out.write("%s" % data[2].__str__())
        if f_out is not None:
            f_out.close()
    except Exception as e:
        mwmon.printer(str(e))
        mwmon.printer(traceback.print_exc())
