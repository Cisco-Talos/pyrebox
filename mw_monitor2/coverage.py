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

from __future__ import print_function
import os
import json
import functools

# Determine TARGET_LONG_SIZE
from api import get_os_bits
TARGET_LONG_SIZE = get_os_bits() / 8

# Script requirements
requirements = ["mw_monitor2.interproc"]

# Global variables
# Callback manager
cm = None
# Printer
pyrebox_print = None

# Configuration values
COVERAGE_DUMP_PATH = None

def log_coverage():
    '''
        When this module is unloaded,
        we create a text summary of the 
        coverage binary log generated.
    '''
    import api
    import ntpath
    from interproc import interproc_data
    import struct

    for proc in interproc_data.get_processes():
        cov_bin_path = str(os.path.join(COVERAGE_DUMP_PATH, "coverage.%x" % (proc.get_pid())))
        cov_log_path = str(os.path.join(COVERAGE_DUMP_PATH, "coverage_log.%x" % (proc.get_pid())))

        if os.path.isfile(cov_bin_path):
            try:
                current_vad = None
                f = open(cov_log_path, "w")
                f_in = open(cov_bin_path, "rb")

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
                    # This will only work if api tracer is
                    # as well activated
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
                                    current_vad.get_start(),
                                    current_vad.get_size(),
                                    last_pc,
                                    pc,
                                    ntpath.basename(current_vad.get_mapped_file()), sym_text))
                            elif TARGET_LONG_SIZE == 8:
                                f.write("VAD: %16x(%16x) %16x --> %16x [%s%s]\n" % (
                                    current_vad.get_start(),
                                    current_vad.get_size(),
                                    last_pc,
                                    pc,
                                    ntpath.basename(current_vad.get_mapped_file()),
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
                                    current_vad.get_start(),
                                    current_vad.get_size(),
                                    last_pc,
                                    pc,
                                    ntpath.basename(current_vad.get_mapped_file()), sym_text))
                            elif TARGET_LONG_SIZE == 8:
                                f.write("VAD: %16x(%16x) %16x --> %16x [%s%s]\n" % (
                                    current_vad.get_start(),
                                    current_vad.get_size(),
                                    last_pc,
                                    pc,
                                    ntpath.basename(current_vad.get_mapped_file()), sym_text))
                            else:
                                raise Exception(
                                    "[log_coverage()] Unsupported TARGET_LONG_SIZE: %d" % TARGET_LONG_SIZE)

                    data = f_in.read(TARGET_LONG_SIZE + TARGET_LONG_SIZE)
                    # last_pc, last_size = pc, size
                    last_pc = pc
                f_in.close()
                f.close()
            except Exception:
                import traceback
                traceback.print_exc()


def block_executed(params, proc=None):
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    cpu_index = params["cpu_index"]
    cpu = params["cpu"]
    tb = params["tb"] 

    # Get the overlapping VAD, if we don't have it, update VADs
    if TARGET_LONG_SIZE == 4:
        page = cpu.EIP & 0xFFFFF000
    elif TARGET_LONG_SIZE == 8:
        page = cpu.RIP & 0xFFFFFFFFFFFFF000

    vad = proc.get_overlapping_vad(page)

    if vad is None:
        proc.update_vads()
    return


def module_entry_point(params):
    '''
        Callback on the entry point of the main module being monitored
    '''
    global cm
    global COVERAGE_DUMP_PATH
    global pyrebox_print
    global ntdll_space
    import os

    from api import CallbackManager
    import api
    from interproc import interproc_data

    # Get pameters
    cpu_index = params["cpu_index"]
    cpu = params["cpu"]

    # Get running process
    pgd = api.get_running_process(cpu_index)

    pyrebox_print("[COVERAGE] Reached entry point of new process: %x" % pgd)

    new_proc = interproc_data.get_process_by_pgd(pgd)

    if new_proc is not None:
        cm.add_callback(CallbackManager.BLOCK_BEGIN_CB, functools.partial(
            block_executed, proc=new_proc), name="block_begin_coverage_%d" % new_proc.get_proc_num())

        cm.add_trigger("block_begin_coverage_%d" %
                             new_proc.get_proc_num(), "triggers/trigger_block_user_only_coverage.so")
        cm.set_trigger_var("block_begin_coverage_%d" %
                                 (new_proc.get_proc_num()), "cr3", new_proc.get_pgd())
        cm.set_trigger_var("block_begin_coverage_%d" %
                                 (new_proc.get_proc_num()), "proc_num", new_proc.get_proc_num())
        # Output file name, with pid
        cm.set_trigger_var("block_begin_coverage_%d" %
                                 (new_proc.get_proc_num()), "log_name", str(os.path.join(COVERAGE_DUMP_PATH, "coverage.%x" %
                                 (new_proc.get_pid()))))
    else:
        pyrebox_print("Could not set coverage callbacks for process %x" % pgd)

    # Start monitoring process
    api.start_monitoring_process(pgd)

def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    global pyrebox_print
    global UNPACKER_LOG_PATH
    global UNPACKER_DUMP_PATH
    global interproc_data

    pyrebox_print("[*]    Cleaning module")
    log_coverage()
    interproc_data.remove_entry_point_callback(module_entry_point)
    cm.clean()
    pyrebox_print("[*]    Cleaned module")


def initialize_callbacks(module_hdl, printer):
    '''
    Initialize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    from api import CallbackManager
    from plugins.guest_agent import guest_agent
    from mw_monitor2.interproc import interproc_data

    global cm
    global pyrebox_print
    global COVERAGE_DUMP_PATH
    global interproc_data

    pyrebox_print = printer

    # Set configuration values
    try:
        f = open(os.environ["MWMONITOR_COVERAGE_CONF_PATH"], "r")
        conf_data = json.load(f)
        f.close()
        COVERAGE_DUMP_PATH = conf_data.get("coverage_dump_path", None)
        if COVERAGE_DUMP_PATH is None:
            raise ValueError("The json configuration file is not well-formed: fields missing?")
    except Exception as e:
        pyrebox_print("Could not read or correctly process the configuration file: %s" % str(e))
        return
    
    try:
        # Initialize process creation callback
        pyrebox_print("[*]    Initializing callbacks")
        interproc_data.register_entry_point_callback(module_entry_point)
        cm = CallbackManager(module_hdl, new_style = True)
        pyrebox_print("[*]    Initialized callbacks")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
