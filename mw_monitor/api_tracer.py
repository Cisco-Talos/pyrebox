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

import functools
import struct
import traceback


class APICallData:

    def __init__(self):
        self.in_args = []
        self.out_args = []
        self.ret = None
        self.pc = None
        self.mod = None
        self.fun = None
        self.ret_addr = None

    def __str__(self):
        from mw_monitor_classes import mwmon
        import api
        TARGET_LONG_SIZE = api.get_os_bits() / 8
        try:
            outstr = ""
            if TARGET_LONG_SIZE == 4:
                outstr += ("\n\n\n[0x%08x] --> [%s:%s] --> [0x%08x]\n" %
                           (self.pc, self.mod, self.fun, self.ret_addr))
            elif TARGET_LONG_SIZE == 8:
                outstr += ("\n\n\n[0x%016x] --> [%s:%s] --> [0x%016x]\n" %
                           (self.pc, self.mod, self.fun, self.ret_addr))
            args = sorted(self.in_args + self.out_args)
            for arg in args:
                if arg.is_output_arg():
                    try:
                        outstr += ("[OUT] %s: %s\n" %
                                   (arg.get_arg_name(), arg.__str__()))
                    except Exception as e:
                        outstr += (
                            "[OUT] %s: Unable to process: %s\n" % (arg.get_arg_name(), str(e)))
                else:
                    try:
                        outstr += ("[IN ] %s: %s\n" %
                                   (arg.get_arg_name(), arg.__str__()))
                    except Exception as e:
                        outstr += (
                            "[IN] %s: Unable to process : %s\n" % (arg.get_arg_name(), str(e)))
            if self.ret is not None and self.ret is not "":
                try:
                    outstr += ("[RET] %s: %s\n" %
                               (self.ret.get_arg_name(), self.ret.__str__()))
                except Exception as e:
                    outstr += ("[RET] %s: Unable to process: %s\n" %
                               (self.ret.get_arg_name(), str(e)))
            return outstr
        except Exception as e:
            mwmon.printer(traceback.print_exc())
            mwmon.printer(str(e))


def opcodes_ret(addr_from, addr_to, data, callback_name, argument_parser, mod, fun, proc, cpu_index, cpu):
    from mw_monitor_classes import mwmon
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8
    try:
        mwmon.cm.rm_callback(callback_name)
        if TARGET_LONG_SIZE == 4:
            argument_parser.update_return(cpu.EAX)
        elif TARGET_LONG_SIZE == 8:
            argument_parser.update_return(cpu.RAX)
        data.out_args = [arg for arg in argument_parser.get_out_args()]
        data.ret = argument_parser.get_ret()
        proc.add_call(addr_from, addr_to, data)
    except Exception as e:
        mwmon.printer("Exception: %s" % str(e))
    finally:
        return


def opcodes(cpu_index, cpu, pc, next_pc, db, proc):
    from mw_monitor_classes import mwmon
    from mw_monitor_classes import is_in_pending_resolution
    from api import CallbackManager
    import api
    from DeviareDbParser import ArgumentParser

    TARGET_LONG_SIZE = api.get_os_bits() / 8

    # First, check if the next_pc is located in a module with
    # pending symbol resolution, and update symbols
    # accordingly
    if is_in_pending_resolution(proc.get_pgd(), next_pc):
        proc.update_symbols()

    try:
        # Locate nearest lower symbol
        sym = proc.locate_nearest_symbol(next_pc)
        if sym is None:
            return
        mod = sym.get_mod()
        fun = sym.get_fun()
        real_api_addr = sym.get_addr()
        # Reduce FP's by checking that the origin EIP is not also within the
        # same module (code reuse inside the dll)
        if mod in proc.modules:
            for (base, size) in proc.modules[mod]:
                if pc >= base and pc <= (base + size):
                    return

        # First shortcut: check if it is an excluded api/module, or included:
        if mwmon.exclude_apis_addrs is not None and len(mwmon.exclude_apis_addrs) > 0:
            if real_api_addr in mwmon.exclude_apis_addrs:
                return

        if mwmon.exclude_modules_addrs is not None and len(mwmon.exclude_modules_addrs) > 0:
            for (base, size) in mwmon.exclude_modules_addrs:
                if real_api_addr >= base and real_api_addr < (base + size):
                    return

        # Origin modules
        if mwmon.exclude_origin_modules_addrs is not None and len(mwmon.exclude_origin_modules_addrs) > 0:
            # pc is the originating pc
            for (base, size) in mwmon.exclude_origin_modules_addrs:
                if pc >= base and pc < (base + size):
                    return

        if mwmon.include_apis_addrs is not None and len(mwmon.include_apis_addrs) > 0:
            if real_api_addr not in mwmon.include_apis_addrs:
                return

        if proc.in_mod_boundaries(real_api_addr):

            pgd = api.get_running_process(cpu_index)

            # Set callback on return address
            if TARGET_LONG_SIZE == 4:
                try:
                    ret_addr_val = api.r_va(pgd, cpu.ESP, 4)
                    ret_addr = struct.unpack("<I", ret_addr_val)[0]
                except:
                    ret_addr = 0
                    mwmon.printer("Could not read return address on API tracer")
            elif TARGET_LONG_SIZE == 8:
                try:
                    ret_addr_val = api.r_va(pgd, cpu.RSP, 8)
                    ret_addr = struct.unpack("<Q", ret_addr_val)[0]
                except:
                    ret_addr = 0 
                    mwmon.printer("Could not read return address on API tracer")

            if mwmon.api_tracer_light_mode:
                if real_api_addr == next_pc:
                    if TARGET_LONG_SIZE == 4:
                        proc.add_call(pc, real_api_addr, "[PID: %x] %08x --> %s:%s(%08x) --> %08x\n" % (
                            proc.pid, pc, mod, fun, real_api_addr, ret_addr))
                    elif TARGET_LONG_SIZE == 8:
                        proc.add_call(pc, real_api_addr, "[PID: %x] %016x --> %s:%s(%016x) --> %016x\n" % (
                            proc.pid, pc, mod, fun, real_api_addr, ret_addr))
                else:
                    if TARGET_LONG_SIZE == 4:
                        proc.add_call(pc, real_api_addr, "[PID: %x] %08x --> %s:%s(+%x)(%08x) --> %08x\n" % (
                            proc.pid, pc, mod, fun, (next_pc - real_api_addr), next_pc, ret_addr))
                    elif TARGET_LONG_SIZE == 8:
                        proc.add_call(pc, real_api_addr, "[PID: %x] %016x --> %s:%s(+%x)(%016x) --> %016x\n" % (
                            proc.pid, pc, mod, fun, (next_pc - real_api_addr), next_pc, ret_addr))
                return

            data = APICallData()
            data.pc = pc
            data.mod = mod
            data.fun = fun
            data.ret_addr = ret_addr

            if TARGET_LONG_SIZE == 4:
                argument_parser = ArgumentParser(db, cpu, cpu.ESP, mod, fun)
            elif TARGET_LONG_SIZE == 8:
                argument_parser = ArgumentParser(db, cpu, cpu.RSP, mod, fun)

            if not argument_parser.in_db():
                return

            data.in_args = [arg for arg in argument_parser.get_in_args()]

            # If return address could not be read, we skip the callback
            if ret_addr != 0:
                callback_name = "ret_bp_%d" % mwmon.bp_counter

                callback = functools.partial(opcodes_ret,
                                             pc,
                                             real_api_addr,
                                             data,
                                             callback_name,
                                             argument_parser,
                                             mod,
                                             fun,
                                             proc)

                mwmon.cm.add_callback(CallbackManager.INSN_BEGIN_CB,
                                      callback,
                                      name=callback_name,
                                      addr=data.ret_addr,
                                      pgd=pgd)

                mwmon.bp_counter += 1

    except Exception as e:
        mwmon.printer(str(e))
        traceback.print_exc()
    finally:
        return


def apitracer_start_monitoring_process(proc):
    from mw_monitor_classes import mwmon
    from api import CallbackManager

    mwmon.printer("Initializing API tracer...")

    """
    # E8 - call, E9,EA,EB - jmp
    mwmon.cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(
        opcodes, db=mwmon.db, proc=proc), name="opcode1_%x" % (proc.pid), start_opcode=0xE8, end_opcode=0xEB)
    mwmon.cm.add_trigger("opcode1_%x" %
                         (proc.get_pid()), "triggers/trigger_opcode_user_only.so")
    mwmon.cm.set_trigger_var("opcode1_%x" %
                             (proc.get_pid()), "cr3", proc.get_pgd())
    """
    # FF - call and jmp
    mwmon.cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(
        opcodes, db=mwmon.db, proc=proc), name="opcode2_%x" % (proc.pid), start_opcode=0xFF, end_opcode=0xFF)
    mwmon.cm.add_trigger("opcode2_%x" %
                         (proc.get_pid()), "triggers/trigger_opcode_user_only.so")
    mwmon.cm.set_trigger_var("opcode2_%x" %
                             (proc.get_pid()), "cr3", proc.get_pgd())
    """
    # 9A - call
    mwmon.cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(
        opcodes, db=mwmon.db, proc=proc), name="opcode3_%x" % (proc.pid), start_opcode=0x9A, end_opcode=0x9A)
    mwmon.cm.add_trigger("opcode3_%x" %
                         (proc.get_pid()), "triggers/trigger_opcode_user_only.so")
    mwmon.cm.set_trigger_var("opcode3_%x" %
                             (proc.get_pid()), "cr3", proc.get_pgd())
    """
    """
    # C2 - C3 - ret
    mwmon.cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(
        opcodes, db=mwmon.db, proc=proc), name="opcode4_%x" % (proc.pid), start_opcode=0xC2, end_opcode=0xC3)
    mwmon.cm.add_trigger("opcode4_%x" %
                         (proc.get_pid()), "triggers/trigger_opcode_user_only.so")
    mwmon.cm.set_trigger_var("opcode4_%x" %
                             (proc.get_pid()), "cr3", proc.get_pgd())
    # CA - CB - ret
    mwmon.cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(
        opcodes, db=mwmon.db, proc=proc), name="opcode5_%x" % (proc.pid), start_opcode=0xCA, end_opcode=0xCB)
    mwmon.cm.add_trigger("opcode5_%x" %
                         (proc.get_pid()), "triggers/trigger_opcode_user_only.so")
    mwmon.cm.set_trigger_var("opcode5_%x" %
                             (proc.get_pid()), "cr3", proc.get_pgd())
    """
