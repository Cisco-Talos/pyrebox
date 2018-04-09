# -------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
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

# Main imports

import struct
import re
import sys
import termios
import functools
import textwrap
import fnmatch
import traceback
import inspect

# IPython related imports

from IPython.core.magic import (Magics, magics_class, line_magic)
from IPython.core.autocall import IPyAutocall
from IPython.terminal.embed import InteractiveShellEmbed
from traitlets.config import Config
from IPython.terminal.prompts import Prompts, Token

# Some packages

from prettytable import PrettyTable
from capstone import Cs
from capstone import CS_ARCH_X86
from capstone import CS_MODE_32
from capstone import CS_MODE_64


import volatility.registry as registry
import volatility.commands as commands
import volatility.obj as obj

# Pyrebox imports

import api
from cpus import X86CPU
from cpus import X64CPU
from utils import ConfigurationManager as conf_m
from utils import pp_print
from utils import pp_debug
from utils import pp_warning
from utils import pp_error

# Third party utils

import third_party.python_modules.hexdump
from third_party.viper.strings import Strings

# Some globals
__shell = None
__cfg = None
__proc_prompt = None
__local_ns = None
__added_commands = {}

# Counter for the last BP inserted
last_bp = -1


class Proc:
    '''
    Class used internally to store processes
    '''

    def __init__(self, pid, pgd):
        self.pid = pid
        self.pgd = pgd

    def get_pid(self):
        return self.pid

    def get_pgd(self):
        return self.pgd


def vol_command_help(command):
    outputs = []
    for item in dir(command):
        if item.startswith("render_"):
            outputs.append(item.split("render_", 1)[-1])
    outputopts = "\nModule Output Options: " + \
        "{0}\n".format("{0}".format("\n".join([", ".join(o for o in sorted(outputs))])))

    result = textwrap.dedent("""
    ---------------------------------
    Module {0}
    ---------------------------------\n""".format(command.__class__.__name__))

    return outputopts + result + command.help() + "\n\n"


def vol_execute_command(cmds, cmdname, config, line):
    sys.argv = line.split()
    sys.argv = [cmdname] + sys.argv
    try:
        if config.parse_options():
            c = cmds[cmdname](config)
            # Register the help cb from the command itself
            config.set_help_hook(functools.partial(vol_command_help, c))
            c.execute()
    except Exception as e:
        pp_error(
            "VolShell: Error while executing volatility command\n%s\n" %
            str(e))


def vol_generate_commands(config):
    command_list = {}
    cmds = registry.get_plugin_classes(commands.Command, lower=True)
    profs = registry.get_plugin_classes(obj.Profile)

    if config.PROFILE not in profs:
        pp_error("Invalid profile " + config.PROFILE + " selected\n")
        return True
    profile = profs[config.PROFILE]()
    for cmdname in sorted(cmds):
        command = cmds[cmdname]
        if command.is_valid_profile(profile):
            command_list[cmdname] = functools.partial(
                vol_execute_command, cmds, cmdname, config)

    return command_list


class ProcPrompt(Prompts):

    def __init__(self, shell, **kwargs):
        super(ProcPrompt, self).__init__(shell, **kwargs)
        self.val = None

    def in_prompt_tokens(self, cli=None):
        if self.val is None:
            return [(Token, "["), (Token.PromptNum, str(
                self.shell.execution_count)), (Token, "] pyrebox"), (Token.Prompt, "> ")]
        else:
            return [
                (
                    Token, "["), (Token.PromptNum, str(
                        self.shell.execution_count)), (Token, "] pyrebox("), (Token.PromptNum, "%x" %
                                                                              self.val), (Token, ")"), (Token.Prompt, "> ")]

    def continuation_prompt_tokens(self, cli=None, width=None):
        if width is None:
            width = self._width()
        return [(Token.Prompt, (' ' * (width - 2)) + u'> '), ]

    def out_prompt_tokens(self):
        width = self._width()
        spaces = width - 7 - len(str(self.shell.execution_count))
        return [(Token, "["), (Token.PromptNum, str(self.shell.execution_count)),
                (Token, "]" + " " * spaces + "out"), (Token.Prompt, "> ")]

    def set_proc(self, proc):
        self.val = proc


@magics_class
class ShellMagics(Magics):
    # Class variables
    bps = {}

    def __init__(self, shell=None, **kwargs):
        super(ShellMagics, self).__init__(shell=shell, **kwargs)
        self.cpu_index = 0
        self.vol_conf = None
        self.vol_commands = None
        self.initialize()

    def update_conf(self):
        if "__cpu_index" in self.shell.user_ns:
            self.cpu_index = self.shell.user_ns["__cpu_index"]
        else:
            self.cpu_index = 0

        if "__vol_conf" in self.shell.user_ns:
            self.vol_conf = self.shell.user_ns["__vol_conf"]
            if self.vol_conf is not None and self.vol_commands is None:
                self.vol_commands = vol_generate_commands(self.vol_conf)
        else:
            self.vol_conf = None

    def initialize(self):
        self.update_conf()
        self.proc_context = None
        self.symbols = None
        if conf_m.platform == "i386-softmmu":
            cpu = X86CPU()
        elif conf_m.platform == "x86_64-softmmu":
            cpu = X64CPU()
        else:
            raise RuntimeError(
                "[ShellMagics.initialize] Wrong platform specification")
            return None

        self.regs = []
        for el in inspect.getmembers(cpu):
            self.regs.append(el[0])

    # ===================================================== Helpers ===========

    def find_procs(self, param):
        '''
        Return processes that match the parameter by pid, pgd, or name
        '''
        from utils import find_procs
        return find_procs(param)

    def find_syms(self, name):
        '''
        Return symbols that match the given parameter (by module or function name), case insensitive.
        '''
        if self.symbols is None:
            try:
                self.symbols = api.get_symbol_list()
            except BaseException:
                traceback.print_exc()
                return []
        pp_debug("[*] Searching for symbols with name %s\n" % str(name))
        found = []
        if name == "":
            found = self.symbols
        elif "!" in name:
            toks = name.split("!")
            m = toks[0]
            f = toks[1]
            for d in self.symbols:
                mod_name = d["mod"]
                f_name = d["name"]
                addr = d["addr"]
                if (m.lower() in mod_name.lower() or fnmatch.fnmatch(mod_name.lower(), m.lower())) and (
                        f.lower() in f_name.lower() or fnmatch.fnmatch(f_name.lower(), f.lower())):
                    found.append((mod_name, f_name, addr))
        else:
            for d in self.symbols:
                mod_name = d["mod"]
                f_name = d["name"]
                addr = d["addr"]
                if name.lower() in mod_name.lower() or fnmatch.fnmatch(
                        mod_name.lower(), name.lower()):
                    found.append(d)
                    continue
                if name.lower() in f_name.lower() or fnmatch.fnmatch(f_name.lower(), name.lower()):
                    found.append(d)
        return found

    def get_val(self, line):
        '''
            Helper, return a value given a parameter line.
        '''
        val = None
        if line == "":
            pp_warning(
                "Please, specify value in hex (default), decimal (e.g., \d12345), or symbol name \n")
        else:
            param = line.split()[0]
            try:
                if "\\d" == param[0:2] and param[2:].isdigit():
                    val = int(param[2:])
                else:
                    # Try to parse as hex
                    try:
                        val = int(param, 16)
                    except BaseException:
                        pass
                if val is None:
                    mods = {}
                    # If process is set, get the base address for all the
                    # modules:
                    if self.proc_context is not None:
                        for m in api.get_module_list(self.proc_context.get_pgd()):
                            mods[m["name"].lower()] = m["base"]
                    # Try to resolve symbol
                    found = []
                    for sym in self.find_syms(param):
                        found.append(sym)
                        if len(found) > 1:
                            pp_warning(
                                "Several matches for specified pattern\n")
                            self.x(param)
                            return
                    if len(found) == 0:
                        pp_warning(
                            "Tried to resolve symbol %s, but not found\n" %
                            (param))
                    else:
                        sym = found[0]
                        val = (sym["addr"] if sym["mod"].lower(
                        ) not in mods else sym["addr"] + mods[sym["mod"].lower()])
            except BaseException:
                val = None
                pass
            if val is None:
                pp_error(
                    "Incorrect val specified, please use val in hex (default), decimal (e.g., \d12345), or symbol name\n")
        return val

    def get_nearest_symbols(self, addr):
        '''
            Helper, get nearest symbols
        '''
        mods = {}
        # If process is set, get the base address for all the modules:
        if self.proc_context is not None:
            for m in api.get_module_list(self.proc_context.get_pgd()):
                mods[m["name"].lower()] = m["base"]

        # Read symbols near the address given:
        nearest_low = None
        nearest_high = None
        # Set a 0x1000 bracket to search for symbols
        start_addr = addr - 0x1000
        end_addr = addr + 0x1000
        for d in self.find_syms(""):
            mod_name = d["mod"]
            f_name = d["name"]
            saddr = d["addr"]
            if mod_name.lower() in mods:
                saddr = saddr + mods[mod_name.lower()]
            if saddr >= start_addr and saddr <= end_addr:
                if saddr <= addr and (
                        nearest_low is None or saddr > nearest_low[2]):
                    nearest_low = (mod_name, f_name, saddr)
                if saddr >= addr and (
                        nearest_high is None or saddr < nearest_high[2]):
                    nearest_high = (mod_name, f_name, saddr)

        return (nearest_low, nearest_high)

    def find_regs(self, reg):
        '''
        Find regisers that match the reg string passed as parameter
        '''
        found = []
        for regname in self.regs:
            if reg.lower() in regname.lower():
                found.append(regname)
        return found

    def get_port_param(self, line):
        '''
        Helper to parse parameters in the form: 0x7c313452
        '''
        if line == "":
            return None

        addr = self.get_val(line)
        if addr is None:
            return None

        return addr

    def get_addr_size_param(self, line):
        '''
        Helper to parse parameters in the form: [p]0x7c313452:0x100
        '''
        if line == "":
            return None, None, None
        params = re.split(" |\t|:", line)
        if len(params) < 1:
            return None, None, None

        physical = False
        addr = 0
        if params[0][0] == "p":
            physical = True
            addr = self.get_val(params[0][1:])
        else:
            addr = self.get_val(params[0])
        if addr is None:
            return None, None, None

        # Set a default size
        size = 512
        if len(params) == 2:
            size = self.get_val(params[1])

        return addr, size, physical

    def get_addr_content_param(self, line):
        '''
        Helper to parse parameters in the form:
            [p]0x7c212312=DEADBEEF
            [p]0x7c212312="this is a test"
            [p]0x7c212312=u"this is a test"
        '''
        if line == "":
            return None, None, None
        params = re.split("=", line)
        if len(params) < 2:
            pp_error("Incorrect number of parameters\n")
            return None, None, None
        physical = False
        addr = 0
        if params[0][0] == "p":
            physical = True
            addr = self.get_val(params[0][1:])
        else:
            addr = self.get_val(params[0])
        if addr is None:
            pp_error("Invalid address\n")
            return None, None, None

        val = ""
        is_utf = False
        if params[1].strip()[0] == '"' or params[1].strip()[0] == 'u':
            is_utf = (params[1].strip()[0] == 'u')
            for el in params[1:]:
                val += el
            if is_utf:
                val = val.strip()[2:-1]
            else:
                val = val.strip()[1:-1]
        else:
            for i in range(0, len(params[1]), 2):
                val += struct.pack("B", int(params[1][i:i + 2], 16))
        if len(val) == 0:
            pp_error("Unspecified value\n")
            return None, None, None
        if is_utf:
            val = val.encode("utf-16")[2:]

        return addr, val, physical

    def get_addr_size_pattern_param(self, line):
        '''
        Helper to parse parameters in the form:
            Format: s <addr>:<size>:<pattern>
            Example: s [p]0x00000000:0xFFFFFFFF:A0B0C0D0
                     s [p]0x00000000:0xFFFFFFFF:"some string"
                     s [p]0x00000000:0xFFFFFFFF:u"some string" for UTF-16 strings
        '''
        if line == "":
            return None, None, None, None
        params = re.split(":", line)
        if len(params) < 3:
            return None, None, None, None
        physical = False
        addr = 0
        if params[0][0] == "p":
            physical = True
            addr = self.get_val(params[0][1:])
        else:
            if self.proc_context is None:
                pp_warning("Specify process context (proc command)\n")
                return None, None, None, None
            addr = self.get_val(params[0])
        if addr is None:
            return None, None, None, None

        size = self.get_val(params[1])
        if size is None:
            return None, None, None, None

        pattern = ""
        is_utf = False
        if params[2].strip()[0] == '"' or params[2].strip()[0] == 'u':
            is_utf = (params[2].strip()[0] == 'u')
            for el in params[2:]:
                pattern += el
            if is_utf:
                pattern = pattern.strip()[2:-1]
            else:
                pattern = pattern.strip()[1:-1]
        else:
            for i in range(0, len(params[2]), 2):
                pattern += struct.pack("B", int(params[2][i:i + 2], 16))

        if len(pattern) == 0:
            pp_error("Unspecified pattern\n")
            return None, None, None, None
        if is_utf:
            # Encode and remove first byte order characters
            pattern = pattern.encode("utf-16")[2:]
        return addr, size, pattern, physical

    def disassemble(self, addr, nb, physical):
        # Capstone disassembler
        md = None

        if conf_m.platform == "i386-softmmu":
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif conf_m.platform == "x86_64-softmmu":
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            pp_error("[disassemble] Wrong platform specification\n")
            return None

        content = ""
        if physical:
            content = api.r_pa(addr, 0x1000)
        else:
            if self.proc_context is None:
                pp_warning("Specify process context (proc command)\n")
                return

            # Try to read 0x1000 bytes
            # First, read until the page boundary
            to_read = 0x1000 - (addr & 0xFFF)
            try:
                content += api.r_va(self.proc_context.get_pgd(), addr, to_read)
            except:
                pp_warning("Could not read memory at address %x, is it paged out?\n" % addr)

            if len(content) > 0 and to_read < 0x1000:
                try:
                    content += api.r_va(self.proc_context.get_pgd(), addr + to_read, 0x1000 - to_read)
                except:
                    pp_warning("Could not read memory at address %x, is it paged out?\n" % (addr + to_read))

        counter = 0
        base = 0
        for i in md.disasm(content, addr):
            if counter >= nb:
                break
            pp_print("0x%x:\t%s\t%s\t%s\n" % (i.address, "".join([(("%02x " % ord(
                content[base + e])) if e < i.size else "   ") for e in range(0, 15)]), i.mnemonic, i.op_str))
            base += i.size
            counter += 1

    def do_help(self, command):
        if isinstance(command, str) or isinstance(command, unicode):
            f = getattr(self, command)
            if f:
                pp_print(f.__doc__)

    # ===================================================== Commands ==========

    @line_magic
    def proc(self, line):
        '''
        Specify a process pid, pgd, or name to set the context.
        '''
        if line == "":
            pp_warning("Please, specify pid, pgd, or process name\n")
            return
        param = line.split()[0]
        found = self.find_procs(param)
        if len(found) == 0:
            pp_warning("Process %s not found\n" % param)
        elif len(found) == 1 or (len(found) == 2 and found[0][1] == found[1][1]):
            if found[0][0] == 0:
                # kernel process
                pid, pgd, pname = found[1]
            else:
                pid, pgd, pname = found[0]
            self.proc_context = Proc(pid, pgd)
            pp_print("Process set to %x:%x:%s\n" % (pid, pgd, pname))
            self.shell.prompts.set_proc(pid)
        else:
            pp_warning(
                "%d processes match, please select one...\n" %
                len(found))
            self.ps(line)

    @line_magic
    def setcpu(self, line):
        '''
        Specify a cpu for all the cpu dependant commands (r_cpu, r, etc...)
        '''
        if line == "":
            pp_warning("Current cpu is %d\n" % self.cpu_index)
            return
        else:
            try:
                new_index = int(line.strip())
            except BaseException:
                pp_warning(
                    "Incorrect index specified, current cpu is %d\n" %
                    self.cpu_index)
                return
            self.cpu_index = new_index
            pp_print("CPU index set to %d\n" % new_index)

    @line_magic
    def ps(self, line):
        '''
        List processes, optionally specify name, pgd or pid to filter.
        '''
        nb = None
        name = None
        if line != "":
            param = line.split()[0]
            try:
                nb = int(param, 16)
            except BaseException:
                name = param

        proc_list = api.get_process_list()
        t = PrettyTable(["Name", "Running", "Monitored", "PID", "PGD"])
        t.align["PID"] = "r"
        t.align["PGD"] = "r"
        # t.align["Nb modules"] = "r"
        running_pgd = []
        is_kernel = []
        for i in range(0, api.get_num_cpus()):
            running_pgd.append(api.get_running_process(i))
            is_kernel.append(api.is_kernel_running(i))
            pp_print("CPU %d PGD: %x InKernel: %d\n" %
                     (i, api.get_running_process(i), api.is_kernel_running(i)))
        for proc in proc_list:
            pid = proc["pid"]
            pgd = proc["pgd"]
            pname = proc["name"]
            # k_addr = proc["kaddr"]

            include = False
            include = include or (nb is None and name is None)
            include = include or (nb is not None and (nb == pid or nb == pgd))
            include = include or (
                name is not None and (
                    fnmatch.fnmatch(
                        pname,
                        name) or name in pname))
            if include:
                if self.proc_context is not None and self.proc_context.get_pid() == pid:
                    pname = ">> " + pname + " <<"
                running_str = ""
                if pgd in running_pgd:
                    i = running_pgd.index(pgd)
                    if is_kernel[i]:
                        running_str = "(%d-k)" % (i)
                    else:
                        # Do not mark the kernel as running if we are in user
                        # mode
                        if pid != 0:
                            running_str = "(%d-u)" % (i)
                t.add_row([pname,
                           running_str,
                           "*" if api.is_monitored_process(pgd) else "",
                           "%016x" % pid,
                           ("%016x") % pgd if pgd != 0 else "----"])
        pp_print(str(t) + "\n")

    @line_magic
    def lm(self, line):
        '''
        List modules, specify name, pgd, or pid
        '''
        if line == "":
            pp_warning("Please, specify pid, pgd, or process name." +
                       " Specify '0', 'System' or 'kernel' in order to list kernel modules\n")
            return
        param = line.split()[0]
        if (param.isdigit() and int(param) == 0) or param == "System" or param == "kernel":
            pid = 0
            pgd = 0
            pname = "kernel"
        else:
            found = self.find_procs(param)
            if len(found) == 0:
                pp_warning("Process %s not found\n" % param)
                return
            elif len(found) == 1:
                pid, pgd, pname = found[0]
                if pname == "System":
                    # pid = 0
                    pgd = 0
                    pname = "kernel"
            else:
                pp_warning(
                    "%d processes match, please select one...\n" %
                    len(found))
                self.ps(line)
                return

        t = PrettyTable(["Name", "Base", "Size"])
        t.align["Base"] = "r"
        t.align["Size"] = "r"
        for m in sorted(api.get_module_list(pgd), key=lambda k: k['base']):
            t.add_row([m["name"], "%016x" % m["base"], "%016x" % m["size"]])
        pp_print(str(t) + "\n")

    # ===================================================== Process monitoring

    @line_magic
    def mon(self, line):
        '''
        Start monitoring process , specify name, pgd, or pid
        '''
        if line == "":
            pp_warning("Please, specify pid, pgd, or process name\n")
            return
        param = line.split()[0]
        found = self.find_procs(param)
        if len(found) == 0:
            pp_warning("Process %s not found\n" % param)
        elif len(found) == 1:
            pid, pgd, pname = found[0]
            api.start_monitoring_process(pgd)
        else:
            pp_warning(
                "%d processes match, please select one...\n" %
                len(found))
            self.ps(line)

    @line_magic
    def unmon(self, line):
        '''
        Stop monitoring process , specify name, pgd, or pid
        '''
        if line == "":
            pp_warning("Please, specify pid, pgd, or process name\n")
            return
        param = line.split()[0]
        found = self.find_procs(param)
        if len(found) == 0:
            pp_warning("Process %s not found\n" % param)
        elif len(found) == 1:
            pid, pgd, pname = found[0]
            api.stop_monitoring_process(pgd, True)
        else:
            pp_warning(
                "%d processes match, please select one...\n" %
                len(found))
            self.ps(line)

    # ===================================================== Symbol resolv  ====

    @line_magic
    def x(self, line):
        '''
        List addresses corresponding to symbols that match the given symbol (wildcards accepted). Dll and function name
        separated by |.
        '''
        if line == "":
            pp_warning(
                "Please, specify module name, or function name. If both, separate with !\n")
            return
        param = line.split()[0]

        mods = {}

        # Get the base address for all the kernel modules
        for m in api.get_module_list(0):
            mods[m["name"].lower()] = m["base"]

        # If process is set, get the base address for all the modules:
        if self.proc_context is not None:
            for m in api.get_module_list(self.proc_context.get_pgd()):
                mods[m["name"].lower()] = m["base"]
        t = PrettyTable(["Module", "Function", "Address"])
        t.align["Address"] = "r"
        for sym in self.find_syms(param):
            t.add_row([sym["mod"], sym["name"], "%016x" % (sym["addr"] if sym["mod"].lower(
            ) not in mods else sym["addr"] + mods[sym["mod"].lower()])])
        pp_print(str(t) + "\n")

    @line_magic
    def ln(self, line):
        '''
        Display symbols near the given address, given in hex or decimal.
        '''
        addr = self.get_val(line)
        if addr is None:
            return

        nearest_low, nearest_high = self.get_nearest_symbols(addr)

        if nearest_low is not None:
            pp_print(
                "===> %s:%s (+0x%x)\n" %
                (nearest_low[0], nearest_low[1], (addr - nearest_low[2])))
        if nearest_high is not None:
            pp_print(
                "===> %s:%s (-0x%x)\n" %
                (nearest_high[0], nearest_high[1], (nearest_high[2] - addr)))
        if nearest_low is None and nearest_high is None:
            pp_print("No symbols found near addr 0x%016x\n" % (addr))

    # ===================================================== Memory/Reg read/wri

    @line_magic
    def r(self, line):
        '''
        Read or write a register. E.g.: r EAX / r EAX=0x00000000
        '''
        if line == "":
            self.do_help("r")
        elif "=" in line:
            # assignment to one register
            params = re.split(" |\t|=", line)
            if len(params) != 2:
                pp_error("Incorrect format for register assignment\n")
                return
            found = self.find_regs(params[0])
            if len(found) == 0:
                pp_error("Specify a valid register name\n")
                return
            elif len(found) > 1:
                pp_warning("Parameter matches several registers...\n")
                for reg in found:
                    pp_warning(reg + "\n")
            else:
                # Use get_val function to parse the value, so we can accept
                # decimal, hexadecimal, and symbols
                val = self.get_val(params[1])
                if val is None:
                    return
                api.w_r(self.cpu_index, found[0], val)
                pp_print("Register %s modified\n" % found[0])
        else:
            # display one register
            param = line.split()[0]
            found = self.find_regs(param)
            if len(found) == 0:
                pp_error("Specify a valid register name\n")
                return
            elif len(found) > 1:
                pp_warning("Parameter matches several registers...\n")
                for reg in found:
                    pp_warning(reg + "\n")
            else:
                cpu = api.r_cpu(self.cpu_index)
                pp_print("CPU: %d %s:   %016x\n" %
                         (self.cpu_index, found[0], getattr(cpu, found[0])))

    @line_magic
    def db(self, line):
        '''
        Display memory, p denotes physical address, repeat N times.  Format: db [p]<addr>:<N>
        '''
        addr, repeat, physical = self.get_addr_size_param(line)
        if addr is None:
            self.do_help("db")
            return
        size = 1
        for i in range(0, repeat):
            if physical:
                content = api.r_pa(addr + (size * i), size)
            else:
                if self.proc_context is None:
                    pp_warning("Specify process context (proc command)\n")
                    return
                content = ""
                try:
                    content = api.r_va(self.proc_context.get_pgd(),
                                       addr + (size * i), size)
                except:
                    pp_warning("Could not read memory at address %x, is it paged out?\n" % (addr + (size * i)))
                    break
            third_party.python_modules.hexdump.hexdump(
                content, addr + (size * i))

    @line_magic
    def dw(self, line):
        '''
        Display memory, p denotes physical address, repeat N times.  Format: dw [p]<addr>:<N>
        '''
        addr, repeat, physical = self.get_addr_size_param(line)
        if addr is None:
            self.do_help("dw")
            return
        size = 2
        for i in range(0, repeat):
            if physical:
                content = api.r_pa(addr + (size * i), size)
            else:
                if self.proc_context is None:
                    pp_warning("Specify process context (proc command)\n")
                    return
                content = ""
                try:
                    content = api.r_va(self.proc_context.get_pgd(),
                                       addr + (size * i), size)
                except:
                    pp_warning("Could not read memory at address %x, is it paged out?\n" % (addr + (size * i)))
                    break
            third_party.python_modules.hexdump.hexdump(
                content, addr + (size * i))

    @line_magic
    def iorb(self, line):
        '''
        Read IO Port, 1 byte. Format: iodb <port addr>
        '''
        addr = self.get_port_param(line)
        if addr is None:
            self.do_help("iorb")
            return
        size = 1
        val = api.r_ioport(addr, size)
        pp_print("Port [0x%04x] = 0x%02x\n" % (addr, val))

    @line_magic
    def iorw(self, line):
        '''
        Read IO Port, 2 byte. Format: iorw <port addr>
        '''
        addr = self.get_port_param(line)
        if addr is None:
            self.do_help("iorw")
            return
        size = 2
        val = api.r_ioport(addr, size)
        pp_print("Port [0x%04x] = 0x%04x\n" % (addr, val))

    @line_magic
    def iord(self, line):
        '''
        Read IO Port, 4 byte. Format: iord <port addr>
        '''
        addr = self.get_port_param(line)
        if addr is None:
            self.do_help("iord")
            return
        size = 4
        val = api.r_ioport(addr, size)
        pp_print("Port [0x%04x] = 0x%016x\n" % (addr, val))

    @line_magic
    def iowb(self, line):
        '''
        Write IO Port, 1 byte. Format: iowb <port addr>=<val>
        '''
        addr, buf, physical = self.get_addr_content_param(line)

        size = 1

        if addr is None:
            self.do_help("iowb")
            return

        if len(buf) != size:
            pp_error("Incorrect value size\n")
            self.do_help("iowb")
            return

        val = struct.unpack("<B", buf)[0]

        api.w_ioport(addr, size, val)
        pp_print("Port [0x%04x] = 0x%02x\n" % (addr, val))

    @line_magic
    def ioww(self, line):
        '''
        Write IO Port, 2 byte. Format: ioww <port addr>=<val>
        '''
        addr, buf, physical = self.get_addr_content_param(line)

        size = 2

        if addr is None:
            self.do_help("ioww")
            return

        if len(buf) != size:
            pp_error("Incorrect value size\n")
            self.do_help("ioww")
            return

        val = struct.unpack("<H", buf)[0]

        api.w_ioport(addr, size, val)
        pp_print("Port [0x%04x] = 0x%04x\n" % (addr, val))

    @line_magic
    def iowd(self, line):
        '''
        Write IO Port, 4 bytes. Format: iowd <port addr>=<val>
        '''
        addr, buf, physical = self.get_addr_content_param(line)

        size = 4

        if addr is None:
            self.do_help("iowd")
            return

        if len(buf) != size:
            pp_error("Incorrect value size\n")
            self.do_help("iowd")
            return

        val = struct.unpack("<I", buf)[0]

        api.w_ioport(addr, size, val)
        pp_print("Port [0x%04x] = 0x%016x\n" % (addr, val))

    @line_magic
    def dd(self, line):
        '''
        Display memory, p denotes physical address, repeat N times.  Format: dd [p]<addr>:<N>
        '''
        addr, repeat, physical = self.get_addr_size_param(line)
        if addr is None:
            self.do_help("dd")
            return
        size = 4
        for i in range(0, repeat):
            if physical:
                content = api.r_pa(addr + (size * i), size)
            else:
                if self.proc_context is None:
                    pp_warning("Specify process context (proc command)\n")
                    return
                content = ""
                try:
                    content = api.r_va(self.proc_context.get_pgd(),
                                       addr + (size * i), size)
                except:
                    pp_warning("Could not read memory at address %x, is it paged out?\n" % (addr + (size * i)))
                    break
            third_party.python_modules.hexdump.hexdump(
                content, addr + (size * i))

    @line_magic
    def dq(self, line):
        '''
        Display memory, p denotes physical address, repeat N times.  Format: dq [p]<addr>:<N>
        '''
        addr, repeat, physical = self.get_addr_size_param(line)
        if addr is None:
            self.do_help("dq")
            return
        size = 8
        for i in range(0, repeat):
            if physical:
                content = api.r_pa(addr + (size * i), size)
            else:
                if self.proc_context is None:
                    pp_warning("Specify process context (proc command)\n")
                    return
                content = ""
                try:
                    content = api.r_va(self.proc_context.get_pgd(),
                                       addr + (size * i), size)
                except:
                    pp_warning("Could not read memory at address %x, is it paged out?\n" % (addr + (size * i)))
                    break
            third_party.python_modules.hexdump.hexdump(
                content, addr + (size * i))

    @line_magic
    def eb(self, line):
        '''
        Edit memory, p denotes physical address. Format: eb [p]0x7c313452=43
        '''

        addr, val, physical = self.get_addr_content_param(line)
        if addr is None:
            self.do_help("eb")
            return
        size = 1
        if len(val) != size:
            pp_error("Incorrect value size\n")
            self.do_help("eb")
            return

        if physical:
            api.w_pa(addr, val, len(val))
        else:
            if self.proc_context is None:
                pp_warning("Specify process context (proc command)\n")
                return
            api.w_va(self.proc_context.get_pgd(), addr, val, len(val))

    @line_magic
    def ew(self, line):
        '''
        Edit memory, p denotes physical address. Format: ew [p]0x7c313452=2343
        '''
        addr, val, physical = self.get_addr_content_param(line)
        if addr is None:
            self.do_help("ew")
            return
        size = 2
        if len(val) != size:
            pp_error("Incorrect value size\n")
            self.do_help("ew")
            return

        if physical:
            api.w_pa(addr, val, len(val))
        else:
            if self.proc_context is None:
                pp_warning("Specify process context (proc command)\n")
                return
            api.w_va(self.proc_context.get_pgd(), addr, val, len(val))

    @line_magic
    def ed(self, line):
        '''
        Edit memory, p denotes physical address. Format: ed [p]0x7c313452=23231243
        '''
        addr, val, physical = self.get_addr_content_param(line)
        if addr is None:
            self.do_help("ed")
            return
        size = 4
        if len(val) != size:
            pp_error("Incorrect value size\n")
            self.do_help("ed")
            return

        if physical:
            api.w_pa(addr, val, len(val))
        else:
            if self.proc_context is None:
                pp_warning("Specify process context (proc command)\n")
                return
            api.w_va(self.proc_context.get_pgd(), addr, val, len(val))

    @line_magic
    def eq(self, line):
        '''
        Edit memory, p denotes physical address. Format: eq [p]0x7c313452=2312342312234556
        '''
        addr, val, physical = self.get_addr_content_param(line)
        if addr is None:
            self.do_help("eq")
            return
        size = 8
        if len(val) != size:
            pp_error("Incorrect value size\n")
            self.do_help("eq")
            return

        if physical:
            api.w_pa(addr, val, len(val))
        else:
            if self.proc_context is None:
                pp_warning("Specify process context (proc command)\n")
                return
            api.w_va(self.proc_context.get_pgd(), addr, val, len(val))

    @line_magic
    def write(self, line):
        '''
        Write buffer to memory address. Format:
            write [p]0x7c313452=DEADBEEF
            write [p]0x7c313452="this is a test"
            write [p]0x7c313452=u"this is a test"  (for UTF-16)
        '''
        addr, val, physical = self.get_addr_content_param(line)
        if addr is None:
            self.do_help("write")
            return

        if physical:
            api.w_pa(addr, val, len(val))
        else:
            if self.proc_context is None:
                pp_warning("Specify process context (proc command)\n")
                return
            api.w_va(self.proc_context.get_pgd(), addr, val, len(val))
        pp_print("%d bytes written\n" % len(val))

    @line_magic
    def dump(self, line):
        '''
        Dump memory, p denotes physical address, size is optional. Format: dump [p]0x7c313452:0x100
        '''
        addr, size, physical = self.get_addr_size_param(line)
        if addr is None:
            self.do_help("dump")
            return

        content = ""
        if physical:
            content = api.r_pa(addr, size)
        else:
            if self.proc_context is None:
                pp_warning("Specify process context (proc command)\n")
                return
            content = ""
            try:
                content = api.r_va(self.proc_context.get_pgd(), addr, size)
            except:
                pp_warning("Could not read memory at address %x, is it paged out?\n" % addr)
        third_party.python_modules.hexdump.hexdump(content, addr)

    @line_magic
    def print_cpu(self, line):
        '''
        Dump cpu, specify cpu index
        '''
        params = line.split()
        cpu_i = 0
        if len(params) != 1:
            pp_warning(
                "Showing results for cpu %d, indicate cpu index otherwise\n" %
                self.cpu_index)
            cpu_i = self.cpu_index
        else:
            try:
                param = params[0]
                cpu_i = int(param)
            except BaseException:
                pp_error("The cpu index specified is not a valid number\n")
                return

        cpu = api.r_cpu(cpu_i)
        pp_print(str(cpu))

    # ===================================================== Disassembly at addr

    @line_magic
    def u(self, line):
        '''
        Disassemble nb instructions at address. Format: u [p]<addr>:<nb>
        '''
        addr, nb, physical = self.get_addr_size_param(line)
        if addr is None:
            self.do_help("u")
            return
        self.disassemble(addr, nb, physical)

    @line_magic
    def dis(self, line):
        '''
        Disassemble nb instructions at EIP, in the context of the process currently running.
        '''
        nb = 20
        if line != "":
            param = line.split()[0]
            try:
                nb = int(param)
            except BaseException:
                try:
                    nb = int(param, 16)
                except BaseException:
                    nb = 20

        # Set proc to running process
        self.proc("0x%x" % api.get_running_process(self.cpu_index))
        # Get eip

        cpu = api.r_cpu(self.cpu_index)
        # Disassemble at eip
        self.disassemble(cpu.PC, nb, False)

    # ===================================================== Display strings of

    @line_magic
    def strings(self, line):
        '''
        Show strings at address. Format: strings [p]<addr>:<size>.
        '''
        addr, size, physical = self.get_addr_size_param(line)
        if addr is None:
            self.do_help("strings")
            return

        # Now, perform search
        found = {}
        strings = Strings()

        pos = addr

        block = ""
        while pos < (addr + size):
            # Read until the page boundary
            block_size = 0x1000 - (pos & 0xFFF)
            block_size = min(block_size, (addr + size - pos))
    
            if physical:
                block += api.r_pa(pos, block_size)
            else:
                try:
                    block += api.r_va(self.proc_context.get_pgd(), pos, block_size)
                except:
                    pp_warning("Could not read memory at address %x, is it paged out?\n" % pos)
                    pos += block_size
                    continue

            pos += block_size

        # Print strings
        items = strings.strings(addr, block)
        for item in items:
            if item not in found or len(
                    item) > len(found[item.pos].string):
                found[item.pos] = item

        for k in sorted(found.keys()):
            pp_print(
                "%s0x%016x: %s %s\n" %
                ("p" if physical else "",
                 found[k].pos,
                 "[HOST]" if found[k].is_host else "",
                 found[k].string))

    @line_magic
    def s(self, line):
        '''
        Search pattern in memory. Format: s <addr>:<size>:<pattern>
            Example: s [p]0x00000000:0xFFFFFFFF:A0B0C0D0
                     s [p]0x00000000:0xFFFFFFFF:"some string"
                     s [p]0x00000000:0xFFFFFFFF:u"some string" for UTF-16 strings

        '''
        addr, size, pattern, physical = self.get_addr_size_pattern_param(line)
        if addr is None:
            self.do_help("s")
            return

        pos = addr

        block = ""
        while pos < (addr + size):
            # Read until the page boundary
            block_size = 0x1000 - (pos & 0xFFF)
            block_size = min(block_size, (addr + size - pos))
    
            if physical:
                block += api.r_pa(pos, block_size)
            else:
                try:
                    block += api.r_va(self.proc_context.get_pgd(), pos, block_size)
                except:
                    pp_warning("Could not read memory at address %x, is it paged out?\n" % pos)
                    pos += block_size
                    continue

            pos += block_size

        # Now, perform search
        found = []

        pos = addr
        m = re.search(pattern, block)
        while m is not None:
            pos = (pos + m.start())
            if pos not in found:
                found.append(pos)
            block = block[m.start() + len(pattern):]
            m = re.search(pattern, block)

        for entry in found:
            pp_print(
                "Pattern found: %s0x%016x\n" %
                ("p" if physical else "", entry))

    # ===================================================== Breakpoints =======

    @line_magic
    def bp(self, line):
        '''
            Set a breakpoint at a given address and launch shell on that breakpoint.
                Usage: bp 0x00401000             - break at 0x00401000.
                       bp 0x00401000:0x1000     - break at any address from 0x00401000 to 0x00402000.
        '''
        global last_bp
        if line == "":
            self.do_help("bp")
            return

        addr, size, physical = (0, 0, False)
        if ":" in line:
            addr, size, physical = self.get_addr_size_param(line)
        else:
            addr = self.get_val(line)

        if addr is None:
            self.do_help("bp")
            return

        if physical or self.proc_context is None:
            pp_warning(
                "Specify a virtual address and a process context (proc command) to set a breakpoint\n")
            return

        last_bp += 1
        self.bps[last_bp] = api.BP(
            addr,
            self.proc_context.get_pgd(),
            size=size,
            typ=api.BP.EXECUTION)
        self.bps[last_bp].enable()

    @line_magic
    def bpw(self, line):
        '''
            Set a memory write breakpoint at a given address and launch shell on that breakpoint.
                Usage: bpw 0x00401000             - break if 0x00401000 is written
                       bpw 0x00401000:0x1000     - break at any memory write from 0x00401000 to 0x00402000.
        '''
        global last_bp
        if line == "":
            self.do_help("bpw")
            return

        addr, size, physical = (0, 0, False)
        if ":" in line:
            addr, size, physical = self.get_addr_size_param(line)
        else:
            addr = self.get_val(line)

        if addr is None:
            self.do_help("bpw")
            return

        if physical or self.proc_context is None:
            pp_warning(
                "Specify a virtual address and a process context (proc command) to set a breakpoint\n")
            return

        last_bp += 1
        self.bps[last_bp] = api.BP(
            addr,
            self.proc_context.get_pgd(),
            size=size,
            typ=api.BP.MEM_WRITE)
        self.bps[last_bp].enable()

    @line_magic
    def bpr(self, line):
        '''
            Set a memory write breakpoint at a given address and launch shell on that breakpoint.
                Usage: bpw 0x00401000             - break if 0x00401000 is written
                       bpw 0x00401000:0x1000     - break at any memory write from 0x00401000 to 0x00402000.
        '''
        global last_bp
        if line == "":
            self.do_help("bpr")
            return

        addr, size, physical = (0, 0, False)
        if ":" in line:
            addr, size, physical = self.get_addr_size_param(line)
        else:
            addr = self.get_val(line)

        if addr is None:
            self.do_help("bpr")
            return

        if physical or self.proc_context is None:
            pp_warning(
                "Specify a virtual address and a process context (proc command) to set a breakpoint\n")
            return

        last_bp += 1
        self.bps[last_bp] = api.BP(
            addr,
            self.proc_context.get_pgd(),
            size=size,
            typ=api.BP.MEM_READ)
        self.bps[last_bp].enable()

    @line_magic
    def bl(self, line):
        '''
        List breakpoints
        '''
        t = PrettyTable(["Nb", "Address", "Proc", "Enabled", "Symbol"])
        for bp_nb in self.bps:
            bp = self.bps[bp_nb]
            # get procname
            proc_list = api.get_process_list()
            procname = ""
            for proc in proc_list:
                # pid = proc["pid"]
                pgd = proc["pgd"]
                pname = proc["name"]
                # k_addr = proc["kaddr"]
                if pgd == bp.get_pgd() and pname != "<kernel>":
                    procname = pname
                    break
            nearest_low, nearest_high = self.get_nearest_symbols(bp.get_addr())
            sym = ""
            if nearest_low is not None:
                sym = "%s:%s (+0x%x)" % (nearest_low[0],
                                         nearest_low[1],
                                         (bp.get_addr() - nearest_low[2]))
            addr_txt = ""
            if bp.get_size <= 1:
                addr_txt = "%016x" % bp.get_addr()
            else:
                addr_txt = "%016x:%x" % (bp.get_addr(), bp.get_size())
            t.add_row([str(bp_nb), addr_txt, procname, str(bp.enabled()), sym])
        pp_print(str(t) + "\n")

    @line_magic
    def bd(self, line):
        '''
        Disable breakpoint
        '''

        if line == "":
            pp_warning("Please, specify breakpoint number\n")
            return
        param = line.split()[0]
        if param == "*":
            for bp in self.bps.keys():
                # If breakpoint is enabled
                if self.bps[bp].enabled():
                    self.bps[bp].disable()
            pp_print("All breakpoints disabled\n")
        else:
            try:
                bp = int(param)
                if bp in self.bps:
                    # If breakpoint is enabled
                    if self.bps[bp].enabled():
                        self.bps[bp].disable()
                    pp_print("Breakpoint %d disabled\n" % (bp))
                else:
                    pp_warning("Breakpoint %d does not exist\n" % (bp))
            except BaseException:
                pp_warning("Please, specify breakpoint number\n")

    @line_magic
    def be(self, line):
        '''
        Enable breakpoint
        '''
        if line == "":
            pp_warning("Please, specify breakpoint number\n")
            return
        param = line.split()[0]
        if param == "*":
            for bp in self.bps.keys():
                if not self.bps[bp].enabled():
                    self.bps[bp].enable()
            pp_print("All breakpoints enabled\n")
        else:
            try:
                bp = int(param)
                if bp in self.bps:
                    if not self.bps[bp].enabled():
                        self.bps[bp].enable()
                    pp_print("Breakpoint %d enabled\n" % (bp))
                else:
                    pp_warning("Breakpoing %d does not exist\n" % (bp))
            except BaseException:
                pp_warning("Please, specify breakpoint number\n")

    # ===================================================== Misc commands  ====

    @line_magic
    def savevm(self, line):
        '''
        Save vm state
        '''
        if line == "":
            pp_warning("Please specify snapshot name\n")
            return
        snapshot_name = line.strip()
        api.save_vm(snapshot_name)

    @line_magic
    def loadvm(self, line):
        '''
        Load vm state
        '''
        if line == "":
            pp_warning("Please specify snapshot name\n")
            return
        snapshot_name = line.strip()
        api.load_vm(snapshot_name)

    @line_magic
    def list_commands(self, line):
        "List all the available pyrebox commands"
        global __added_commands
        global __local_ns
        help_text = """
    MISCELLANEOUS COMMANDS
    ----------------------
    list_commands     - Print this list
    list_vol_commands - List volatility commands_
    vol               - Execute any volatility command. E.g.: vol pslist
    proc              - Select address space of process
    setcpu            - Select CPU to operate on
    mon               - Start monitoring process
    unmon             - Stop monitoring process
    savevm            - Save vm status
    loadvm            - Load vm status
    quit              - Exit this prompt
    q                 - Exit this prompt
    cont              - Exit this prompt
    c                 - Exit this prompt
    ctrl-d            - Exit this prompt

    ?                 - Use it to obtain help for a command. E.g.: ps?
    help(api)         - Get help for the pyrebox API you can import and use in the interactive shell
    help(r_cpu)   - Get help for a specific function of the API

    INSTROSPECTION COMMANDS
    -----------------------
    ps                - List processes
    lm                - List modules
    x                 - Show symbols matching pattern (module!function)
    ln                - List nearest symbols to address

    CPU / MEMORY MANIPULATION
    -------------------------
    r                 - Write register
    db|dw|dd|dq       - Display memory byte, word, dword, qword
    eb|ew|ed|eq       - Edit memory byte, word, dword, qword
    iorb|iorw|iord    - Read IO Port (byte, word, dword)
    iowb|ioww|iowd    - Write IO Port (byte, word, dword)
    write             - Write a buffer to memory
    dump              - Dump a buffer of memory into command line.
    print_cpu         - Show CPU status (registers)

    DISASSEMBLY
    -----------
    dis               - Disassemble N instructions starting from PC, on the context of the running process
    u                 - Disassemble N instructions starting from a given address, on the context of
                        selected address space (proc)

    BREAKPOINTS
    -----------
    bp                - Set execution breakpoint at address(es)
    bpw               - Set memory write breakpoint at address(es)
    bpr               - Set memory read breakpoint at address(es)
    bl                - List breakpoints
    bd                - Disable breakpoint
    be                - Enable breakpoint


    SEARCH
    ------
    strings           - Show printable strings in a given memory area
    s                 - Search for string or byte parttern in a given memory area
        """
        pp_print(help_text)

        # Now print the dynamically imported commands
        list_custom_commands()

    @line_magic
    def list_vol_commands(self, line):
        '''
        List all the available volatility commands
        '''
        config = self.shell.user_ns["__vol_conf"]

        if len(line) == 0:
            result = "\n\tSupported volatility commands:\n\n"
            cmds = registry.get_plugin_classes(commands.Command, lower=True)
            profs = registry.get_plugin_classes(obj.Profile)

            if config.PROFILE not in profs:
                pp_error("Invalid profile " + config.PROFILE + " selected\n")
                return True
            profile = profs[config.PROFILE]()
            wrongprofile = ""

            for cmdname in sorted(cmds):
                command = cmds[cmdname]
                helpline = command.help() or ''
                # Just put the title line (First non empty line) in this
                # abbreviated display
                for line in helpline.splitlines():
                    if line:
                        helpline = line
                        break
                if command.is_valid_profile(profile):
                    result += "\t\t{0:15}\t{1}\n".format(cmdname, helpline)
                else:
                    wrongprofile += "\t\t{0:15}\t{1}\n".format(
                        cmdname, helpline)

            pp_print(result + "\n")
        else:
            cmds = registry.get_plugin_classes(commands.Command, lower=True)
            cmdname = line.split()[0]
            c = cmds[cmdname](config)
            # Register the help cb from the command itself
            pp_print(vol_command_help(c) + "\n")

    @line_magic
    def vol(self, line):
        '''
        Execute a volatility command. Eg: vol pslist. List commands with %list_vol_commands
        '''
        if self.vol_commands is None:
            self.update_conf()
        if self.vol_commands is None:
            pp_error("[!] No volatility commands available\n")

        els = line.split()
        if len(els) < 1:
            self.do_help("vol")
            return
        cmd = els[0]
        if len(els) > 1:
            cmd_params = " ".join(els[1:])
        else:
            cmd_params = ""
        if cmd not in self.vol_commands:
            pp_error("[!] The specified volatility command is not in the command list (%list_vol_commands)")
            return
        self.vol_commands[cmd](cmd_params)

    @line_magic
    def custom(self, line):
        '''
        Execute a custom command defined in an imported script (function prepended by do_)

            If no command is specified, a list of available commands will be printed.
            Syntax: custom <cmd> <args..>
        '''
        if line.strip() == "":
            list_custom_commands()
        else:
            elements = line.split(" ")
            if len(elements) == 0:
                list_custom_commands()
            else:
                cmd = elements[0]
                args = " ".join(elements[1:])
                run_custom_command(cmd, args)


class CustomCommand(IPyAutocall):
    rewrite = False

    def __init__(self, ip, func):
        super(CustomCommand, self).__init__(ip)
        self.__func = func

    def get_func(self):
        return self.__func

    def __call__(self, *args):
        return self.__func(*args)


def add_command(name, func):
    '''
        Add a command via __added_commands
    '''
    global __added_commands
    global __shell
    if __added_commands is not None:
        __added_commands[name] = CustomCommand(__shell, func)
    else:
        raise RuntimeError(
            "The function start_shell() was called but the shell is not initialized")


def remove_command(name):
    '''
        Remove a command from __added_commands
    '''
    if __added_commands is not None and name in __added_commands:
        del __added_commands[name]


def list_custom_commands():
    global __added_commands
    if len(__added_commands) > 0:
        pp_print("\n    DINAMICALLY IMPORTED COMMANDS")
        pp_print("\n    -----------------------------\n\n")
        pp_print("\n    Use custom <command> <args..>\n\n")
        for name in __added_commands:
            desc = __added_commands[name].get_func().__doc__
            if desc is not None:
                desc = desc.split("\n")[0]
                desc = desc.replace("%", "-")
                line_desc = "    %s        - %s\n" % (name, desc)
                pp_print(line_desc)
            else:
                pp_print("    %s\n" % name)


def run_custom_command(cmd, args):
    global __added_commands
    if cmd in __added_commands:
        __added_commands[cmd](args)
    else:
        pp_error(
            "The custom command %s is not a valid or defined command\n" %
            cmd)


def initialize_shell():
    global __shell
    global __local_ns
    global __cfg
    global __proc_prompt
    if __shell is None:
        try:
            __cfg = Config()
            __shell = InteractiveShellEmbed(
                config=__cfg, banner1="", exit_msg="")
            __proc_prompt = ProcPrompt(__shell)
            __shell.register_magics(ShellMagics)
            __shell.prompts = __proc_prompt
            # Add a couple of aliases to exit the shell
            __local_ns = {
                "c": __shell.exiter,
                "cont": __shell.exiter,
                "q": __shell.exiter}
        except Exception:
            traceback.print_stack()
            traceback.print_exc()


def start_shell(cpu_index=0):
    global __shell
    global __local_ns
    global __cfg
    global __proc_prompt
    from plugins.guest_agent import guest_agent as agent
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] = new[3] | termios.ECHO
    finished = False

    if __shell is not None:
        while not finished:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, new)
                finished = True
                __local_ns["__cpu_index"] = cpu_index
                __local_ns["__vol_conf"] = conf_m.vol_conf
                __local_ns["cpu"] = api.r_cpu(cpu_index)
                if agent is not None:
                    __local_ns["agent"] = agent
                __shell(local_ns=__local_ns)
            except Exception:
                traceback.print_stack()
                traceback.print_exc()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
    else:
        raise RuntimeError(
            "The function start_shell() was called but the shell is not initialized")
