# -------------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox
#   Author: Jonas Zaddach
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

import api
import os
import ConfigParser
import functools
import struct
from cpus import X86CPU
from cpus import X64CPU


class GuestAgentPlugin(object):

    """
        This plugin deals with a host-guest interface through unused opcodes.
        It facilitates getting samples into the guest VM, starting them, ...

        How to use this plugin:

          A) For scripts:
             - Add `plugins.guest_agent: True` to your pyrebox.conf
                   or
             - Add a member to your module named "requirements" containing a
               list of required plugins/scripts. E.g.:
                   requirements = ["plugins.guest_agent"]
             - Import the plugin with `from plugins.guest_agent import guest_agent` in your script.
             - Interact with the guest agent using the public interface of this class (agent is
               a singleton instance of GuestAgentPlugin).

          B) In the ipython shell:
             - If no loaded script is loading the guest_agent plugin, you will need to make sure it
               gets loaded by adding `plugins.guest_agent: True` to your pyrebox.conf
             - Interact with the guest agent using the global member agent that is a singleton
               instance of GuestAgentPlugin.
    """

    __INTERFACE_VERSION = 1

    # Commands understood by the agent
    __CMD_WAIT = 0
    __CMD_COPY = 1
    __CMD_EXEC = 2
    __CMD_EXIT = 3

    # Composed commands
    __CMD_STOP = 100
    __CMD_EXEC_EXIT = 101

    __AGENT_INITIALIZED = 0
    __AGENT_RUNNING = 1
    __AGENT_READY = 2
    __AGENT_STOPPED = 3

    def __init__(self, cb, printer):
        """
            Create a new instance of the GuestAgentPlugin.

            :arg cb: The callback manager.
            :arg printer: The printer where logs should go to.
        """
        from utils import ConfigurationManager as conf_m
        from utils import pp_error
        self.__cb = None
        self.__printer = None

        # status
        self.__status = None

        # File descriptors
        self.__file_descriptor_counter = 0
        self.__file_descriptors = {}

        # Get the file name for the guest_agent, as well as the buffer offset
        # and max size
        self.__agent_config_file = None
        self.__agent_filename = None
        self.__agent_buffer_offset = None
        self.__agent_buffer_address = None
        self.__agent_buffer_size = None

        # Agent pgd
        self.__agent_pgd = None

        # Commands, and command information
        self.__file_to_execute = {"path": "", "args": "", "env": ""}
        self.__file_to_copy = {"source": "", "destiny": ""}
        self.__commands = [
            {"command": GuestAgentPlugin.__CMD_WAIT, "meta": {}}]

        # Initialize guest agent configuration
        try:
            if conf_m.agent_filename is None:
                conf_m.agent_filename = conf_m.config.get('AGENT', 'name')
            self.__agent_filename = conf_m.agent_filename

            # Read agent config file if necessary
            if self.__agent_config_file is None:
                if not os.path.isfile(conf_m.config.get('AGENT', 'conf')):
                    pp_error(
                        "[!] Could not initialize agent, offset config file missing!\n")
                    return
                self.__agent_config_file = ConfigParser.RawConfigParser()
                self.__agent_config_file.read(
                    conf_m.config.get('AGENT', 'conf'))

            if conf_m.agent_buffer_offset is None:
                conf_m.agent_buffer_offset = int(
                    self.__agent_config_file.get('BUFFER', 'BufferOffset'))
            self.__agent_buffer_offset = conf_m.agent_buffer_offset

            if conf_m.agent_buffer_size is None:
                conf_m.agent_buffer_size = int(
                    self.__agent_config_file.get('BUFFER', 'BufferSize'))
            self.__agent_buffer_size = conf_m.agent_buffer_size

        except ConfigParser.NoSectionError:
            pp_error(
                "[*] No agent configuration provided, guest agent will not work if not configured\n")
        except ConfigParser.NoOptionError:
            pp_error(
                "[*] No agent name provided, guest agent will not work if not configured properly\n")

        # Now, initialize plugin
        self.__cb = cb
        self.__printer = printer
        self.__cb.add_callback(
            api.CallbackManager.CREATEPROC_CB, self.__new_process_callback,
            name="host_file_plugin_process_create")
        # update the status
        self.__status = GuestAgentPlugin.__AGENT_INITIALIZED

    def __clean(self):
        """
            Cleanup, we no longer listen for process creation.
        """
        if self.__status == GuestAgentPlugin.__AGENT_RUNNING or \
            self.__status == GuestAgentPlugin.__AGENT_READY:
            # This will remove the callbacks
            api.stop_monitoring_process(self.__agent_pgd)
            self.__agent_pgd = None
            self.__cb.clean()
            self.__status = GuestAgentPlugin.__AGENT_STOPPED

    def __clean_opcode_callback(self):
        """
            Cleanup, but we still listen for new processes, so a new agent can
            be started.
        """
        if self.__status == GuestAgentPlugin.__AGENT_RUNNING or \
            self.__status == GuestAgentPlugin.__AGENT_READY:
            # This will remove the callbacks
            api.stop_monitoring_process(self.__agent_pgd)
            self.__agent_pgd = None
            self.__cb.rm_callback("host_file_plugin_opcode_range")
            # Restart status of the agent. We have all the data initialized
            # but the agent is no longer running. Nevertheless the process
            # creation callback is still active so a new agent could
            # be spawned in the guest.
            self.__status = GuestAgentPlugin.__AGENT_INITIALIZED

    def stop_agent(self):
        """
            Forces the agent to exit, and stops listening to
            agent creation, so guest agent interaction is disabled
            forever.
        """
        self.__commands.append(
            {"command": GuestAgentPlugin.__CMD_STOP, "meta": {}})
        return True

    def exit_agent(self):
        """
            Forces the agent to exit. Nevertheless, if a new agent is
            spawned in the guest, it will be up and running again.
        """
        self.__commands.append(
            {"command": GuestAgentPlugin.__CMD_EXIT, "meta": {}})
        return True

    def copy_file(self, source_path, destiny_path):
        """
            Copy file from host machine to guest VM

            :param source_path: The path (on the host) of the file to copy
            :type source_path: str

            :param destiny_path: The path (on the guest) of the file to copy
            :type destinity_path: str
        """
        # if self.__status != GuestAgentPlugin.__AGENT_RUNNING:
        #    raise Exception(
        #        "The agent is not ready yet, or it has been stopped")

        # Count the "\x00" character at the end
        if len(source_path) + 1 > self.__agent_buffer_size:
            raise ValueError("The size of the source path should not exceed %d bytes" %
                             self.__agent_buffer_size)
        if len(destiny_path) + 1 > self.__agent_buffer_size:
            raise ValueError(
                "The size of the destiny path should not exceed %d bytes" % self.__agent_buffer_size)

        self.__commands.append(
            {"command": GuestAgentPlugin.__CMD_COPY, "meta": {"source": source_path, "destiny": destiny_path}})

        return True

    def execute_file(self, path, args=[], env={}, exit_afterwards=False):
        """
            Execute file on the guest VM and terminate the agent

            :param path: The path of the file to execute.
            :type path: str

            :param args: The list of arguments to execute the file. (list of str)
            :type args: list

            :param env: A dictionary with environment variables to set for the file to be executed.
            :type env: dict
        """
        if type(path) is not str:
            raise ValueError("The path must be a string")
        if type(args) is not list:
            raise ValueError("Args must be provided as a python list")
        if type(env) is not dict:
            raise ValueError(
                "Args must be provided as a dictionary of varible name -> value mappings")

        # Check size of path and combined length of arguments and env to write
        if len(path) + 1 > self.__agent_buffer_size:
            raise ValueError(
                "The size of the file path should not exceed %d bytes" % self.__agent_buffer_size)

        # Add the args and the env as they are, to the meta

        if exit_afterwards:
            self.__commands.append({"command": GuestAgentPlugin.__CMD_EXEC_EXIT, "meta": {
                                   "path": path, "args": args, "env": env}})
        else:
            self.__commands.append({"command": GuestAgentPlugin.__CMD_EXEC, "meta": {
                                   "path": path, "args": args, "env": env}})

        return True

    def __get_command_name(self, cmd):
        """
            Gets a printable command name for a command number
        """
        if cmd == GuestAgentPlugin.__CMD_WAIT:
            return "WAIT"
        elif cmd == GuestAgentPlugin.__CMD_COPY:
            return "COPY_FILE"
        elif cmd == GuestAgentPlugin.__CMD_EXEC:
            return "EXEC_FILE"
        elif cmd == GuestAgentPlugin.__CMD_EXIT:
            return "EXIT AGENT"
        elif cmd == GuestAgentPlugin.__CMD_STOP:
            return "STOP AGENT"
        elif cmd == GuestAgentPlugin.__CMD_EXEC_EXIT:
            return "EXEC FILE AND EXIT AGENT"
        else:
            return "UNKNOWN"

    def print_command_list(self):
        """
            Prints the list of commands in the queue.
        """
        self.__printer("LIST OF COMMANDS")
        self.__printer("================")
        for i in range(0, len(self.__commands)):
            self.__printer(
                "    [%d] CMD: %s - %s" % (i, self.__get_command_name(self.__commands[i]["command"]),
                                           str(self.__commands[i]["meta"])))

    def remove_command(self, cmd_number):
        """
            Removes a command from the queue of commands to execute

            :param cmd_number: The command number to remove (obtained from print_command_list())
            :type cmd_number: int
        """
        if cmd_number >= 0 and cmd_number < (len(self.__commands)):
            del self.__commands[cmd_number]
            self.__printer("[*] Command %d succesfully removed" % cmd_number)

    def __context_change_callback(self, target_pgd, target_mod_name, old_pgd, new_pgd):
        """
            Updates the module base (to have the absolute agent buffer address) as soon
            as it is available.
        """
        global cm
        try:
            if target_pgd == new_pgd and self.__status == GuestAgentPlugin.__AGENT_RUNNING:
                lowest_addr = None

                for m in api.get_module_list(target_pgd):
                    name = m["name"]
                    base = m["base"]
                    # size = m["size"]
                    if name == target_mod_name or target_mod_name in name:
                        if lowest_addr is None:
                            lowest_addr = base
                        elif base < lowest_addr:
                            lowest_addr = base

                if self.__agent_buffer_offset is not None and \
                    lowest_addr is not None:

                    self.__agent_buffer_address = lowest_addr + \
                        self.__agent_buffer_offset
                    # Now, our agent is fully up and running
                    self.__status = GuestAgentPlugin.__AGENT_READY
                    # Now, we add the opcode hook and start monitoring the
                    # process
                    self.__cb.add_callback(
                        api.CallbackManager.REMOVEPROC_CB, self.__remove_process_callback,
                        name="host_file_plugin_process_REMOVE")

                    self.__cb.rm_callback("context_change_guest_agent")
        except Exception as e:
            self.__printer("Exception occurred on context change callback: %s" % str(e))

    def __new_process_callback(self, pid, pgd, name):
        """
            Called by the callback manager when a new process is created.
        """
        try:
            # If we already have a running agent, ignore it
            if self.__status < GuestAgentPlugin.__AGENT_RUNNING:
                # Use only the first 8 characters since the name could be truncated
                if name is not None and name != "" and name in self.__agent_filename:
                    self.__agent_pgd = pgd
                    # Monitor context change to check we can get the base address
                    # for the process main module
                    self.__cb.add_callback(api.CallbackManager.CONTEXTCHANGE_CB, functools.partial(
                        self.__context_change_callback, pgd, name), name="context_change_guest_agent")
                    self.__cb.add_callback(
                        api.CallbackManager.OPCODE_RANGE_CB, self.__opcode_range_callback,
                        name="host_file_plugin_opcode_range",
                        start_opcode=0x13f,
                        end_opcode=0x13f)
                    api.start_monitoring_process(pgd)
                    self.__status = GuestAgentPlugin.__AGENT_RUNNING
        except Exception as e:
            self.__printer("Exception occurred on create process callback: %s" % str(e))

    def __remove_process_callback(self, pid, pgd, name):
        """
            Called by the callback manager when a process is removed.
        """
        if self.__status == GuestAgentPlugin.__AGENT_RUNNING or \
            self.__status == GuestAgentPlugin.__AGENT_READY:
            if pgd == self.__agent_pgd:
                self.__clean_opcode_callback()
                self.__printer(
                    "HostFilePlugin: Guest agent with PGD %x was killed, but you can start it again!" % (pgd))

    def __check_buffer_validity(self, buf, size):
        """
            Checks that the declared buffer is within the allowed range
            for the configured agent.
        """
        if self.__agent_buffer_address is None or self.__agent_buffer_size is None:
            raise ValueError(
                "Buffer offset and size have not been initialized, cannot perform security check!")
        return (buf == self.__agent_buffer_address and size == self.__agent_buffer_size)

    def __opcode_range_callback(self, cpu_index, cpu, cur_pc, next_pc):
        """
            Called by the callback manager when the desired opcode is hit.
        """
        try:
            if self.__status == GuestAgentPlugin.__AGENT_READY:
                function = api.r_va(api.get_running_process(cpu_index), cur_pc + 3, 2)
                try:
                    handler = {
                        "\x00\x00": self.__handle_host_version,
                        "\x00\x01": self.__handle_host_message,
                        "\x00\x02": self.__handle_host_get_command,
                        "\x10\x00": self.__handle_host_open,
                        "\x10\x01": self.__handle_host_read,
                        "\x10\x02": self.__handle_host_close,
                        "\x10\x03": self.__handle_host_get_file_name,
                        "\x20\x00": self.__handle_host_request_exec_path,
                        "\x20\x01": self.__handle_host_request_exec_args,
                        "\x20\x02": self.__handle_host_request_exec_env,
                        "\x20\x03": self.__handle_host_request_exec_args_linux,
                        "\x20\x04": self.__handle_host_request_exec_env_linux

                    }[function]
                    handler(cpu_index, cpu)
                except KeyError:
                    self.__printer(
                        "HostFilePlugin: Unknown host opcode %x at 0x%08x" % (function, cur_pc))

                # Advance the program counter.
                # Needs to be done explicitly, as Qemu doesn't know the instruction
                # length.
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EIP", cpu.EIP + 10)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RIP", cpu.RIP + 10)
            elif self.__status == GuestAgentPlugin.__AGENT_RUNNING:
                # Agent already running but not ready yet (the base
                # address was not correctly determined yet.

                # Advance the program counter.
                # Needs to be done explicitly, as Qemu doesn't know the instruction
                # length.
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EIP", cpu.EIP + 10)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RIP", cpu.RIP + 10)
        except Exception as e:
            self.__printer("Exception occurred on opcode callback: %s" % str(e))

    def __read_string(self, cpu_index, addr):
        """
            Read a string from the virtual address space of the guest's user mode.
        """
        pgd = api.get_running_process(cpu_index)
        string = []
        for i in range(256):
            byte = api.r_va(pgd, addr + i, 1)
            if byte == "\x00":
                break
            string.append(byte)
        return "".join(string)

    def __write_strings_array(self, pgd, vaddr, array):
        """
            Write a char* arg[] array.
        """
        TARGET_LONG_SIZE = api.get_os_bits() / 8
        array_ptr = vaddr
        strings_ptr = vaddr + TARGET_LONG_SIZE * (len(array) + 1)
        for i, s in enumerate(array):
            api.w_va(pgd, array_ptr, struct.pack(
                "<" + ("L" if TARGET_LONG_SIZE == 4 else "Q"), strings_ptr), TARGET_LONG_SIZE)
            api.w_va(pgd, strings_ptr, s + "\x00", len(s) + 1)
            array_ptr += TARGET_LONG_SIZE
            strings_ptr += len(s) + 1
        api.w_va(pgd, array_ptr, "\x00" * TARGET_LONG_SIZE, TARGET_LONG_SIZE)

    def __write_arg_strings_array(self, pgd, vaddr, array):
        """
            Write a space separated list of argument over a single char array.
        """
        array_ptr = vaddr
        for el in array:
            api.w_va(pgd, array_ptr, el + " ", len(el) + 1)
            array_ptr += (len(el) + 1)
        # Terminating null character
        api.w_va(pgd, array_ptr, "\x00", 1)

    def __write_env_strings_array(self, pgd, vaddr, array):
        """
            Write a block of null terminated strings, followed by a null character.
            Env variable format for CreateProcess.
        """
        array_ptr = vaddr
        for el in array:
            api.w_va(pgd, array_ptr, el + "\x00", len(el) + 1)
            array_ptr += (len(el) + 1)
        # Terminating null character
        api.w_va(pgd, array_ptr, "\x00", 1)

    def __handle_host_version(self, cpu_index, cpu):
        """
            Handle the host_version interface  call.

            Returns the interface version.
        """
        # self.__printer("GuestAgentPlugin: host_version() called")
        if isinstance(cpu, X86CPU):
            api.w_r(cpu_index, "EAX", GuestAgentPlugin.__INTERFACE_VERSION)
        elif isinstance(cpu, X64CPU):
            api.w_r(cpu_index, "RAX", GuestAgentPlugin.__INTERFACE_VERSION)

    def __handle_host_message(self, cpu_index, cpu):
        """
            Handle the host_message interface call.
        """
        if isinstance(cpu, X86CPU):
            msg = self.__read_string(cpu_index, cpu.EAX)
        elif isinstance(cpu, X64CPU):
            msg = self.__read_string(cpu_index, cpu.RAX)

        self.__printer(
            "GuestAgentPlugin: Message from guest: \"{:s}\"".format(msg))

    def __handle_host_get_command(self, cpu_index, cpu):
        """
            Handle the host_get_command interface call.
        """
        do_exit = False
        if len(self.__commands) > 0:
            # Fetch the first command
            command = self.__commands[0]["command"]
            meta = self.__commands[0]["meta"]
            # Remove the first command of the queue
            self.__commands = self.__commands[1:]
        else:
            command = GuestAgentPlugin.__CMD_WAIT
            meta = {}

        # if the command was an exit command, then clean up opcode callback
        if command == GuestAgentPlugin.__CMD_EXIT:
            self.__clean_opcode_callback()
        elif command == GuestAgentPlugin.__CMD_STOP:
            self.__clean()
            # Set it to EXIT, so that the agent understands
            # it has to exit.
            command = GuestAgentPlugin.__CMD_EXIT
        elif command == GuestAgentPlugin.__CMD_EXEC:
            self.__file_to_execute = meta
        elif command == GuestAgentPlugin.__CMD_COPY:
            self.__file_to_copy = meta
        elif command == GuestAgentPlugin.__CMD_EXEC_EXIT:
            command = GuestAgentPlugin.__CMD_EXEC
            self.__file_to_execute = meta
            do_exit = True

        if isinstance(cpu, X86CPU):
            api.w_r(cpu_index, "EAX", command)
        elif isinstance(cpu, X64CPU):
            api.w_r(cpu_index, "RAX", command)

        # A command asks to exit afterwards
        if do_exit:
            self.__commands.append(
                {"command": GuestAgentPlugin.__CMD_EXIT, "meta": {}})

    def __handle_host_open(self, cpu_index, cpu):
        """
            Handle the host_open interface call.
            Argument in EAX: Pointer (VA) to file name.
            Returns the file descriptor in EAX.
        """
        if isinstance(cpu, X86CPU):
            fname = self.__read_string(cpu_index, cpu.EAX)
        elif isinstance(cpu, X64CPU):
            fname = self.__read_string(cpu_index, cpu.RAX)

        # self.__printer("GuestAgentPlugin: host_open(%s) called" % fname)
        try:
            # Check the program is requesting the file that we asked to copy
            if self.__file_to_copy["destiny"] == fname:
                fpath = self.__file_to_copy["source"]
                fd = open(fpath, "rb")
                self.__file_descriptors[self.__file_descriptor_counter] = fd
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", self.__file_descriptor_counter)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", self.__file_descriptor_counter)

                self.__file_descriptor_counter += 1
            else:
                self.__printer(
                    "HostFilesPlugin: The guest requested to open an invalid file %s" % fname)
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", -1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", -1)
        except KeyError:
            self.__printer(
                "HostFilesPlugin: Guest tried to read unknown file %s" % fname)
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", -1)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", -1)
        except Exception as ex:
            self.__printer(
                "HostFilesPlugin: Exception %s while opening file %s" % (str(ex), fname))
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", -1)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", -1)

    def __handle_host_read(self, cpu_index, cpu):
        """
            Handle the host_read interface call.

            Argument in EAX: The file descriptor.
            Argument in EBX: Pointer to the buffer (VA) where bytes should be read into.
            Argument in ECX: Size of the buffer.
            Returns number of bytes read in EAX, or -1 if the call failed.
        """
        if isinstance(cpu, X86CPU):
            fd = cpu.EAX
            buf = cpu.EBX
            size = cpu.ECX
        elif isinstance(cpu, X64CPU):
            fd = cpu.RAX
            buf = cpu.RBX
            size = cpu.RCX

        # self.__printer("GuestAgentPlugin: host_read(%d, 0x%08x, %d) called" %
        # (fd, buf, size))
        if fd not in self.__file_descriptors:
            self.__printer(
                "HostFilesPlugin: host_read tried to access invalid file descriptor %d" % fd)
            return

        pgd = api.get_running_process(cpu_index)
        try:
            data = self.__file_descriptors[fd].read(size)
            # Security check: the buffer should be located on the allowed
            # boundaries
            if self.__check_buffer_validity(buf, size):
                api.w_va(pgd, buf, data, len(data))
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", len(data))
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", len(data))
            else:
                self.__printer("HostFilesPlugin: Declared buffer or buffer size are not" +
                               "within the allowed boundaries %x (%x)" % (buf, size))
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", -1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", -1)

        except Exception as ex:
            self.__printer(
                "HostFilesPlugin: Exception %s while trying to read from file descriptor %d" % (str(ex), fd))
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", -1)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", -1)

    def __handle_host_close(self, cpu_index, cpu):
        """
            Handle the host_close interface call.

            Argument in EAX: The file descriptor.
            Returns 0 on success in EAX, or -1 on error.
        """
        if isinstance(cpu, X86CPU):
            fd = cpu.EAX
        elif isinstance(cpu, X64CPU):
            fd = cpu.RAX

        if fd not in self.__file_descriptors:
            self.__printer(
                "HostFilesPlugin: host_close tried to access invalid file descriptor %d" % fd)
            return

        try:
            self.__file_descriptors[fd].close()
            del self.__file_descriptors[fd]
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", 0)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", 0)
            # self.__printer("GuestAgentPlugin: host_close(%d) called" % (fd))
        except Exception as ex:
            self.__printer(
                "HostFilesPlugin: Exception %s while trying to close file descriptor %d" % (str(ex), fd))
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", -1)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", -1)

    def __handle_host_get_file_name(self, cpu_index, cpu):
        """
            Handle the get_file_name interface call.

            Argument in EAX: the buffer to write to
            Argument in EBX: the max size of the buffer to write to

            Returns number of bytes written in EAX, or -1 if the call failed.
        """
        if isinstance(cpu, X86CPU):
            buf = cpu.EAX
            size = cpu.EBX
        elif isinstance(cpu, X64CPU):
            buf = cpu.RAX
            size = cpu.RBX

        # self.__printer("GuestAgentPlugin: host_get_file_name(0x%08x, %d)
        # called" % (buf, size))
        pgd = api.get_running_process(cpu_index)
        try:
            # Security check: the buffer should be located on the allowed
            # boundaries
            if self.__check_buffer_validity(buf, size):
                api.w_va(pgd, buf, self.__file_to_copy[
                         "destiny"] + "\x00", len(self.__file_to_copy["destiny"]) + 1)
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", len(
                        self.__file_to_copy["destiny"]) + 1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", len(
                        self.__file_to_copy["destiny"]) + 1)
            else:
                self.__printer("HostFilesPlugin: Declared buffer or buffer size are not" +
                               "within the allowed boundaries %x (%x)" % (buf, size))
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", -1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", -1)

        except Exception as ex:
            self.__printer(
                "HostFilesPlugin: Exception %s while trying to write file name to guest" % (str(ex)))
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", -1)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", -1)

    def __handle_host_request_exec_path(self, cpu_index, cpu):
        """
            Handle the host_request_exec_path interface call.

            Argument in EAX: the buffer to write to
            Argument in EBX: the max size of the buffer to write to

            Returns number of bytes written in EAX, or -1 if the call failed.
        """

        if isinstance(cpu, X86CPU):
            buf = cpu.EAX
            size = cpu.EBX
        elif isinstance(cpu, X64CPU):
            buf = cpu.RAX
            size = cpu.RBX
        # self.__printer("GuestAgentPlugin: host_request_exec_path(0x%08x, %d)
        # called" % (buf, size))
        pgd = api.get_running_process(cpu_index)
        try:
            # Security check: the buffer should be located on the allowed
            # boundaries
            if self.__check_buffer_validity(buf, size):
                api.w_va(pgd, buf, self.__file_to_execute[
                         "path"] + "\x00", len(self.__file_to_execute["path"]) + 1)
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", len(
                        self.__file_to_execute["path"]) + 1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", len(
                        self.__file_to_execute["path"]) + 1)
            else:
                self.__printer("HostFilesPlugin: Declared buffer or buffer size are not" +
                               "within the allowed boundaries %x (%x)" % (buf, size))
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", -1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", -1)

        except Exception as ex:
            self.__printer(
                "HostFilesPlugin: Exception %s while trying to write file path to guest" % (str(ex)))
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", -1)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", -1)

    def __handle_host_request_exec_args(self, cpu_index, cpu):
        """
            Handle the host_request_exec_args interface call.

            Argument in EAX: the buffer to write to
            Argument in EBX: the max size of the buffer to write to

            Returns number of bytes written in EAX, or -1 if the call failed.
        """

        if isinstance(cpu, X86CPU):
            buf = cpu.EAX
            size = cpu.EBX
        elif isinstance(cpu, X64CPU):
            buf = cpu.RAX
            size = cpu.RBX

        args = self.__file_to_execute["args"]

        argv_size = sum(len(x) + 1 for x in args) + 1
        if argv_size > self.__agent_buffer_size:
            raise ValueError("The size of the args should not exceed %d bytes" %
                             self.__agent_buffer_size)

        # self.__printer("GuestAgentPlugin: host_request_exec_args(0x%08x, %d)
        # called" % (buf, size))
        pgd = api.get_running_process(cpu_index)
        try:
            # Security check: the buffer should be located on the allowed
            # boundaries
            if self.__check_buffer_validity(buf, size):
                self.__write_arg_strings_array(
                    pgd, buf, args)
                if isinstance(cpu, X86CPU):
                    api.w_r(
                        cpu_index, "EAX", argv_size)
                elif isinstance(cpu, X64CPU):
                    api.w_r(
                        cpu_index, "RAX", argv_size)
            else:
                self.__printer("HostFilesPlugin: Declared buffer or buffer size are not" +
                               "within the allowed boundaries %x (%x)" % (buf, size))
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", -1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", -1)

        except Exception as ex:
            self.__printer(
                "HostFilesPlugin: Exception %s while trying to write file args to guest" % (str(ex)))
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", -1)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", -1)

    def __handle_host_request_exec_env(self, cpu_index, cpu):
        """
            Handle the host_request_exec_env interface call.

            Argument in EAX: the buffer to write to
            Argument in EBX: the max size of the buffer to write to

            Returns number of bytes written in EAX, or -1 if the call failed.
        """

        if isinstance(cpu, X86CPU):
            buf = cpu.EAX
            size = cpu.EBX
        elif isinstance(cpu, X64CPU):
            buf = cpu.RAX
            size = cpu.RBX

        env = self.__file_to_execute["env"]

        pgd = api.get_running_process(cpu_index)
        # self.__printer("GuestAgentPlugin: host_request_exec_env(0x%08x, %d)
        # called" % (buf, size))
        if len(env) > 0:

            env_size = 0
            if len(env) > 0:
                env = ["{:s}={:s}".format(k, v) for k, v in env.items()]
                env_size = sum(len(x) + 1 for x in env) + 1
                if env_size > self.__agent_buffer_size:
                    raise ValueError(
                        "The size of the env variables should not exceed %d bytes" % self.__agent_buffer_size)

            try:
                # Security check: the buffer should be located on the allowed
                # boundaries
                if self.__check_buffer_validity(buf, size):
                    self.__write_env_strings_array(
                        pgd, buf, env)

                    if isinstance(cpu, X86CPU):
                        api.w_r(
                            cpu_index, "EAX", env_size)
                    elif isinstance(cpu, X64CPU):
                        api.w_r(
                            cpu_index, "RAX", env_size)
                else:
                    self.__printer("HostFilesPlugin: Declared buffer or buffer size are not" +
                                   "within the allowed boundaries %x (%x)" % (buf, size))
                    if isinstance(cpu, X86CPU):
                        api.w_r(cpu_index, "EAX", -1)
                    elif isinstance(cpu, X64CPU):
                        api.w_r(cpu_index, "RAX", -1)

            except Exception as ex:
                self.__printer(
                    "HostFilesPlugin: Exception %s while trying to write env vars to guest" % (str(ex)))
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", -1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", -1)
        else:
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", 0)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", 0)

    def __handle_host_request_exec_args_linux(self, cpu_index, cpu):
        """
            Handle the host_request_exec_args interface call.

            Argument in EAX: the buffer to write to
            Argument in EBX: the max size of the buffer to write to

            Returns number of bytes written in EAX, or -1 if the call failed.
        """

        if isinstance(cpu, X86CPU):
            buf = cpu.EAX
            size = cpu.EBX
        elif isinstance(cpu, X64CPU):
            buf = cpu.RAX
            size = cpu.RBX

        TARGET_LONG_SIZE = api.get_os_bits() / 8

        args = self.__file_to_execute["args"]

        argv_size = TARGET_LONG_SIZE * (len(args) + 1) + sum(len(x) + 1 for x in args)

        if argv_size > self.__agent_buffer_size:
            raise ValueError("The size of the args should not exceed %d bytes" %
                             self.__agent_buffer_size)

        # self.__printer("GuestAgentPlugin: host_request_exec_args(0x%08x, %d)
        # called" % (buf, size))
        pgd = api.get_running_process(cpu_index)
        try:
            # Security check: the buffer should be located on the allowed
            # boundaries
            if self.__check_buffer_validity(buf, size):
                self.__write_strings_array(
                    pgd, buf, args)
                if isinstance(cpu, X86CPU):
                    api.w_r(
                        cpu_index, "EAX", argv_size)
                elif isinstance(cpu, X64CPU):
                    api.w_r(
                        cpu_index, "RAX", argv_size)
            else:
                self.__printer("HostFilesPlugin: Declared buffer or buffer size are not" +
                               "within the allowed boundaries %x (%x)" % (buf, size))
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", -1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", -1)

        except Exception as ex:
            self.__printer(
                "HostFilesPlugin: Exception %s while trying to write file args to guest" % (str(ex)))
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", -1)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", -1)

    def __handle_host_request_exec_env_linux(self, cpu_index, cpu):
        """
            Handle the host_request_exec_env interface call.

            Argument in EAX: the buffer to write to
            Argument in EBX: the max size of the buffer to write to

            Returns number of bytes written in EAX, or -1 if the call failed.
        """

        if isinstance(cpu, X86CPU):
            buf = cpu.EAX
            size = cpu.EBX
        elif isinstance(cpu, X64CPU):
            buf = cpu.RAX
            size = cpu.RBX

        TARGET_LONG_SIZE = api.get_os_bits() / 8

        env = self.__file_to_execute["env"]

        pgd = api.get_running_process(cpu_index)
        # self.__printer("GuestAgentPlugin: host_request_exec_env(0x%08x, %d)
        # called" % (buf, size))
        if len(env) > 0:

            env = ["{:s}={:s}".format(k, v) for k, v in env.items()]
            env_size = sum(len(x) + 1 for x in env) + TARGET_LONG_SIZE * (len(env) + 1)

            try:
                # Security check: the buffer should be located on the allowed
                # boundaries
                if self.__check_buffer_validity(buf, size):
                    self.__write_strings_array(
                        pgd, buf, env)

                    if isinstance(cpu, X86CPU):
                        api.w_r(
                            cpu_index, "EAX", env_size)
                    elif isinstance(cpu, X64CPU):
                        api.w_r(
                            cpu_index, "RAX", env_size)
                else:
                    self.__printer("HostFilesPlugin: Declared buffer or buffer size are not" +
                                   "within the allowed boundaries %x (%x)" % (buf, size))
                    if isinstance(cpu, X86CPU):
                        api.w_r(cpu_index, "EAX", -1)
                    elif isinstance(cpu, X64CPU):
                        api.w_r(cpu_index, "RAX", -1)

            except Exception as ex:
                self.__printer(
                    "HostFilesPlugin: Exception %s while trying to write env vars to guest" % (str(ex)))
                if isinstance(cpu, X86CPU):
                    api.w_r(cpu_index, "EAX", -1)
                elif isinstance(cpu, X64CPU):
                    api.w_r(cpu_index, "RAX", -1)
        else:
            if isinstance(cpu, X86CPU):
                api.w_r(cpu_index, "EAX", 0)
            elif isinstance(cpu, X64CPU):
                api.w_r(cpu_index, "RAX", 0)


guest_agent = None


def initialize_callbacks(module_hdl, printer):
    global guest_agent
    printer("[*]    Initializing guest_agent plugin")
    guest_agent = GuestAgentPlugin(api.CallbackManager(module_hdl), printer)


def clean():
    '''
    Clean up everything.
    '''
    global guest_agent
    guest_agent.stop_agent()
