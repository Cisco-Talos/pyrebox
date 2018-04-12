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
import functools
import struct
from utils import ConfigurationManager as conf_m

# =============================================================== UTILS ==


def read_return_parameter(cpu):
    '''
        Returns the return parameter (EAX/RAX)
    '''
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8
    if TARGET_LONG_SIZE == 4:
        return cpu.EAX
    elif TARGET_LONG_SIZE == 8:
        return cpu.RAX
    else:
        raise Exception(
            "[interproc::read_return_parameter(cpu)] : Non-supported TARGET_LONG_SIZE: %d" % TARGET_LONG_SIZE)


def read_parameters(cpu, num_params):
    '''
        Reads parameters from the registers/stack
    '''
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8
    if TARGET_LONG_SIZE == 4:
        # All the parameters are on the stack
        # We need to read num_params values + the return address
        try:
            buff = api.r_va(cpu.CR3, cpu.ESP, (num_params + 1) * 4)
        except:
            buff = "\x00" * len((num_params + 1) * 4)
            mwmon.printer("Could not read properly the parameters in interproc.py")
        params = struct.unpack("<" + "I" * (1 + num_params), buff)
        return params
    elif TARGET_LONG_SIZE == 8:
        params_regs = []
        params_stack = ()

        # Add the return address as parameter 0
        try:
            buff = api.r_va(cpu.CR3, cpu.RSP, 8)
        except:
            buff = "\x00" * 8
            mwmon.printer("Could not read properly the parameters in interproc.py")

        params_regs.append(struct.unpack("<Q", buff)[0])

        if num_params <= 1:
            params_regs.append(cpu.RCX)
        if num_params <= 2:
            params_regs.append(cpu.RDX)
        if num_params <= 3:
            params_regs.append(cpu.R8)
        if num_params <= 4:
            params_regs.append(cpu.R9)
        if num_params > 4:
            # We need to read num_params + the return address + 0x20
            # 0x20 is for the 4 slots (of 8 bytes) allocated to store
            # register parameters (allocated by caller, used by callee)
            try:
                buff = api.r_va(cpu.CR3, cpu.RSP, (num_params + 5) * 8)
            except:
                buff = "\x00" * ((num_params + 5) * 8)
                mwmon.printer("Could not read properly the parameters in interproc.py")
                
            params_stack = struct.unpack(
                "<" + "Q" * (5 + num_params), buff)
            params_stack = params_stack[5:]
        return (tuple(params_regs) + params_stack)
    else:
        raise Exception(
            "[interproc::read_return_parameter(cpu)] : Non-supported TARGET_LONG_SIZE: %d" % TARGET_LONG_SIZE)


def dereference_target_long(addr, pgd):
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8
    typ = "<I" if TARGET_LONG_SIZE == 4 else "<Q"
    try:
        buff = api.r_va(pgd, addr, TARGET_LONG_SIZE)
    except:
        buff = "\x00" * TARGET_LONG_SIZE
        mwmon.printer("Could not dereference TARGET_LONG in interproc.py")
    return struct.unpack(typ, buff)[0]

# =============================================================== HOOKS ==


def ntcreateprocessret(cpu_index,
                       cpu,
                       pid,
                       callback_name,
                       proc_hdl_p,
                       proc,
                       update_vads):

    import volatility.win32.tasks as tasks
    from mw_monitor_classes import mwmon
    from mw_monitor_classes import mw_monitor_start_monitoring_process
    from mw_monitor_classes import Process
    from api import get_running_process
    from utils import get_addr_space
    import api

    TARGET_LONG_SIZE = api.get_os_bits() / 8

    pgd = get_running_process(cpu_index)

    # First, remove callback
    mwmon.cm.rm_callback(callback_name)

    # Do not continue if EAX/RAX returns and invalid return code.
    if read_return_parameter(cpu) != 0:
        return

    # Load volatility address space
    addr_space = get_addr_space(pgd)

    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    # Initialize proc_obj, that will point to the eprocess of the new created
    # process
    proc_obj = None

    # Dereference the output argument containing the hdl of the newly created
    # process
    proc_hdl = dereference_target_long(proc_hdl_p, pgd)

    # Search handle table for the new created process
    for task in eprocs:
        if task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
            for handle in task.ObjectTable.handles():
                if handle.is_valid() and handle.HandleValue == proc_hdl and handle.get_object_type() == "Process":
                    proc_obj = handle.dereference_as("_EPROCESS")
                    break
            break

    if proc_obj is not None:
        if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
            f = mwmon.interproc_text_log_handle
            f.write(
                "[PID: %x] NtCreateProcess: %s - PID: %x - CR3: %x\n" % (pid,
                                                                         str(proc_obj.ImageFileName),
                                                                         int(proc_obj.UniqueProcessId),
                                                                         int(proc_obj.Pcb.DirectoryTableBase.v())))

        # Check if we are already monitoring the process
        for proc in mwmon.data.procs:
            if proc.pid == int(proc_obj.UniqueProcessId):
                return
        mwmon.printer("Following %s %x %x" %
        (proc_obj.ImageFileName,proc_obj.UniqueProcessId,proc_obj.Pcb.DirectoryTableBase.v()))
        new_proc = Process(str(proc_obj.ImageFileName))
        new_proc.set_pid(int(proc_obj.UniqueProcessId))
        new_proc.set_pgd(int(proc_obj.Pcb.DirectoryTableBase.v()))
        mw_monitor_start_monitoring_process(new_proc)
    else:
        if TARGET_LONG_SIZE == 4: 
            mwmon.printer("Error while trying to retrieve EPROCESS for handle %x, PID %x, EAX: %x" % (proc_hdl, pid, cpu.EAX))
        elif TARGET_LONG_SIZE == 8:
            mwmon.printer("Error while trying to retrieve EPROCESS for handle %x, PID %x, EAX: %x" % (proc_hdl, pid, cpu.RAX))

    if update_vads:
        proc.update_vads()

    return


def ntcreateprocess(cpu_index,
                    cpu,
                    pid,
                    proc,
                    update_vads):

    # This function interface is for NTCreateProcess.
    # NtCreateProcessEx has different interface, but
    # the parameters we need, are aligned.

    # From Vista onwards, kernel32.dll calls NtCreateUserProcess
    # instead of NtCreateProcess(Ex).

    # NtCreateProcess:

    # OUT PHANDLE     ProcessHandle,
    # IN ACCESS_MASK  DesiredAccess,
    # IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
    # IN HANDLE   ParentProcess,
    # IN BOOLEAN  InheritObjectTable,
    # IN HANDLE SectionHandle     OPTIONAL,
    # IN HANDLE DebugPort     OPTIONAL,
    # IN HANDLE ExceptionPort     OPTIONAL

    # NtCreateProcessEx

    # OUT PHANDLE ProcessHandle,
    # IN ACCESS_MASK DesiredAccess,
    # IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    # IN HANDLE ParentProcess,
    # IN ULONG Flags,
    # IN HANDLE SectionHandle OPTIONAL,
    # IN HANDLE DebugPort OPTIONAL,
    # IN HANDLE ExceptionPort OPTIONAL,
    # IN BOOLEAN InJob

    # NtCreateUserProcess

    # PHANDLE ProcessHandle,
    # PHANDLE ThreadHandle,
    # ACCESS_MASK ProcessDesiredAccess,
    # ACCESS_MASK ThreadDesiredAccess,
    # POBJECT_ATTRIBUTES ProcessObjectAttributes,
    # POBJECT_ATTRIBUTES ThreadObjectAttributes,
    # ULONG ulProcessFlags,
    # ULONG ulThreadFlags,
    # PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParameters,
    # PPS_CREATE_INFO PsCreateInfo,
    # PPS_ATTRIBUTE_LIST PsAttributeList

    from mw_monitor_classes import mwmon
    import api
    pgd = api.get_running_process(cpu_index)
    # Set callback on return address

    # Read the first parameter (process handle)
    params = read_parameters(cpu, 1)

    callback_name = mwmon.cm.generate_callback_name("ntcreateprocess_ret")

    # Arguments to callback: the callback name, so that it can unset it, the
    # process handle variable

    callback_function = functools.partial(ntcreateprocessret,
                                          pid=pid,
                                          callback_name=callback_name,
                                          proc_hdl_p=params[1],
                                          proc=proc,
                                          update_vads=update_vads)

    mwmon.cm.add_callback(api.CallbackManager.INSN_BEGIN_CB,
                          callback_function,
                          name=callback_name,
                          addr=params[0],
                          pgd=pgd)


def ntopenprocessret(cpu_index, cpu, pid, callback_name, proc_hdl_p, proc, update_vads):
    import volatility.win32.tasks as tasks
    from mw_monitor_classes import mwmon
    from mw_monitor_classes import mw_monitor_start_monitoring_process
    from mw_monitor_classes import Process
    from api import get_running_process
    from utils import get_addr_space
    import api

    TARGET_LONG_SIZE = api.get_os_bits() / 8

    pgd = get_running_process(cpu_index)

    # First, remove callback
    mwmon.cm.rm_callback(callback_name)

    # Do not continue if EAX/RAX returns and invalid return code.
    if read_return_parameter(cpu) != 0:
        return

    # Load volatility address space
    addr_space = get_addr_space(pgd)

    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    # Initialize proc_obj, that will point to the eprocess of the new created
    # process
    proc_obj = None

    # Dereference the output argument containing the hdl of the newly created
    # process
    proc_hdl = dereference_target_long(proc_hdl_p, pgd)

    # Search handle table for the new created process
    for task in eprocs:
        if task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
            for handle in task.ObjectTable.handles():
                if handle.is_valid() and handle.HandleValue == proc_hdl and handle.get_object_type() == "Process":
                    proc_obj = handle.dereference_as("_EPROCESS")
                    break
            break

    if proc_obj is not None:
        if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
            f = mwmon.interproc_text_log_handle
            f.write("[PID: %x] NtOpenProcess: %s - PID: %x - CR3: %x\n" %
                    (pid,
                     str(proc_obj.ImageFileName),
                     int(proc_obj.UniqueProcessId),
                     int(proc_obj.Pcb.DirectoryTableBase.v())))

        # Check if we are already monitoring the process
        for proc in mwmon.data.procs:
            if proc.pid == int(proc_obj.UniqueProcessId):
                return
        new_proc = Process(str(proc_obj.ImageFileName))
        new_proc.set_pid(int(proc_obj.UniqueProcessId))
        new_proc.set_cr3(int(proc_obj.Pcb.DirectoryTableBase.v()))
        mw_monitor_start_monitoring_process(new_proc)
    else:
        if TARGET_LONG_SIZE == 4: 
            mwmon.printer("Error while trying to retrieve EPROCESS for handle %x, PID %x, EAX: %x" % (proc_hdl, pid, cpu.EAX))
        elif TARGET_LONG_SIZE == 8:
            mwmon.printer("Error while trying to retrieve EPROCESS for handle %x, PID %x, EAX: %x" % (proc_hdl, pid, cpu.RAX))

    if update_vads:
        proc.update_vads()

    return


def ntopenprocess(cpu_index, cpu, pid, proc, update_vads):
    #  OUT PHANDLE             ProcessHandle,
    #  IN ACCESS_MASK          AccessMask,
    #  IN POBJECT_ATTRIBUTES   ObjectAttributes,
    #  IN PCLIENT_ID           ClientId );
    from mw_monitor_classes import mwmon
    import api
    pgd = api.get_running_process(cpu_index)

    # Read the first parameter (process handle)
    params = read_parameters(cpu, 1)

    # Set callback on return address
    callback_name = mwmon.cm.generate_callback_name("ntopenprocess_ret")

    callback_function = functools.partial(ntopenprocessret,
                                          pid=pid,
                                          callback_name=callback_name,
                                          proc_hdl_p=params[1],
                                          proc=proc,
                                          update_vads=update_vads)

    mwmon.cm.add_callback(api.CallbackManager.INSN_BEGIN_CB,
                          callback_function,
                          name=callback_name,
                          addr=params[0],
                          pgd=pgd)


def ntwritevirtualmemory(cpu_index, cpu, pid, proc, update_vads, reverse=False):
    import volatility.win32.tasks as tasks
    from mw_monitor_classes import mwmon
    from mw_monitor_classes import Injection
    import api
    from utils import get_addr_space

    TARGET_LONG_SIZE = api.get_os_bits() / 8

    # _In_ HANDLE     ProcessHandle,
    # _In_ PVOID  BaseAddress,
    # _In_ PVOID  Buffer,
    # _In_ SIZE_T     NumberOfBytesToWrite,
    # _Out_opt_ PSIZE_T   NumberOfBytesWritten

    pgd = api.get_running_process(cpu_index)

    # Read the parameters
    ret_addr, proc_hdl, remote_addr, local_addr, size, size_out = read_parameters(
        cpu, 5)

    local_proc = None
    # Get local proc
    for proc in mwmon.data.procs:
        if proc.pid == pid:
            local_proc = proc
            break
    # Try to get remote process from list of monitored processes
    remote_proc = None
    # Load volatility address space
    addr_space = get_addr_space(pgd)

    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    # Initialize proc_obj, that will point to the eprocess of the new created
    # process
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
        for proc in mwmon.data.procs:
            if proc.pid == proc_obj.UniqueProcessId:
                remote_proc = proc
                break
    else:
        # Sometimes we get calls to this function over non-proc handles (e.g. type "Desktop")
        return
    if remote_proc is None:
        mwmon.printer(
            "[!]  Could not obtain remote proc, or it is not being monitored")
        return
    elif local_proc is None:
        mwmon.printer(
            "[!]  Could not obtain local proc, or it is not being monitored")
        return
    else:
        if reverse:
            data = None
            if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
                f = mwmon.interproc_text_log_handle
                if TARGET_LONG_SIZE == 4:
                    f.write("[PID: %x] NtReadVirtualMemory: PID: %x - Addr: %08x <-- PID: %x Addr: %08x / Size: %08x\n" %
                            (pid, local_proc.pid, local_addr, remote_proc.pid, remote_addr, size))
                elif TARGET_LONG_SIZE == 8:
                    f.write("[PID: %x] NtReadVirtualMemory: PID: %x - Addr: %16x <-- PID: %x Addr: %16x / Size: %16x\n" %
                            (pid, local_proc.pid, local_addr, remote_proc.pid, remote_addr, size))
        else:
            data = None
            if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
                f = mwmon.interproc_text_log_handle
                if TARGET_LONG_SIZE == 4:
                    f.write("[PID: %x] NtWriteVirtualMemory: PID: %x - Addr: %08x --> PID: %x Addr: %08x / Size: %08x\n" %
                            (pid, local_proc.pid, local_addr, remote_proc.pid, remote_addr, size))
                elif TARGET_LONG_SIZE == 8:
                    f.write("[PID: %x] NtWriteVirtualMemory: PID: %x - Addr: %16x --> PID: %x Addr: %16x / Size: %16x\n" %
                            (pid, local_proc.pid, local_addr, remote_proc.pid, remote_addr, size))

        inj = Injection(remote_proc, remote_addr,
                        local_proc, local_addr, size, data, reverse)
        local_proc.add_injection(inj)

    if update_vads:
        proc.update_vads()


def ntreadvirtualmemory(cpu_index, cpu, pid, proc, update_vads):
    # Reuse implementation in write virtual memory
    ntwritevirtualmemory(cpu_index, cpu, pid, proc, update_vads, reverse=True)


def ntreadfile(cpu_index, cpu, pid, proc, update_vads, is_write=False):
    import volatility.win32.tasks as tasks
    from mw_monitor_classes import mwmon
    from mw_monitor_classes import FileRead
    from mw_monitor_classes import FileWrite
    from mw_monitor_classes import File
    from utils import get_addr_space
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    # IN HANDLE   FileHandle,
    # IN HANDLE Event     OPTIONAL,
    # IN PIO_APC_ROUTINE ApcRoutine   OPTIONAL,
    # IN PVOID ApcContext     OPTIONAL,
    # OUT PIO_STATUS_BLOCK    IoStatusBlock,
    # OUT PVOID   Buffer,
    # IN ULONG    Length,
    # IN PLARGE_INTEGER ByteOffset    OPTIONAL,
    # IN PULONG Key   OPTIONAL

    pgd = api.get_running_process(cpu_index)

    # Read the parameters
    ret_addr, file_handle, arg2, arg3, arg4, arg5, buff, length, offset_p, arg9 = read_parameters(
        cpu, 9)

    # Load volatility address space
    addr_space = get_addr_space(pgd)

    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    # Initialize file_obj, that will point to the object of the referenced file
    file_obj = None

    # Search handle table for the new created process
    for task in eprocs:
        if task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
            for handle in task.ObjectTable.handles():
                if handle.is_valid() and handle.HandleValue == file_handle and handle.get_object_type() == "File":
                    file_obj = handle.dereference_as("_FILE_OBJECT")
                    break
            break

    if file_obj is not None:
        file_instance = None
        for fi in mwmon.data.files:
            if fi.file_name == str(file_obj.FileName):
                file_instance = fi
                break

        # If we have still not recorded the file, add it to files to record
        if file_instance is None:
            file_instance = File(str(file_obj.FileName))
            mwmon.data.files.append(file_instance)
        # Now, record the read/write
        # curr_file_offset is never used
        # curr_file_offset = int(file_obj.CurrentByteOffset.QuadPart)
        # FO_SYNCHRONOUS_IO     0x0000002
        is_offset_maintained = ((file_obj.Flags & 0x0000002) != 0)

        # If no offset was specified, and the offset is mantained, the real
        # offset is taken from the file object
        offset = None
        if offset_p == 0 and is_offset_maintained:
            offset = int(file_obj.CurrentByteOffset.QuadPart)
        elif offset_p != 0:
            # If an offset is provided, the current offset in the file_object
            # will be updated, regardless of the flag.
            try:
                offset = struct.unpack("Q", api.r_va(pgd, offset_p, 8))[0]
            except:
                offset = 0
                mwmon.printer("Could not dereference offset in NtReadFile call in interproc.py")
        else:
            # If no offset was specified and the file object does not have the flag set, we may be in front of some kind
            # of corruption error or deliberate manipulation
            print "[!] The file object flag FO_SYNCHRONOUS_IO is not set, and no offset was provided"
            return

        # At this moment we do not record the data
        op = None

        for proc in mwmon.data.procs:
            if proc.pid == pid:
                local_proc = proc
                break

        if not is_write:
            op = FileRead(file_instance, local_proc, offset, length, None)
            if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
                f = mwmon.interproc_text_log_handle
                if TARGET_LONG_SIZE == 4:
                    f.write("[PID: %x] NtReadFile: Offset: %08x Size: %08x / %s\n" %
                            (pid, offset, length, str(file_obj.FileName)))
                elif TARGET_LONG_SIZE == 8:
                    f.write("[PID: %x] NtReadFile: Offset: %16x Size: %16x / %s\n" %
                            (pid, offset, length, str(file_obj.FileName)))
        else:
            op = FileWrite(file_instance, local_proc, offset, length, None)
            if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
                f = mwmon.interproc_text_log_handle
                if TARGET_LONG_SIZE == 4:
                    f.write("[PID: %x] NtWriteFile: Offset: %08x Size: %08x / %s\n" %
                            (pid, offset, length, str(file_obj.FileName)))
                elif TARGET_LONG_SIZE == 8:
                    f.write("[PID: %x] NtWriteFile: Offset: %16x Size: %16x / %s\n" %
                            (pid, offset, length, str(file_obj.FileName)))

        file_instance.add_operation(op)
        local_proc.file_operations.append(op)

    if update_vads:
        proc.update_vads()


def ntwritefile(cpu_index, cpu, pid, proc, update_vads):
    # IN HANDLE               FileHandle,
    # IN HANDLE               Event OPTIONAL,
    # IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
    # IN PVOID                ApcContext OPTIONAL,
    # OUT PIO_STATUS_BLOCK    IoStatusBlock,
    # IN PVOID                Buffer,
    # IN ULONG                Length,
    # IN PLARGE_INTEGER       ByteOffset OPTIONAL,
    # IN PULONG               Key OPTIONAL );
    ntreadfile(cpu_index, cpu, pid, proc, update_vads, is_write=True)


def ntmapviewofsection_ret(cpu_index,
                           cpu,
                           pid,
                           callback_name,
                           mapped_sec,
                           mapping_proc,
                           base_p, size_p,
                           offset_p,
                           proc,
                           update_vads):
    from mw_monitor_classes import mwmon
    from mw_monitor_classes import SectionMap
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    pgd = api.get_running_process(cpu_index)

    # First, remove callback
    mwmon.cm.rm_callback(callback_name)

    if base_p != 0:
        base = dereference_target_long(base_p, pgd)
    else:
        base = 0

    if size_p != 0:
        size = dereference_target_long(size_p, pgd)
    else:
        size = 0

    # Offset is always 8 bytes
    if offset_p != 0:
        try:
            offset = struct.unpack("Q", api.r_va(pgd, offset_p, 8))[0]
        except:
            offset = 0
            mwmon.printer("Could not dereference offset in NtMapViewOfSection return, in interproc.py")
    else:
        offset = 0

    mapping_proc.section_maps.append(
        SectionMap(mapped_sec, base, size, offset))

    if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
        f = mwmon.interproc_text_log_handle
        if TARGET_LONG_SIZE == 4:
            f.write("[PID: %x] NtMapViewOfSection: Base: %08x Size: %08x Offset: %08x / Section: %s\n" %
                    (pid, base, size, offset, mapped_sec.backing_file))
        elif TARGET_LONG_SIZE == 8:
            f.write("[PID: %x] NtMapViewOfSection: Base: %16x Size: %16x Offset: %08x / Section: %s\n" %
                    (pid, base, size, offset, mapped_sec.backing_file))

    if update_vads:
        proc.update_vads()


def ntmapviewofsection(cpu_index, cpu, pid, proc, update_vads):
    import volatility.obj as obj
    import volatility.win32.tasks as tasks
    import volatility.plugins.overlays.windows.windows as windows
    from mw_monitor_classes import mwmon
    from mw_monitor_classes import Section
    from utils import get_addr_space
    import api
    from api import CallbackManager
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    # IN HANDLE               SectionHandle,
    # IN HANDLE               ProcessHandle,
    # IN OUT PVOID            *BaseAddress OPTIONAL,
    # IN ULONG                ZeroBits OPTIONAL,
    # IN ULONG                CommitSize,
    # IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
    # IN OUT PULONG           ViewSize,
    # IN                      InheritDisposition,
    # IN ULONG                AllocationType OPTIONAL,
    # IN ULONG                Protect

    pgd = api.get_running_process(cpu_index)

    # Read the parameters
    ret_addr, section_handle, proc_handle, base_p, arg_3, arg_4, offset_p, size_p = read_parameters(
        cpu, 7)

    # Load volatility address space
    addr_space = get_addr_space(pgd)

    class _SECTION_OBJECT(obj.CType, windows.ExecutiveObjectMixin):

        def is_valid(self):
            return obj.CType.is_valid(self)

    addr_space.profile.object_classes.update(
        {'_SECTION_OBJECT': _SECTION_OBJECT})
    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]
    # Initialize proc_obj, that will point to the object of the referenced
    # process, and section_obj, idem
    proc_obj = None
    section_obj = None
    mapping_proc = None
    if (TARGET_LONG_SIZE == 4 and proc_handle == 0xffffffff) or (TARGET_LONG_SIZE == 8 and proc_handle == 0xffffffffffffffff):
        for proc in mwmon.data.procs:
            if proc.pid == pid:
                mapping_proc = proc
                break
    # Search handle table for the caller process
    for task in eprocs:
        if task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
            for handle in task.ObjectTable.handles():
                if handle.is_valid():
                    if not mapping_proc and not proc_obj and \
                       handle.HandleValue == proc_handle and \
                       handle.get_object_type() == "Process":
                        proc_obj = handle.dereference_as("_EPROCESS")
                    elif handle.HandleValue == section_handle and handle.get_object_type() == "Section":
                        # We dereference the object as _SECTION_OBJECT, although it is not a _SECTION_OBJECT but a
                        # _SECTION, that is not present in the volatility overlay:
                        # http://forum.sysinternals.com/section-object_topic24975.html
                        # For a better reference see the comments on the Section class
                        # in mw_monitor_classes.py
                        section_obj = handle.dereference_as("_SECTION_OBJECT")
                if (proc_obj or mapping_proc) and section_obj:
                    break
            break
    # proc_obj represents the process over which the section is mapped
    # section_object represents the section being mapped.
    if (proc_obj is not None or mapping_proc is not None) and section_obj is not None:
        mapped_sec = None
        if not mapping_proc:
            for proc in mwmon.data.procs:
                if proc.pid == proc_obj.UniqueProcessId:
                    mapping_proc = proc
                    break
        if mapping_proc is None:
            mwmon.printer("[!] The mapping process is not being monitored," +
                          " a handle was obtained with an API different from " +
                          "OpenProcess or CreateProcess")
            return
        for sec in mwmon.data.sections:
            if sec.get_offset() == section_obj.obj_offset:
                mapped_sec = sec
                break

        # If the section was not in our list, we create an entry
        if mapped_sec is None:
            mapped_sec = Section(pgd, section_obj)
            mwmon.data.sections.append(mapped_sec)

        # Record the actual map once we return back from the call and we can
        # dereference output parameters
        callback_name = mwmon.cm.generate_callback_name("mapviewofsection_ret")
        # Arguments to callback: the callback name, so that it can unset it,
        # the process handle variable, and the section handle

        callback_function = functools.partial(ntmapviewofsection_ret,
                                              pid=pid,
                                              callback_name=callback_name,
                                              mapping_proc=mapping_proc,
                                              mapped_sec=mapped_sec,
                                              base_p=base_p,
                                              size_p=size_p,
                                              offset_p=offset_p,
                                              proc=proc,
                                              update_vads=update_vads)

        mwmon.cm.add_callback(CallbackManager.INSN_BEGIN_CB,
                              callback_function,
                              name=callback_name,
                              addr=ret_addr,
                              pgd=pgd)


def ntunmapviewofsection(cpu_index, cpu, pid, proc, update_vads):
    import volatility.win32.tasks as tasks
    from mw_monitor_classes import mwmon
    from utils import get_addr_space
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    # IN HANDLE               ProcessHandle,
    # IN PVOID                BaseAddress);
    # Search for the map, and deactivate it

    pgd = api.get_running_process(cpu_index)

    ret_addr, proc_handle, base = read_parameters(cpu, 2)

    # Load volatility address space
    addr_space = get_addr_space(pgd)

    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    # Initialize proc_obj, that will point to the object of the referenced
    # process, and section_obj, idem
    proc_obj = None
    # Search handle table for the caller process
    for task in eprocs:
        if task.UniqueProcessId == pid:
            if (TARGET_LONG_SIZE == 4 and proc_handle == 0xffffffff) or \
               (TARGET_LONG_SIZE == 8 and proc_handle == 0xffffffffffffffff):
                proc_obj = task
                break
            elif task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
                for handle in task.ObjectTable.handles():
                    if handle.is_valid():
                        if handle.HandleValue == proc_handle and handle.get_object_type() == "Process":
                            proc_obj = handle.dereference_as("_EPROCESS")
                            break
                break

    mapping_proc = None
    if proc_obj is not None:
        for proc in mwmon.data.procs:
            if proc.pid == proc_obj.UniqueProcessId:
                mapping_proc = proc
                break
    if mapping_proc is not None:
        for m in mapping_proc.section_maps:
            if m.base == base and m.is_active():
                m.deactivate()
                if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
                    f = mwmon.interproc_text_log_handle
                    if (TARGET_LONG_SIZE == 4):
                        f.write("[PID: %x] NtUnmapViewOfSection: Base: %08x Size: %08x / Section: %s\n" %
                                (pid, base, m.size, m.section.backing_file))
                    elif (TARGET_LONG_SIZE == 8):
                        f.write("[PID: %x] NtUnmapViewOfSection: Base: %16x Size: %16x / Section: %s\n" %
                                (pid, base, m.size, m.section.backing_file))

    if update_vads:
        proc.update_vads()


def ntvirtualprotect(cpu_index, cpu, pid, proc, update_vads):
    import volatility.win32.tasks as tasks
    from mw_monitor_classes import mwmon
    from utils import get_addr_space
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    pgd = api.get_running_process(cpu_index)

    #  IN HANDLE               ProcessHandle,
    #  IN OUT PVOID            *BaseAddress,
    #  IN OUT PULONG           NumberOfBytesToProtect,
    #  IN ULONG                NewAccessProtection,
    #  OUT PULONG              OldAccessProtection );
    # Keep a log of page permissions for each VAD. Log changes for every virtualprotect call.
    # Output this informaiton on the log file, signal the sections with
    # changed permissions.

    ret_addr, proc_handle, base_addr_p, size_p, new_access, old_access = read_parameters(
        cpu, 5)

    # Load volatility address space
    addr_space = get_addr_space(pgd)

    # Get call parameters

    base_addr = dereference_target_long(base_addr_p, pgd)
    size = dereference_target_long(size_p, pgd)

    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    # Initialize proc_obj, that will point to the object of the referenced
    # process, and section_obj, idem
    proc_obj = None
    # Search handle table for the caller process
    for task in eprocs:
        if task.UniqueProcessId == pid:
            if (TARGET_LONG_SIZE == 4 and proc_handle == 0xffffffff) or \
               (TARGET_LONG_SIZE == 8 and proc_handle == 0xffffffffffffffff):
                proc_obj = task
                break
            elif task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
                for handle in task.ObjectTable.handles():
                    if handle.is_valid():
                        if handle.HandleValue == proc_handle and handle.get_object_type() == "Process":
                            proc_obj = handle.dereference_as("_EPROCESS")
                            break
                break

    mapping_proc = None
    if proc_obj is not None:
        for proc in mwmon.data.procs:
            if proc.pid == proc_obj.UniqueProcessId:
                mapping_proc = proc
                break

    if mapping_proc is not None:
        for v in mapping_proc.vads:
            # If the block overlaps the vad:
            if base_addr >= v.start and base_addr < (v.start + v.size):
                v.update_page_access(base_addr, size, new_access)

    if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
        f = mwmon.interproc_text_log_handle
        if TARGET_LONG_SIZE == 4:
            f.write("[PID: %x] NtVirtualProtect: Base: %08x Size: %08x NewProtect: %08x\n" %
                    (pid, base_addr, size, new_access))
        elif TARGET_LONG_SIZE == 8:
            f.write("[PID: %x] NtVirtualProtect: Base: %016x Size: %016x NewProtect: %016x\n" %
                    (pid, base_addr, size, new_access))
    if update_vads:
        proc.update_vads()


def ntallocatevirtualmemory_ret(cpu_index,
                                cpu,
                                pid,
                                callback_name,
                                mapping_proc=None,
                                base_addr_p=None,
                                zerobits=None,
                                size_p=None,
                                aloc_type=None,
                                access=None,
                                proc=None,
                                update_vads=None):

    from mw_monitor_classes import mwmon
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    pgd = api.get_running_process(cpu_index)

    # First, remove callback
    mwmon.cm.rm_callback(callback_name)
    # Now, dereference all the output pointers
    # base and size_p depend on 32-bit vs. 64 bit. This should be turned into
    # 8 bytes for 64 bit guest.

    if base_addr_p != 0:
        base = dereference_target_long(base_addr_p, pgd)
    else:
        base = 0

    if size_p != 0:
        size = dereference_target_long(size_p, pgd)
    else:
        size = 0

    if mwmon.interproc_text_log and mwmon.interproc_text_log_handle is not None:
        f = mwmon.interproc_text_log_handle
        if TARGET_LONG_SIZE == 4:
            f.write("[PID: %x] NtAllocateVirtualMemory: Base: %08x Size: %08x Protect: %08x\n" %
                    (pid, base, size, access))
        elif TARGET_LONG_SIZE == 8:
            f.write("[PID: %x] NtAllocateVirtualMemory: Base: %016x Size: %016x Protect: %016x\n" %
                    (pid, base, size, access))

    if update_vads:
        proc.update_vads()


def ntallocatevirtualmemory(cpu_index,
                            cpu,
                            pid,
                            proc,
                            update_vads):

    import volatility.win32.tasks as tasks
    from mw_monitor_classes import mwmon
    import api
    from api import CallbackManager
    from utils import get_addr_space
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    pgd = api.get_running_process(cpu_index)

    # IN HANDLE               ProcessHandle,
    # IN OUT PVOID            *BaseAddress,
    # IN ULONG                ZeroBits,
    # IN OUT PULONG           RegionSize,
    # IN ULONG                AllocationType,
    # IN ULONG                Protect );

    # Only used for logging the event
    if not mwmon.interproc_text_log:
        return

    # Get call parameters
    (ret_addr, proc_handle, base_addr_p, zerobits,
     size_p, aloc_type, access) = read_parameters(cpu, 6)

    # Load volatility address space
    addr_space = get_addr_space(pgd)

    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    # Initialize proc_obj, that will point to the object of the referenced
    # process, and section_obj, idem
    proc_obj = None
    # Search handle table for the caller process
    for task in eprocs:
        if task.UniqueProcessId == pid:
            if (TARGET_LONG_SIZE == 4 and proc_handle == 0xffffffff) or \
               (TARGET_LONG_SIZE == 8 and proc_handle == 0xffffffffffffffff):
                proc_obj = task
                break
            elif task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
                for handle in task.ObjectTable.handles():
                    if handle.is_valid():
                        if handle.HandleValue == proc_handle and handle.get_object_type() == "Process":
                            proc_obj = handle.dereference_as("_EPROCESS")
                            break
                break

    mapping_proc = None
    if proc_obj is not None:
        for proc in mwmon.data.procs:
            if proc.pid == proc_obj.UniqueProcessId:
                mapping_proc = proc
                break

    if mapping_proc is not None:
        # Arguments to callback: the callback name, so that it can unset it,
        # the process handle variable, and the section handle

        callback_name = mwmon.cm.generate_callback_name(
            "ntallocatevirtualmemory_ret")

        callback_function = functools.partial(ntallocatevirtualmemory_ret,
                                              pid=pid,
                                              callback_name=callback_name,
                                              mapping_proc=mapping_proc,
                                              base_addr_p=base_addr_p,
                                              zerobits=zerobits,
                                              size_p=size_p,
                                              aloc_type=aloc_type,
                                              access=access,
                                              proc=proc,
                                              update_vads=update_vads)

        mwmon.cm.add_callback(CallbackManager.INSN_BEGIN_CB,
                              callback_function,
                              name=callback_name,
                              addr=ret_addr,
                              pgd=pgd)
