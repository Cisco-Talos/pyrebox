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

from utils import pp_error
import volatility.obj as obj
# import volatility.plugins.kdbgscan as kdbg
import volatility.utils as utils
import traceback
import hashlib

from utils import pp_print
from utils import pp_debug
from utils import pp_warning
from utils import pp_error

last_kdbg = None

# To store the sleuthkit filesystem
filesystem = None

# To mark whether or not we need to save the cache
symbol_cache_must_be_saved = False

def windows_insert_module_internal(
        p_pid,
        p_pgd,
        base,
        size,
        fullname,
        basename,
        checksum,
        update_symbols,
        do_stop = False):

    from utils import get_addr_space
    from vmi import add_symbols
    from vmi import get_symbols
    from vmi import has_symbols
    from vmi import Module
    from vmi import add_module
    from vmi import get_module
    from vmi import has_module
    from api_internal import dispatch_module_load_callback
    from api_internal import dispatch_module_remove_callback
    import pefile
    import api

    global filesystem
    global symbol_cache_must_be_saved

    if fullname.startswith("\\??\\"):
        fullname = fullname[4:]
    if fullname.upper().startswith("C:\\"):
        fullname = fullname[3:]
    if fullname.upper().startswith("\\SYSTEMROOT"):
        fullname = "\WINDOWS" + fullname[11:]

    fullname = fullname.replace("\\", "/")

    if fullname[-4:].upper() == ".SYS" and not "/" in fullname:
        fullname = "/WINDOWS/system32/DRIVERS/" + fullname

    fullname = fullname.lower()

    mod = Module(base, size, p_pid, p_pgd, checksum, basename, fullname)

    # First, we try to get the symbols from the cache 
    if fullname != "" and has_symbols(fullname):
        mod.set_symbols(get_symbols(fullname))

    # If we are updating symbols (a simple module retrieval would
    # not require symbol extraction), and we don't have any
    # symbols on the cache:
    elif fullname != "" and update_symbols:
        pp_debug("Symbols not found in cache, extracting from %s...\n" % fullname)
        unnamed_function_counter = 0
        syms = {}
    
        # Here, fetch the file using the sleuthkit, and use 
        # PE file to process it
        
        # First select the file system if not selected already
        if filesystem is None:
            for fs in api.get_filesystems():
                file_list = api.open_guest_path(fs["index"], "")
                if isinstance(file_list, list) and len(file_list) > 0:
                    if "windows" in [f.lower() for f in file_list]:
                        filesystem = fs

        if filesystem is not None:
            # Try to read the file
            f = None
            try:
                f = api.open_guest_path(filesystem["index"], fullname)
            except Exception as e:
                pp_error("%s - %s\n" % (str(e), fullname))

            if f is not None:
                data = f.read()
        
                pe = pefile.PE(data=data)

                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name is not None:
                            syms[exp.name] = exp.address
                        else:
                            syms["unnamed_funcion_%d" % unnamed_function_counter] = exp.address
                            unnamed_function_counter += 1

        add_symbols(fullname, syms)
        mod.set_symbols(syms)
        # Even if it is empty, the module symbols are set
        # to an empty list, and thus are 'resolved'.
        # Anyway, in future updates, they could be resolved,
        # as we allow this in the first condition.
        symbol_cache_must_be_saved = True
 
    #Module load/del notification
    if has_module(p_pid, p_pgd, base):
        ex_mod = get_module(p_pid, p_pgd, base)
        # Module replacement, only if it is a different module, and also
        # take into consideration wow64 redirection. Never substitute the
        # wow64 version by the system32 version of the same dll
        if (ex_mod.get_fullname().lower() != fullname.lower()) and not ((ex_mod.get_name().lower() == basename.lower()) and ("windows/syswow64".lower() in ex_mod.get_fullname().lower()) and ("windows/system32" in fullname.lower())):
            # Notify of module deletion and module load
            dispatch_module_remove_callback(p_pid, p_pgd, base,
                                            ex_mod.get_size(),
                                            ex_mod.get_name(),
                                            ex_mod.get_fullname())
            add_module(p_pid, p_pgd, base, mod)
            mod.set_present()
            dispatch_module_load_callback(p_pid, p_pgd, base, size, basename, fullname)

        # If we updated the symbols and have a bigger list now, dont substitute the module
        # but update its symbols instead
        elif len(mod.get_symbols()) > len(ex_mod.get_symbols()):
            ex_mod.set_symbols(mod.get_symbols())
        # In any case, mark as present 
        ex_mod.set_present()
    else:
        # Just notify of module load
        add_module(p_pid, p_pgd, base, mod)
        # Mark the module as present
        mod.set_present()
        dispatch_module_load_callback(p_pid, p_pgd, base, size, basename, fullname)


def windows_insert_module(p_pid, p_pgd, module, update_symbols):
    '''
        Insert a module in the module list, only if it has not been inserted yet
    '''

    base = module.DllBase.v()
    if isinstance(base, obj.NoneObject):
        base = 0
    size = module.SizeOfImage.v()
    if isinstance(size, obj.NoneObject):
        size = 0
    fullname = module.FullDllName.v()
    if isinstance(fullname, obj.NoneObject):
        fullname = "Unknown"
    basename = module.BaseDllName.v()
    if isinstance(basename, obj.NoneObject):
        basename = "Unknown"
    checksum = module.CheckSum.v()
    if isinstance(checksum, obj.NoneObject):
        checksum = ""

    windows_insert_module_internal(
        p_pid,
        p_pgd,
        base,
        size,
        fullname,
        basename,
        checksum,
        update_symbols)


def windows_update_modules(pgd, update_symbols=False):
    '''
        Use volatility to get the modules and symbols for a given process, and
        update the cache accordingly
    '''
    global last_kdbg
    global symbol_cache_must_be_saved

    import api
    from utils import get_addr_space
    from vmi import set_modules_non_present
    from vmi import clean_non_present_modules
    from vmi import add_module
    from vmi import get_module
    from vmi import has_module

    if pgd != 0:
        addr_space = get_addr_space(pgd)
    else:
        addr_space = get_addr_space()

    if addr_space is None:
        pp_error("Volatility address space not loaded\n")
        return []

    # Get EPROC directly from its offset
    procs = api.get_process_list()
    inserted_bases = []
    # Parse/update kernel modules if pgd 0 is requested:
    if pgd == 0 and last_kdbg is not None:
        kdbg = obj.Object(
            "_KDDEBUGGER_DATA64",
            offset=last_kdbg,
            vm=addr_space)
        
        # List entries are returned, so that
        # we can monitor memory writes to these
        # entries and detect when a module is added
        # or removed
        list_entry_size = None
        list_entry_regions = []

        # Add the initial list pointer as a list entry
        list_entry_regions.append((kdbg.obj_offset, kdbg.PsLoadedModuleList.obj_offset, kdbg.PsLoadedModuleList.size()))

        # Mark all modules as non-present
        set_modules_non_present(0, 0)
        for module in kdbg.modules():
            if module.DllBase not in inserted_bases:
                inserted_bases.append(module.DllBase)
                windows_insert_module(0, 0, module, update_symbols)
                if list_entry_size is None:
                    list_entry_size = module.InLoadOrderLinks.size()
                list_entry_regions.append((module.obj_offset, module.InLoadOrderLinks.obj_offset, list_entry_size * 3))

        # Remove all the modules that are not marked as present
        clean_non_present_modules(0, 0)
  
        if symbol_cache_must_be_saved:
            from vmi import save_symbols_to_cache_file
            save_symbols_to_cache_file()
            symbol_cache_must_be_saved = False

        return list_entry_regions

    for proc in procs:
        p_pid = proc["pid"]
        p_pgd = proc["pgd"]
        # p_name = proc["name"]
        p_kernel_addr = proc["kaddr"]
        if p_pgd == pgd:
            task = obj.Object("_EPROCESS", offset=p_kernel_addr, vm=addr_space)

            # List entries are returned, so that
            # we can monitor memory writes to these
            # entries and detect when a module is added
            # or removed
            list_entry_size = None
            list_entry_regions = []

            scan_peb = True
            if task.Peb is None or not task.Peb.is_valid():
                if isinstance(task.Peb.obj_offset, int):
                    list_entry_regions.append((task.obj_offset, task.Peb.obj_offset, task.Peb.size()))
                scan_peb = False

            if task.Peb.Ldr is None or not task.Peb.Ldr.is_valid():
                list_entry_regions.append((task.Peb.v(), task.Peb.Ldr.obj_offset, task.Peb.Ldr.size()))
                scan_peb = False

            if scan_peb:
                # Add the initial list pointer as a list entry if we already have a PEB and LDR
                list_entry_regions.append((task.Peb.Ldr.dereference().obj_offset, task.Peb.Ldr.InLoadOrderModuleList.obj_offset, task.Peb.Ldr.InLoadOrderModuleList.size() * 3))
                
                # Note: we do not erase the modules we have information for from the list,
                # unless we have a different module loaded at the same base address.
                # In this way, if at some point the module gets unmapped from the PEB list
                # but it is still in memory, we do not loose the information.

                # Mark all modules as non-present
                set_modules_non_present(p_pid, p_pgd)

                for module in task.get_init_modules():
                    if module.DllBase not in inserted_bases:
                        inserted_bases.append(module.DllBase)
                        windows_insert_module(p_pid, p_pgd, module, update_symbols)
                        if list_entry_size is None:
                            list_entry_size = module.InLoadOrderLinks.size()
                        list_entry_regions.append((module.obj_offset, module.InLoadOrderLinks.obj_offset, list_entry_size * 3))

                for module in task.get_mem_modules():
                    if module.DllBase not in inserted_bases:
                        inserted_bases.append(module.DllBase)
                        windows_insert_module(p_pid, p_pgd, module, update_symbols)
                        if list_entry_size is None:
                            list_entry_size = module.InLoadOrderLinks.size()
                        list_entry_regions.append((module.obj_offset, module.InLoadOrderLinks.obj_offset, list_entry_size * 3))

                for module in task.get_load_modules():
                    if module.DllBase not in inserted_bases:
                        inserted_bases.append(module.DllBase)
                        windows_insert_module(p_pid, p_pgd, module, update_symbols)
                        if list_entry_size is None:
                            list_entry_size = module.InLoadOrderLinks.size()
                        list_entry_regions.append((module.obj_offset, module.InLoadOrderLinks.obj_offset, list_entry_size * 3))

                # Now, if we are a 64bit system and the process is a Wow64 process, traverse VAD 
                # to find the 32 bit modules

                if api.get_os_bits() == 64 and task.IsWow64:
                    for vad in task.VadRoot.traverse():
                        if vad is not None:
                            if hasattr(vad, "FileObject"):
                                f = vad.FileObject
                                if f is not None:
                                    fname = f.file_name_with_device()
                                    if fname and "Windows\\SysWOW64".lower() in fname.lower() and ".dll" == fname[-4:].lower():
                                        fname_starts = fname.find("Windows\\SysWOW64")
                                        fname = fname[fname_starts:]
                                        windows_insert_module_internal(p_pid, p_pgd, vad.Start,
                                                                       vad.End - vad.Start,
                                                                       fname,
                                                                       fname.split("\\")[-1],
                                                                       "",
                                                                       update_symbols,
                                                                       do_stop = True)
                # Remove all the modules that are not marked as present
                clean_non_present_modules(p_pid, p_pgd)

            if symbol_cache_must_be_saved:
                from vmi import save_symbols_to_cache_file
                save_symbols_to_cache_file()
                symbol_cache_must_be_saved = False

            return list_entry_regions

    return None 


def windows_kdbgscan_fast(dtb):
    global last_kdbg
    from utils import ConfigurationManager as conf_m

    try:
        config = conf_m.vol_conf
        config.DTB = dtb
        try:
            addr_space = utils.load_as(config)
        except BaseException:
            # Return silently
            conf_m.addr_space = None
            return 0L
        conf_m.addr_space = addr_space

        if obj.VolMagic(addr_space).KPCR.value:
            kpcr = obj.Object("_KPCR", offset=obj.VolMagic(
                addr_space).KPCR.value, vm=addr_space)
            kdbg = kpcr.get_kdbg()
            if kdbg.is_valid():
                last_kdbg = kdbg.obj_offset
                return long(last_kdbg)

        kdbg = obj.VolMagic(addr_space).KDBG.v()

        if kdbg.is_valid():
            last_kdbg = kdbg.obj_offset
            return long(last_kdbg)

        # skip the KPCR backup method for x64
        memmode = addr_space.profile.metadata.get('memory_model', '32bit')

        version = (addr_space.profile.metadata.get('major', 0),
                   addr_space.profile.metadata.get('minor', 0))

        if memmode == '32bit' or version <= (6, 1):

            # Fall back to finding it via the KPCR. We cannot
            # accept the first/best suggestion, because only
            # the KPCR for the first CPU allows us to find KDBG.
            for kpcr_off in obj.VolMagic(addr_space).KPCR.get_suggestions():

                kpcr = obj.Object("_KPCR", offset=kpcr_off, vm=addr_space)

                kdbg = kpcr.get_kdbg()

                if kdbg.is_valid():
                    last_kdbg = kdbg.obj_offset
                    return long(last_kdbg)
        return 0L
    except BaseException:
        traceback.print_exc()


def windows_read_memory_mapped(pgd, addr, size, pte, is_pae, bitness):
    # Step 1: Traverse the VAD tree for the process with PGD,
    #         and get the VAD that overlaps addr (if any)
    # Step 2: Check if the VAD has a ControlArea and a FilePointer, 
    #         and get the file path.
    # Step 3: Get Segment (pointed to by ControlArea), and get the pointer
    #         to the first PrototypePTE.
    # Step 4: Compute offset of address with respect to the beginning
    #         of the VAD, and compute which PrototypePTE corresponds to the address
    #         No need to consider if the PTE points to the Prototype PTE here.
    # Step 6: Compute the offset in file for such PrototypePTE by looking at the
    #         subsections pointed by the ControlArea.
    # Step 7: Finally, open the file, read the contents, and return them.
    import volatility.obj as obj
    import volatility.win32.tasks as tasks
    import volatility.plugins.vadinfo as vadinfo
    from utils import get_addr_space

    addr_space = get_addr_space(pgd)

    eprocs = [t for t in tasks.pslist(
        addr_space) if t.Pcb.DirectoryTableBase.v() == pgd]

    if len(eprocs) != 1:
        return None

    task = eprocs[0]
    vad = None
    # File name and offset
    for vad in task.VadRoot.traverse():
        if addr >= vad.Start and addr < vad.End:
            break
    if vad is None:
        return None
    
    filename = None
    if vad.ControlArea is not None and vad.FileObject is not None:
        filename = str(vad.ControlArea.FileObject.FileName)

    if vad.ControlArea.Segment is None:
        return None

    # Compute page offset with respect to Start of the VAD,
    # and the corresponding prototype Page Table Entry pointed
    # by the Segment
    offset_on_vad = addr - vad.Start
    page_offset_on_vad = (offset_on_vad - (offset_on_vad & 0xFFF))
    # Consider 4 KiB pages
    ppte_index = page_offset_on_vad / 0x1000
    
    if ppte_index >= vad.ControlArea.Segment.TotalNumberOfPtes.v():
        return None

    if bitness == 32 and is_pae:
        ppte_addr = vad.ControlArea.Segment.PrototypePte.v() + (ppte_index * 8)
    else:
        ppte_addr = vad.ControlArea.Segment.PrototypePte.v() + (ppte_index * addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][0])

    # Read Subsections pointed by ControlArea
    visited_subsections = {}
    if "Subsection" in vad.members:
        subsect = vad.Subsection
    # There is no Subsection pointer in VAD
    # structure, so we just read after the ControlArea
    else:
        subsect = obj.Object("_SUBSECTION", offset=(vad.ControlArea.v() + addr_space.profile.vtypes["_CONTROL_AREA"][0]), vm=addr_space)

    file_offset_to_read = None
    while file_offset_to_read is None and subsect is not None or subsect.v() != 0 and subsect.v() not in visited_subsections:
        visited_subsections.append(subsect.v())
        # Get the PPTE address where the Subsection starts,
        # and compute the virtual address that it corresponds 
        # to.
        ppte_addr = subsect.SubsectionBase.v()
        if bitness == 32 and is_pae:
            ppte_index = (subsect.SubsectionBase.v() - vad.ControlArea.Segment.PrototypePte.v()) / 8
        else:
            ppte_index = (subsect.SubsectionBase.v() - vad.ControlArea.Segment.PrototypePte.v()) / addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][0]

        subsection_base = vad.Start + (ppte_index * 0x1000)
        subsection_size = subsect.PtesInSubsection.v() * 0x1000
        subsection_file_offset = subsect.StartingSector.v() * 512
        subsection_file_size = vad.Subsection.NumberOfFullSectors.v() * 512 

        visited_subsections[subsect.v()] = (subsection_base, 
                                            subsection_size, 
                                            subsection_file_offset,
                                            subsection_file_size)

        if (addr >= subsection_base) and (addr < (subsection_base + subsection_size)):
            file_offset_to_read = (addr - subsection_base) + subsection_file_offset

        subsect = subsect.NextSubsection

    f = None
    for fs in api.get_filesystems():
        try:
            f = api.open_guest_path(fs["index"], filename)
            break
        except:
            # The file cannot be open on such filesystem
            pass
    if not f:
        raise RuntimeError("Could not read memory from pagefile: file not found")

    # print("Reading file %s at offset %x - Size: %x" % (filename, file_offset_to_read, size))
    f.seek(file_offset_to_read)
    data = f.read(size = size)
    f.close()


def windows_get_prototype_pte_address_range(pgd, address):
    import volatility.obj as obj
    import volatility.win32.tasks as tasks
    import volatility.plugins.vadinfo as vadinfo
    from utils import get_addr_space

    addr_space = get_addr_space(pgd)

    eprocs = [t for t in tasks.pslist(
        addr_space) if t.Pcb.DirectoryTableBase.v() == pgd]

    if len(eprocs) != 1:
        return None

    task = eprocs[0]
    vad = None
    # File name and offset
    for vad in task.VadRoot.traverse():
        if address >= vad.Start and address < vad.End:
            break

    if vad is None:
        return None

    if vad.ControlArea is not None and vad.ControlArea.Segment is not None:
        start = vad.ControlArea.Segment.PrototypePte.v()
        end = start + (vad.ControlArea.Segment.TotalNumberOfPtes.v() * addr_space.profile.vtypes["_MMPTE_SOFTWARE"][0])
        return (start,end)
    else:
        return None


def windows_read_paged_file(pgd, addr, size, page_file_offset, page_file_number):
    import api
    # Step 1: Select the page file
    pagefile_filename = "pagefile.sys"
    # Step 2: Read the page file at the given offset
    f = None
    for fs in api.get_filesystems():
        try:
            f = api.open_guest_path(fs["index"], pagefile_filename)
            break
        except:
            # The file cannot be open on such filesystem
            pass
    if not f:
        raise RuntimeError("Could not read memory from pagefile: file not found")

    f.seek(page_file_offset)
    data = f.read(size = size)
    f.close()
    # Step 3: Return the data
    return data


def generate_mask(start_bit, end_bit):
    mask = 0x0
    i = start_bit
    while i < end_bit:
        mask |= 0x1 << i
        i += 1
    return mask


def windows_read_paged_out_memory(pgd, addr, size):
    import api
    import api_internal
    import struct
    from utils import get_addr_space
    
    VALID_BIT = 0x1
    PROTOTYPE_BIT = 0x1 << 10
    TRANSITION_BIT = 0x1 << 11

    PPTE_VALID_BIT = 0x1
    PPTE_TRANSITION_BIT = 0x1 << 11
    PPTE_DIRTY_BIT = 0x1 << 6
    PPTE_P_BIT = 0x1 << 10 # Thit bit means it is a... 
    #...memory mapped file,  instead of "prototype"

    # Get PTE and 'mode'
    pte = api_internal.x86_get_pte(pgd, addr)
    is_pae = api_internal.x86_is_pae()
    bitness = api.get_os_bits()

    addr_space = get_addr_space(pgd)

    # if PTE is None, it could mean that the page directory has not been created.
    # if PTE is 0, it could mean the pte has not been yet created.
    # In these cases, we still check the VAD to see if it corresponds to a 
    # memory mapped file, and if so, read that file at the correct offset
    if pte is None or pte == 0:
        return windows_read_memory_mapped(pgd, addr, size, pte, is_pae, bitness)

    # Make sure the page is invalid and we cannot read it:
    if (pte & VALID_BIT) == 1:
        return api.r_va(pgd, addr, size)

    # The PTE is INVALID. First, we check it doesn't point to a 
    # prototype page table entry (PPTE).
    if (pte & PROTOTYPE_BIT) == 0:
        # The page is in the pagefile, or is demand zero, or memory mapped
        if (pte & TRANSITION_BIT) == 0:
            number_bits_offset = 0 
            number_bits_number = 0
            page_file_offset = 0
            page_file_number = 0
            if (bitness == 32 and not is_pae) or bitness == 64:
                offset_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileHigh"][1][1]["start_bit"],
                                            addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileHigh"][1][1]["end_bit"])
                number_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"],
                                            addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["end_bit"])
                number_bits_offset = addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileHigh"][1][1]["end_bit"] - \
                                     addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileHigh"][1][1]["start_bit"]
                number_bits_number = addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["end_bit"] - \
                                     addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"]
                page_file_offset = (pte & offset_mask) >> addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileHigh"][1][1]["start_bit"]
                page_file_number = (pte & number_mask) >> addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"]
            elif bitness == 32 and is_pae:
                # See Intel manual, consider 24 bits of address for the 4KiB page offset
                # Page file offset should correspond to the same 24 bits
                offset_mask = generate_mask(12, 12 + 24)
                # Reuse the same as for 32/64 bits
                number_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"],
                                            addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["end_bit"])
                number_bits_offset = 24 
                number_bits_number = addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["end_bit"] - \
                                     addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"]
                page_file_offset = (pte & offset_mask) >> 12
                page_file_number = (pte & number_mask) >> addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"]

            else:
                raise NotImplementedError()

            #Demand zero
            if page_file_offset == 0x0:
                return "\x00" * size
            #Check VAD (memory mapped file) (all 1's)
            elif page_file_offset == generate_mask(0, number_bits_offset):
                return windows_read_memory_mapped(pgd, addr, size, pte, is_pae, bitness)
            # Page file
            else:
                return windows_read_paged_file(pgd, addr, size, page_file_offset, page_file_number)
        # Transition page -> Can be read normally from memory, 
        # so proceed with the read even if valid bit is 0.
        else:
            # Get the offset from the PTE, and compute ourselves the physical address
            page_offset = 0
            if (bitness == 32 and not is_pae) or bitness == 64:
                offset_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_HARDWARE"][1]["PageFrameNumber"][1][1]["start_bit"],
                                            addr_space.profile.vtypes["_MMPTE_HARDWARE"][1]["PageFrameNumber"][1][1]["end_bit"])
                page_offset = (pte & offset_mask)
            elif bitness == 32 and is_pae:
                # See Intel manual, consider 24 bits of address for the 4KiB page offset
                # Page file offset should correspond to the same 24 bits
                offset_mask = generate_mask(12, 12 + 24)
                # Reuse the same as for 32/64 bits
                page_offset = (pte & offset_mask)
            else:
                raise NotImplementedError()
            # Read physical address, always 12 bits for a 4KiB page.
            # XXX: Here, we should should also consider 4Mb pages.
            return api.r_pa(page_offset | (addr & generate_mask(0, 12)), size)
    # The page points to a prototype PTE
    else:
        # We read the PPTE
        ppte_addr = 0 
        ppte_size = 0
        if bitness == 32 and not is_pae:
            # In this case, the PPTE pointer is not a pointer, but an index, so it 
            # needs some additional computation
            index_low_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddressLow"][1][1]["start_bit"],
                                        addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddressLow"][1][1]["end_bit"])
            index_low = (pte & index_low_mask) >> addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddressLow"][1][1]["start_bit"]

            index_high_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddressHigh"][1][1]["start_bit"],
                                        addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddressHigh"][1][1]["end_bit"])
            index_high = (pte & index_high_mask) >> addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddressHigh"][1][1]["start_bit"]

            number_bits_index_low = addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddressLow"][1][1]["end_bit"]- \
                                        addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddressLow"][1][1]["start_bit"]

            ppte_size = addr_space.profile.vtypes["_MMPTE"][0]

            # Formula to compute the index
            index = ((index_high << number_bits_index_low) | index_low) << 2

            # The index is an address relative to the base of a paged pool.
            # By debugging several systems, these bases where fixed (on 32 bit systems)
            # to 0x80000000 or 0xe1000000 (windows 7 and windows xp respectively).
            # This address points to one of the PrototypePTEs that are part of the Segment, 
            # pointed out by the ControlArea of the corresponding VAD. Therefore, we should
            # be able to bruteforce the first 8 bits of the address to find the correct base.
            # First, get the Segment, and the first prototype PTE, as well as the number of
            # prototype PTEs for that Segment.
            res = windows_get_prototype_pte_address_range(pgd, addr)
            found = False
            if res is not None:
                start, end = res
                for i in range(0, 255):
                    ppte_addr = (i << 24) | index
                    if ppte_addr >= start and ppte_addr <= end:
                        found = True
                        break
                if not found:
                    raise RuntimeError("Could not read memory on second chance (using filesystem)")
            else:
                raise RuntimeError("Could not read memory on second chance (using filesystem)")

        elif bitness == 32 and is_pae:
            # According to paper: "Windows Operating Systems Agnostic Memory Analysis"
            offset_mask = generate_mask(32, 64)
            ppte_addr = (pte & offset_mask) >> 32 
            ppte_size = 64

        elif bitness == 64:
            offset_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddress"][1][1]["start_bit"],
                                        addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddress"][1][1]["end_bit"])
            ppte_addr = (pte & offset_mask) >> addr_space.profile.vtypes["_MMPTE_PROTOTYPE"][1]["ProtoAddress"][1][1]["start_bit"]
            ppte_size = addr_space.profile.vtypes["_MMPTE"][0]

        else:
            raise NotImplementedError()

        # Now, read the PPTE given its address. The PPTE address is a virtual address!!!! (on a paged pool)
        if ppte_size == 4:
            ppte = struct.unpack("<I", api.r_va(pgd, ppte_addr, 4))[0]
        elif ppte_size == 8:
            ppte = struct.unpack("<Q", api.r_va(pgd, ppte_addr, 8))[0]
        else:
            raise NotImplementedError()

        if (ppte & PPTE_VALID_BIT == 1) or (ppte & PPTE_TRANSITION_BIT == 1):
            # State: Active/Valid - Transision - Modified-no-write
            # The PPTE contains a valid entry, so we can
            # just use the info in it to translate the page.
            # Get the offset from the PTE, and compute ourselves the physical address
            page_offset = 0
            if (bitness == 32 and not is_pae) or bitness == 64:
                offset_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_HARDWARE"][1]["PageFrameNumber"][1][1]["start_bit"],
                                            addr_space.profile.vtypes["_MMPTE_HARDWARE"][1]["PageFrameNumber"][1][1]["end_bit"])
                page_offset = (ppte & offset_mask)
            elif bitness == 32 and is_pae:
                # See Intel manual, consider 24 bits of address for the 4KiB page offset
                # Page file offset should correspond to the same 24 bits
                offset_mask = generate_mask(12, 12 + 24)
                # Reuse the same as for 32/64 bits
                page_offset = (ppte & offset_mask)
            else:
                raise NotImplementedError()

            # Read physical address, always 12 bits for a 4KiB page.
            # XXX: Here, we should should also consider 4Mb pages.
            return api.r_pa(page_offset | (addr & generate_mask(0, 12)), size)
        elif (ppte & (PPTE_VALID_BIT | PPTE_TRANSITION_BIT | PPTE_P_BIT)) == 0:
            # Demand zero or pagefile
            #Read page_file_offset and page_file_number
            page_file_offset = 0
            page_file_number = 0
            if (bitness == 32 and not is_pae) or bitness == 64:
                offset_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileHigh"][1][1]["start_bit"],
                                            addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileHigh"][1][1]["end_bit"])
                number_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"],
                                            addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["end_bit"])
                page_file_offset = (pte & offset_mask) >> addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileHigh"][1][1]["start_bit"]
                page_file_number = (pte & number_mask) >> addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"]
            elif bitness == 32 and is_pae:
                # See Intel manual, consider 24 bits of address for the 4KiB page offset
                # Page file offset should correspond to the same 24 bits
                offset_mask = generate_mask(12, 12 + 24)
                # Reuse the same as for 32/64 bits
                number_mask = generate_mask(addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"],
                                            addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["end_bit"])
                page_file_offset = (pte & offset_mask) >> 12
                page_file_number = (pte & number_mask) >> addr_space.profile.vtypes["_MMPTE_SOFTWARE"][1]["PageFileLow"][1][1]["start_bit"]
            else:
                raise NotImplementedError()

            if page_file_offset == 0 and page_file_number == 0:
                #Demand zero
                return "\x00" * size
            else:
                # PageFile
                return windows_read_paged_file(pgd, addr, size, page_file_offset, page_file_number)
        elif (ppte & PPTE_P_BIT) == 1:
            # Memory mapped file
            return windows_read_memory_mapped(pgd, addr, size, ppte, is_pae, bitness)

def get_system_time():
    from volatility import obj
    from utils import get_addr_space
    addr_space = get_addr_space()
    k = obj.Object("_KUSER_SHARED_DATA", offset = obj.VolMagic(addr_space).KUSER_SHARED_DATA.v(), vm = addr_space)
    return k.SystemTime.as_datetime()

def get_threads():
    from volatility.plugins.malware.threads import Threads
    from utils import ConfigurationManager as conf_m

    # Use the threads plugin to retrieve thread data
    # Code partially obtained from volatility.plugins.malware.threads

    results = []

    config = conf_m.vol_conf
    t = Threads(config, light_mode = True)

    # Each returned item has a pid, a tid, and a variable
    # set of attributes
    for thread, addr_space, mods, mod_addrs, \
                 instances, hooked_tables, system_range, owner_name in t.calculate():

        element = {}
        element['tags'] = set([t for t, v in instances.items() if v.check()])

        element['pid'] = int(thread.Cid.UniqueProcess)
        element['tid'] = int(thread.Cid.UniqueThread)
        element['thread_object_base'] = thread.Tcb.v()
        element['pgd'] = int(thread.attached_process().Pcb.DirectoryTableBase)

        element['id'] = element['tid']

        element['created'] = str(thread.CreateTime)
        element['exited'] = str(thread.ExitTime)
        element['process_name'] = str(
            thread.owning_process().ImageFileName)
        element['attached_process_name'] = str(
            thread.attached_process().ImageFileName)

        # Lookup the thread's state
        state = str(thread.Tcb.State)

        # Append the wait reason
        if state == 'Waiting':
            state = state + ':' + str(thread.Tcb.WaitReason)

        element['state'] = str(state)
        element['base_priority'] = int(thread.Tcb.BasePriority)
        element['priority'] = int(thread.Tcb.Priority)
        element['teb'] = int(thread.Tcb.Teb)
        element['start_address'] = int(thread.StartAddress)
        element['start_address_owner_name'] = str(owner_name)
        element['running'] = None 
        
        results.append(element)

    results = sorted(results,  key=lambda k: k['pid'])
    set_running_threads(results)
    return results
    

def set_running_threads(thread_list):
    from api import get_num_cpus
    from api import r_cpu
    from api import is_kernel_running
    from api import r_va
    import struct
    from cpus import X86CPU
    from cpus import X64CPU

    num_cpus = get_num_cpus()

    for cpu_index in range(0, num_cpus):
        cpu = r_cpu(cpu_index)
        if not is_kernel_running(cpu_index):
            # User mode: Get the TEB address from the TIB, and compare.
            # The TIB is pointed by the FS register (in 32 bits) or the gs register
            # in 64 bit.
            if isinstance(cpu, X86CPU):
                # In 32 bits, use fs register
                teb_addr = r_va(cpu.CR3, cpu.FS["base"] + 0x18, 4)
                if teb_addr:
                    teb_addr = struct.unpack("<I", teb_addr)[0]
            elif isinstance(cpu, X64CPU):
                # In 64 bits, use gs register
                teb_addr = r_va(cpu.CR3, cpu.GS["base"] + 0x30, 8)
                if teb_addr:
                    teb_addr = struct.unpack("<Q", teb_addr)[0]
            if teb_addr:
                # Now, go through the list of threads and find the one with the same TEB
                for element in thread_list:
                    if element['teb'] == teb_addr and element['pgd'] == cpu.CR3:
                        element['running'] = cpu_index
            else:
                raise NotImplementedError("Windows set_running_threads: Architecture of type %s not implemented yet" % str(type(cpu)))
        else:
            from utils import ConfigurationManager as conf_m
            # Kernel mode: For each CPU, KPCR->PCRB->CurrentThread
            if isinstance(cpu, X86CPU):
                # In 32 bits, use fs register
                kpcr_addr = cpu.FS["base"]
                kpcr = obj.Object("_KPCR", offset=kpcr_addr, vm=conf_m.addr_space)
                self_kpcr_addr = kpcr.SelfPcr.v()
            elif isinstance(cpu, X64CPU):
                # In 64 bits, use gs register
                kpcr_addr = cpu.GS["base"]
                kpcr = obj.Object("_KPCR", offset=kpcr_addr, vm=conf_m.addr_space)
                self_kpcr_addr = kpcr.Self.v()
            if self_kpcr_addr == kpcr_addr:
                current_thread = kpcr.ProcessorBlock.CurrentThread.dereference_as("_ETHREAD")
                if current_thread:
                    for element in thread_list:
                        if element["thread_object_base"] == current_thread.obj_offset:
                            element['running'] = cpu_index
            else:
                raise NotImplementedError("Windows set_running_threads: Architecture of type %s not implemented yet" % str(type(cpu)))

def win_read_thread_register_from_ktrap_frame(thread, reg_name):
    """ Get a register from a threads trap frame """
    from utils import ConfigurationManager as conf_m

    vol_thread = obj.Object("_ETHREAD", offset=thread['thread_object_base'], vm=conf_m.addr_space)
    try:
        trap = vol_thread.Tcb.TrapFrame.dereference_as("_KTRAP_FRAME")
    except:
        return 0
    if isinstance(trap, obj.NoneObject):
        return 0
    # Silently fall back to 0
    try:
        value = getattr(trap, reg_name).v()
    except:
        value = 0
    if value == -1:
        value = 0
    return value

def win_write_thread_register_in_ktrap_frame(thread, reg_name, buf, size):
    """ Get a register from a threads trap frame """
    from utils import ConfigurationManager as conf_m

    vol_thread = obj.Object("_ETHREAD", offset=thread['thread_object_base'], vm=conf_m.addr_space)
    try:
        trap = vol_thread.Tcb.TrapFrame.dereference_as("_KTRAP_FRAME")
    except:
        return 0
    if isinstance(trap, obj.NoneObject):
        return 0
    # Silently fall back to 0
    try:
        offset = getattr(trap, reg_name).obj_offset
        from api import w_va
        w_va(thread['pgd'], offset, buf, size)
        return size
    except:
        return 0 
    if value < 0:
        value = 0
    return value
