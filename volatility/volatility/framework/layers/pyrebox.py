# -------------------------------------------------------------------------
#
#   Copyright (C) 2019 Cisco Talos Security Intelligence and Research Group
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

import threading
from typing import Any, Dict, IO, List, Optional, Union

from volatility.framework import exceptions, interfaces, constants
from volatility.framework.configuration import requirements
from volatility.framework.layers import resources

from profilehooks import profile

class DummyLock:

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        pass

class PyREBoxLayer(interfaces.layers.DataLayerInterface):
    """a DataLayer backed by QEMU/PyREBox live memory."""

    # We give it higher priority, so when this file is present, 
    # it is the first one to be checked. 
    priority = 40

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        
        # Set metadata according to PyREBox live data:
        # We need: architecture, platorm, and DTB (page_map_offset - (CR3) (windows)). That will make
        # scanning way faster.
        from api import r_cpu
        arch = None 
        import api
        if api.get_os_bits() == 32:
            arch  = 'Intel32'
        elif api.get_os_bits() == 64:
            arch  = 'Intel64'
        else:
            raise Exception("OS bits is not 32 or 64 bits")

        metadata = {'os': 'Windows',
                    'architecture': 'Intel64',
                    'page_map_offset':  r_cpu().CR3}
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)

        # We don't really need the location, but the layer-stacker (stacker.py) requires to specify a "single_location"
        # so it will be provided anyway.
        self._location = self.config["location"]
        self._max_address = None  # type: Optional[int]
        # Construct the lock now (shared if made before threading) in case we ever need it
        self._lock = DummyLock()  # type: Union[DummyLock, threading.Lock]
        if constants.PARALLELISM == constants.Parallelism.Threading:
            self._lock = threading.Lock()

    @property
    def location(self) -> str:
        """Returns the location on which this Layer abstracts."""
        return self._location

    @property
    def maximum_address(self) -> int:
        """Returns the largest available address in the space."""
        # Zero based, so we return the size of the file minus 1
        if self._max_address:
            return self._max_address
        with self._lock:
            import api_internal
            self._max_address = (api_internal.vol_get_memory_size() - 1) or 0
        return self._max_address

    @property
    def minimum_address(self) -> int:
        """Returns the smallest available address in the space."""
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the offset is valid or not."""
        if length <= 0:
            raise TypeError("Length must be positive")
        return bool(self.minimum_address <= offset <= self.maximum_address
                    and self.minimum_address <= offset + length - 1 <= self.maximum_address)

    #@profile(stdout = True, immediate=True)
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from the file at offset for length."""
        import api_internal
        if not self.is_valid(offset, length):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Offset outside of the buffer boundaries")

        # TODO: implement locking for multi-threading
        with self._lock:
            data = b''
            try:
                # Split the requests into smaller chunks
                block_length = 1024*4*4096
                read_length = 0
                while read_length < length:
                    # Send read request
                    read_len = block_length
                    if length-read_length < read_len:
                        read_len = length-read_length
                    temp_mem = api_internal.vol_read_memory(offset+read_length, read_len)
                    if temp_mem is None:
                        raise AssertionError("PyREBoxLayer: READ of length " + 
                            str(read_length) + '/' + str(length) +
                            " @ " + hex(offset) + " failed.")

                    else:
                        data += temp_mem 
                    read_length += read_len
            except AssertionError as e:
                print(e)
                data = b''

        if len(data) < length:
            if pad:
                data += (b"\x00" * (length - len(data)))
            else:
                raise exceptions.InvalidAddressException(
                    self.name, offset + len(data), "Could not read sufficient bytes from the " + self.name + " file")
        return data

    def write(self, offset: int, data: bytes) -> None:
        """Writes to the file.

        This will technically allow writes beyond the extent of the file
        """
        import api_internal
        if not self.is_valid(offset, len(data)):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Data segment outside of the " + self.name + " file boundaries")
        with self._lock:
            try:
                length = len(data)
                # Send write request
                result = api_internal.vol_write_memory(offset, length, data)
                if result is None:
                    raise AssertionError("PyREBoxLayer: WRITE of length " + str(length) +
                                         " @ " + hex(offset) + " failed.")
            except AssertionError as e:
                print(e)

    def __getstate__(self) -> Dict[str, Any]:
        """Return __dict__"""
        return self.__dict__

    def destroy(self) -> None:
        """We don't need to do anything here."""
        pass

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.StringRequirement(name = 'location', optional = False)]
