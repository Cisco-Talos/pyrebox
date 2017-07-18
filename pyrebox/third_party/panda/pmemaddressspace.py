#!/usr/bin/python

from __future__ import print_function
import volatility.addrspace as addrspace
import urllib
import socket
import struct
import sys
import api_internal

class PMemAddressSpace(addrspace.BaseAddressSpace):
    def __init__(self, base, config, **kwargs):
        '''
        Initializes the address space with volatility
        '''
        # Address space setup
        self.as_assert(base == None, "Must be first Address Space")
        addrspace.BaseAddressSpace.__init__(self, None, config, **kwargs)

    def close(self):
        '''
        '''
        pass

    def __del__(self):
      self.close()
   
    def __read_bytes(self, addr, length, pad):
        '''
        Reads data using PMemAccess
        '''
        memory = ''
        try:
            # Split the requests into smaller chunks
            block_length = 1024*4
            read_length = 0
            while read_length < length:
                # Send read request
                read_len = block_length
                if length-read_length < read_len:
                    read_len = length-read_length
                temp_mem = api_internal.vol_read_memory(addr+read_length, read_len)
                if temp_mem is None:
                    raise AssertionError("PMemAddressSpace: READ of length " + 
                        str(read_length) + '/' + str(length) +
                        " @ " + hex(addr) + " failed.")

                else:
                    memory += temp_mem 
                read_length += read_len
        except AssertionError as e:
            print(e)
            memory = ''
        if pad:
            if memory is None:
                memory = "\x00" * length
            elif len(memory) != length:
                memory += "\x00" * (length - len(memory))
            return memory
        else:
            return memory

    def read(self, addr, length):
        return self.__read_bytes(addr, length, pad=False)

    def zread(self, addr, length):
        return self.__read_bytes(addr, length, pad=True)

    def read_long(self, addr):
        string = self.read(addr, 4)
        longval, = self._long_struct.unpack(string)
        return longval

    def get_memory_size(self):
        return api_internal.vol_get_memory_size() or 0

    def get_available_addresses(self):
        # Since the second parameter is the length of the run
        # not the end location, it must be set to fsize, not fsize - 1
        yield (0,self.get_memory_size())

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return True

    def write(self, addr, data):
        '''
        Writes data using PMemAccess
        '''
        try:
            length = len(data)
            # Send write request
            result = api_internal.vol_write_memory(addr, length, data)
            if result is None:
                raise AssertionError("PMemAddressSpace: WRITE of length " + str(length) +
                                     " @ " + hex(addr) + " failed.")
        except AssertionError as e:
            print(e)
            return False
        return True
