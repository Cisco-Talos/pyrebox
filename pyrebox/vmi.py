#-------------------------------------------------------------------------------
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
#-------------------------------------------------------------------------------

import sys
import traceback

#symbol cache
symbols = {}

modules = {} #List of modules for each process, index is pgd

class Module:
    def __init__(self,base,size,pid,pgd,checksum,name,fullname):
        self.__base = base
        self.__size = size
        self.__pid = pid
        self.__pgd = pgd
        self.__checksum = checksum
        self.__name = name
        self.__fullname = fullname
        self.__symbols = []
    #Getters
    def get_base(self):
        return self.__base
    def get_size(self):
        return self.__size
    def get_pid(self):
        return self.__pid
    def get_pgd(self):
        return self.__pgd
    def get_name(self):
        return self.__name
    def get_fullname(self):
        return self.__fullname
    def get_symbols(self):
        return self.__symbols
    def get_checksum(self):
        return self.__checksum
    #Setters
    def set_base(self,base):
        self.__base = base
    def set_size(self,size):
        self.__size = size
    def set_pid(self,pid):
        self.__pid = pid
    def set_pgd(self,pgd):
        self.__pgd = pgd
    def set_name(self,name):
        self.__name = name
    def set_fullname(self,fullname):
        self.__fullname = fullname
    def set_checksum(self,checksum):
        self.__checksum = checksum
    def set_symbols(self,syms):
        self.__symbols = syms 

class PseudoLDRDATA:
    '''
        Used to trick volatility to let it parse the export table
    '''
    def __init__(self,base,name,export_directory):
        self.DllBase = base
        self.BaseDllName = name
        self.export_directory = export_directory
    def export_dir(self):
        return self.export_directory
