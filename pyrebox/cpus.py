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


class X86CPU:
    reg_nums = {"EAX": 0,
                "ECX": 1,
                "EDX": 2,
                "EBX": 3,
                "ESP": 4,
                "EBP": 5,
                "ESI": 6,
                "EDI": 7,
                "EIP": 8,
                "EFLAGS": 9,
                "ES": 10,
                "CS": 11,
                "SS": 12,
                "DS": 13,
                "FS": 14,
                "GS": 15,
                "LDT": 16,
                "TR": 17,
                "GDT": 18,
                "IDT": 19,
                "CR0": 20,
                "CR1": 21,
                "CR2": 22,
                "CR3": 23,
                "CR4": 24}

    def __init__(self, *args):
        self.EAX = 0
        self.ECX = 0
        self.EDX = 0
        self.EBX = 0
        self.ESP = 0
        self.EBP = 0
        self.ESI = 0
        self.EDI = 0
        self.EIP = 0
        self.EFLAGS = 0
        self.ES = 0
        self.CS = 0
        self.SS = 0
        self.DS = 0
        self.FS = 0
        self.GS = 0
        self.LDT = 0
        self.TR = 0
        self.GDT = 0
        self.IDT = 0
        self.CR0 = 0
        self.CR1 = 0
        self.CR2 = 0
        self.CR3 = 0
        self.CR4 = 0
        self.CPU_INDEX = 0
        self.PC = 0
        if len(args) > 0:
            self.EAX = args[0]
            self.ECX = args[1]
            self.EDX = args[2]
            self.EBX = args[3]
            self.ESP = args[4]
            self.EBP = args[5]
            self.ESI = args[6]
            self.EDI = args[7]
            self.EIP = args[8]
            self.EFLAGS = args[9]
            self.ES = {
                "sel": args[10][0],
                "base": args[10][1],
                "size": args[10][2],
                "flags": args[10][3]}
            self.CS = {
                "sel": args[11][0],
                "base": args[11][1],
                "size": args[11][2],
                "flags": args[11][3]}
            self.SS = {
                "sel": args[12][0],
                "base": args[12][1],
                "size": args[12][2],
                "flags": args[12][3]}
            self.DS = {
                "sel": args[13][0],
                "base": args[13][1],
                "size": args[13][2],
                "flags": args[13][3]}
            self.FS = {
                "sel": args[14][0],
                "base": args[14][1],
                "size": args[14][2],
                "flags": args[14][3]}
            self.GS = {
                "sel": args[15][0],
                "base": args[15][1],
                "size": args[15][2],
                "flags": args[15][3]}
            self.LDT = {
                "sel": args[16][0],
                "base": args[16][1],
                "size": args[16][2],
                "flags": args[16][3]}
            self.TR = {
                "sel": args[17][0],
                "base": args[17][1],
                "size": args[17][2],
                "flags": args[17][3]}
            self.GDT = {
                "sel": args[18][0],
                "base": args[18][1],
                "size": args[18][2],
                "flags": args[18][3]}
            self.IDT = {
                "sel": args[19][0],
                "base": args[19][1],
                "size": args[19][2],
                "flags": args[19][3]}
            self.CR0 = args[20]
            self.CR1 = args[21]
            self.CR2 = args[22]
            self.CR3 = args[23]
            self.CR4 = args[24]
            self.CPU_INDEX = args[25]
            self.PC = self.EIP

    def __str__(self):
        result = ""
        result += "========================================\n"
        result += "               CPU %d\n" % self.CPU_INDEX
        result += "========================================\n"
        result += "EAX      0x%08x\n" % self.EAX
        result += "ECX      0x%08x\n" % self.ECX
        result += "EDX      0x%08x\n" % self.EDX
        result += "EBX      0x%08x\n" % self.EBX
        result += "\n"
        result += "ESP      0x%08x\n" % self.ESP
        result += "EBP      0x%08x\n" % self.EBP
        result += "\n"
        result += "ESI:     0x%08x\n" % self.ESI
        result += "EDI:     0x%08x\n" % self.EDI
        result += "\n"
        result += "EIP:     0x%08x\n" % self.EIP
        result += "EFLAGS:  0x%08x\n" % self.EFLAGS
        result += "\n"
        result += "CR0:     0x%08x\n" % self.CR0
        result += "CR1:     0x%08x\n" % self.CR1
        result += "CR2:     0x%08x\n" % self.CR2
        result += "CR3:     0x%08x\n" % self.CR3
        result += "CR4:     0x%08x\n" % self.CR4
        result += "\n"
        result += "ES:      Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.ES["sel"], self.ES["base"], self.ES["size"], self.ES["flags"])
        result += "CS:      Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.CS["sel"], self.CS["base"], self.CS["size"], self.CS["flags"])
        result += "SS:      Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.SS["sel"], self.SS["base"], self.SS["size"], self.SS["flags"])
        result += "DS:      Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.DS["sel"], self.DS["base"], self.DS["size"], self.DS["flags"])
        result += "FS:      Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.FS["sel"], self.FS["base"], self.FS["size"], self.FS["flags"])
        result += "GS:      Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.GS["sel"], self.GS["base"], self.GS["size"], self.GS["flags"])
        result += "LDT:     Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.LDT["sel"], self.LDT["base"], self.LDT["size"], self.LDT["flags"])
        result += "GDT:     Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.GDT["sel"], self.GDT["base"], self.GDT["size"], self.GDT["flags"])
        result += "IDT:     Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.IDT["sel"], self.IDT["base"], self.IDT["size"], self.IDT["flags"])
        result += "TR:      Sel: %08x   Base: %08x   Size: %08x   Flags: %08x\n" % (
            self.TR["sel"], self.TR["base"], self.TR["size"], self.TR["flags"])
        return result


class X64CPU:
    reg_nums = {"RAX": 0,
                "RCX": 1,
                "RDX": 2,
                "RBX": 3,
                "RSP": 4,
                "RBP": 5,
                "RSI": 6,
                "RDI": 7,
                "RIP": 8,
                "RFLAGS": 9,
                "ES": 10,
                "CS": 11,
                "SS": 12,
                "DS": 13,
                "FS": 14,
                "GS": 15,
                "LDT": 16,
                "TR": 17,
                "GDT": 18,
                "IDT": 19,
                "CR0": 20,
                "CR1": 21,
                "CR2": 22,
                "CR3": 23,
                "CR4": 24,
                "R8": 26,
                "R9": 27,
                "R10": 28,
                "R11": 29,
                "R12": 30,
                "R13": 31,
                "R14": 32,
                "R15": 33}

    def __init__(self, *args):
        self.RAX = 0
        self.RCX = 0
        self.RDX = 0
        self.RBX = 0
        self.RSP = 0
        self.RBP = 0
        self.RSI = 0
        self.RDI = 0
        self.RIP = 0
        self.RFLAGS = 0
        self.ES = 0
        self.CS = 0
        self.SS = 0
        self.DS = 0
        self.FS = 0
        self.GS = 0
        self.LDT = 0
        self.TR = 0
        self.GDT = 0
        self.IDT = 0
        self.CR0 = 0
        self.CR1 = 0
        self.CR2 = 0
        self.CR3 = 0
        self.CR4 = 0
        self.CPU_INDEX = 0
        # 64 Bits
        self.R8 = 0
        self.R9 = 0
        self.R10 = 0
        self.R11 = 0
        self.R12 = 0
        self.R13 = 0
        self.R14 = 0
        self.R15 = 0
        self.PC = 0
        if len(args) > 0:
            self.RAX = args[0]
            self.RCX = args[1]
            self.RDX = args[2]
            self.RBX = args[3]
            self.RSP = args[4]
            self.RBP = args[5]
            self.RSI = args[6]
            self.RDI = args[7]
            self.RIP = args[8]
            self.RFLAGS = args[9]
            self.ES = {
                "sel": args[10][0],
                "base": args[10][1],
                "size": args[10][2],
                "flags": args[10][3]}
            self.CS = {
                "sel": args[11][0],
                "base": args[11][1],
                "size": args[11][2],
                "flags": args[11][3]}
            self.SS = {
                "sel": args[12][0],
                "base": args[12][1],
                "size": args[12][2],
                "flags": args[12][3]}
            self.DS = {
                "sel": args[13][0],
                "base": args[13][1],
                "size": args[13][2],
                "flags": args[13][3]}
            self.FS = {
                "sel": args[14][0],
                "base": args[14][1],
                "size": args[14][2],
                "flags": args[14][3]}
            self.GS = {
                "sel": args[15][0],
                "base": args[15][1],
                "size": args[15][2],
                "flags": args[15][3]}
            self.LDT = {
                "sel": args[16][0],
                "base": args[16][1],
                "size": args[16][2],
                "flags": args[16][3]}
            self.TR = {
                "sel": args[17][0],
                "base": args[17][1],
                "size": args[17][2],
                "flags": args[17][3]}
            self.GDT = {
                "sel": args[18][0],
                "base": args[18][1],
                "size": args[18][2],
                "flags": args[18][3]}
            self.IDT = {
                "sel": args[19][0],
                "base": args[19][1],
                "size": args[19][2],
                "flags": args[19][3]}
            self.CR0 = args[20]
            self.CR1 = args[21]
            self.CR2 = args[22]
            self.CR3 = args[23]
            self.CR4 = args[24]
            self.CPU_INDEX = args[25]
            # 64 Bits
            self.R8 = args[26]
            self.R9 = args[27]
            self.R10 = args[28]
            self.R11 = args[29]
            self.R12 = args[30]
            self.R13 = args[31]
            self.R14 = args[32]
            self.R15 = args[33]
            self.PC = self.RIP

    def __str__(self):
        result = ""
        result += "========================================\n"
        result += "               CPU %d\n" % self.CPU_INDEX
        result += "========================================\n"
        result += "RAX      0x%016x\n" % self.RAX
        result += "RCX      0x%016x\n" % self.RCX
        result += "RDX      0x%016x\n" % self.RDX
        result += "RBX      0x%016x\n" % self.RBX
        result += "R8       0x%016x\n" % self.R8
        result += "R9       0x%016x\n" % self.R9
        result += "R10      0x%016x\n" % self.R10
        result += "R11      0x%016x\n" % self.R11
        result += "R12      0x%016x\n" % self.R12
        result += "R13      0x%016x\n" % self.R13
        result += "R14      0x%016x\n" % self.R14
        result += "R15      0x%016x\n" % self.R15
        result += "\n"
        result += "RSP      0x%016x\n" % self.RSP
        result += "RBP      0x%016x\n" % self.RBP
        result += "\n"
        result += "RSI:     0x%016x\n" % self.RSI
        result += "RDI:     0x%016x\n" % self.RDI
        result += "\n"
        result += "RIP:     0x%016x\n" % self.RIP
        result += "RFLAGS:  0x%016x\n" % self.RFLAGS
        result += "\n"
        result += "CR0:     0x%016x\n" % self.CR0
        result += "CR1:     0x%016x\n" % self.CR1
        result += "CR2:     0x%016x\n" % self.CR2
        result += "CR3:     0x%016x\n" % self.CR3
        result += "CR4:     0x%016x\n" % self.CR4
        result += "\n"
        result += "ES:      Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.ES["sel"], self.ES["base"], self.ES["size"], self.ES["flags"])
        result += "CS:      Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.CS["sel"], self.CS["base"], self.CS["size"], self.CS["flags"])
        result += "SS:      Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.SS["sel"], self.SS["base"], self.SS["size"], self.SS["flags"])
        result += "DS:      Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.DS["sel"], self.DS["base"], self.DS["size"], self.DS["flags"])
        result += "FS:      Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.FS["sel"], self.FS["base"], self.FS["size"], self.FS["flags"])
        result += "GS:      Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.GS["sel"], self.GS["base"], self.GS["size"], self.GS["flags"])
        result += "LDT:     Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.LDT["sel"], self.LDT["base"], self.LDT["size"], self.LDT["flags"])
        result += "GDT:     Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.GDT["sel"], self.GDT["base"], self.GDT["size"], self.GDT["flags"])
        result += "IDT:     Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.IDT["sel"], self.IDT["base"], self.IDT["size"], self.IDT["flags"])
        result += "TR:      Sel: %08x   Base: %016x   Size: %08x   Flags: %08x\n" % (
            self.TR["sel"], self.TR["base"], self.TR["size"], self.TR["flags"])
        return result
