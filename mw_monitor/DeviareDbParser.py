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
import sqlite3
import struct
import unicodedata
from StringIO import StringIO
from mw_monitor_classes import mwmon

# CONSTANTS IN THE DATABASE

NKT_DBFUNDTYPE_SignedByte = 1
NKT_DBFUNDTYPE_UnsignedByte = 2
NKT_DBFUNDTYPE_SignedWord = 3
NKT_DBFUNDTYPE_UnsignedWord = 4
NKT_DBFUNDTYPE_SignedDoubleWord = 5
NKT_DBFUNDTYPE_UnsignedDoubleWord = 6
NKT_DBFUNDTYPE_SignedQuadWord = 7
NKT_DBFUNDTYPE_UnsignedQuadWord = 8
NKT_DBFUNDTYPE_Float = 9
NKT_DBFUNDTYPE_Double = 10
NKT_DBFUNDTYPE_LongDouble = 11
NKT_DBFUNDTYPE_Void = 12
NKT_DBFUNDTYPE_AnsiChar = 13
NKT_DBFUNDTYPE_WideChar = 14

NKT_DBFUNDTYPE_MIN = 1
NKT_DBFUNDTYPE_MAX = 14

NKT_DBOBJCLASS_Fundamental = 0
NKT_DBOBJCLASS_Struct = 1
NKT_DBOBJCLASS_Union = 2
NKT_DBOBJCLASS_Typedef = 3
NKT_DBOBJCLASS_Array = 4
NKT_DBOBJCLASS_Pointer = 5
NKT_DBOBJCLASS_Reference = 6
NKT_DBOBJCLASS_Enumeration = 7

# From 8 to 14, there are no arguments in the database
NKT_DBOBJCLASS_Function = 8
NKT_DBOBJCLASS_FunctionType = 9
NKT_DBOBJCLASS_ClassConstructor = 10
NKT_DBOBJCLASS_ClassDestructor = 11
NKT_DBOBJCLASS_ClassOperatorMethod = 12
NKT_DBOBJCLASS_ClassMethod = 13
NKT_DBOBJCLASS_ClassConverter = 14

NKT_DBOBJCLASS_MASK = 0x0000FFFF
NKT_DBOBJCLASSFLAG_IsConstant = 0x00010000
NKT_DBOBJCLASSFLAG_IsVolatile = 0x00020000
NKT_DBOBJFLAG_PubliCMember = 0x00000000
NKT_DBOBJFLAG_ProtectedMember = 0x00000001
NKT_DBOBJFLAG_PrivateMember = 0x00000002
NKT_DBOBJFLAG_MEMBER_MASK = 0x00000003
NKT_DBOBJFLAG_StdCall = 0x00000000
NKT_DBOBJFLAG_CDecl = 0x00000004
NKT_DBOBJFLAG_FastCall = 0x00000008
NKT_DBOBJFLAG_ThisCall = 0x0000000C
NKT_DBOBJFLAG_CALLINGTYPE_MASK = 0x0000000C
NKT_DBOBJFLAG_IsExternal = 0x00000010
NKT_DBOBJFLAG_IsDllImport = 0x00000020
NKT_DBOBJFLAG_IsPure = 0x00000040
NKT_DBOBJFLAG_Throw = 0x00000080
NKT_DBOBJFLAG_NoThrow = 0x00000100
NKT_DBOBJFLAG_NoReturn = 0x00000200
NKT_DBOBJFLAG_IsConst = 0x00000400
NKT_DBOBJFLAG_Deprecated = 0x00000800
NKT_DBOBJFLAG_NonNull = 0x00001000
NKT_DBOBJFLAG_Malloc = 0x00002000
NKT_DBOBJFLAG_IsDllExport = 0x00004000
NKT_DBOBJFLAG_Format = 0x00008000
NKT_DBOBJFLAG_FUNCTIONFLAGS_MASK = 0x0000FFF0
NKT_DBOBJFLAG_HasConstructor = 0x00100000
NKT_DBOBJFLAG_HasDestructor = 0x00200000
NKT_DBOBJFLAG_HasVirtual = 0x00400000
NKT_DBOBJFLAG_HasInheritance = 0x00800000
NKT_DBOBJFLAG_STRUCTUNION_MASK = 0x00F00000

# =============================================================== UTILS ==


def read(pgd, addr, length):
    '''
        Wrapper to read data from memory
    '''
    import api
    try:
        return api.r_va(pgd, addr, length)
    except:
        return "\x00" * length


class DbConnector:

    '''
    Database connector that first loads the db into memory, then keeps a cursor
    to make queries.
    '''

    def __init__(self, db_path):
        # Read database to tempfile
        con = sqlite3.connect(db_path)
        tempfile = StringIO()
        for line in con.iterdump():
            tempfile.write('%s\n' % line)
        con.close()
        tempfile.seek(0)

        # Create a database in memory and import from tempfile
        self.conn = sqlite3.connect(":memory:")
        self.conn.cursor().executescript(tempfile.read())
        self.conn.commit()
        self.conn.row_factory = sqlite3.Row
        self.c = self.conn.cursor()

    def disconnect(self):
        self.conn.close()

    def get_c(self):
        return self.c


class AbstractArgument:

    def __init__(self, is_out, arg_num):
        self.arg_name = ""
        self.is_out = is_out
        self.arg_num = arg_num

    def get_arg_name(self):
        return self.arg_name

    def __cmp__(self, other):
        if hasattr(other, 'arg_num'):
            return self.arg_num.__cmp__(other.arg_num)

    def __len__(self):
        return 0

    def __str__(self):
        return ""

    def get_val(self):
        return None

    def dereference(self, argument_parser=None):
        return None

    def is_output_arg(self):
        return self.is_out


class BasicArgument(AbstractArgument):

    '''
    Basic type.
    '''

    def __init__(self, arg_name, typ, pgd=None, addr=None, val=None, is_out=False, arg_num=0):
        AbstractArgument.__init__(self, is_out, arg_num)
        if addr is None and val is None:
            raise Exception(
                "BasicArgument: Must provide addr or val to init function")
        self.addr = addr
        self.pgd = pgd
        self.val = val
        # Type ID
        self.typ = typ
        # Normalize name
        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name

    def get_id(self):
        return self.typ

    def __len__(self):
        # Based on standard size for each windows type.
        # Should not need to worry about architecture
        # 32 or 64 bit, since windows types have a fixed
        # length for both architectures
        if self.typ == NKT_DBFUNDTYPE_SignedByte:
            return 1
        elif self.typ == NKT_DBFUNDTYPE_UnsignedByte:
            return 1
        elif self.typ == NKT_DBFUNDTYPE_SignedWord:
            return 2
        elif self.typ == NKT_DBFUNDTYPE_UnsignedWord:
            return 2
        elif self.typ == NKT_DBFUNDTYPE_SignedDoubleWord:
            return 4
        elif self.typ == NKT_DBFUNDTYPE_UnsignedDoubleWord:
            return 4
        elif self.typ == NKT_DBFUNDTYPE_SignedQuadWord:
            return 8
        elif self.typ == NKT_DBFUNDTYPE_UnsignedQuadWord:
            return 8
        elif self.typ == NKT_DBFUNDTYPE_Float:
            return 4
        elif self.typ == NKT_DBFUNDTYPE_Double:
            return 8
        elif self.typ == NKT_DBFUNDTYPE_LongDouble:
            return 8
        elif self.typ == NKT_DBFUNDTYPE_Void:
            return 0
        elif self.typ == NKT_DBFUNDTYPE_AnsiChar:
            return 1
        elif self.typ == NKT_DBFUNDTYPE_WideChar:
            return 2

    def dereference(self, argument_parser=None):
        # If it is an address, resolve the value each time we query dereference(),
        # for cases in which we have input and output function arguments
        if self.addr is not None:
            parsed_value = None
            val = read(self.pgd, self.addr, len(self))
            if self.typ == NKT_DBFUNDTYPE_SignedByte:
                parsed_value = struct.unpack("<b", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_UnsignedByte:
                parsed_value = struct.unpack("<B", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_SignedWord:
                parsed_value = struct.unpack("<h", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_UnsignedWord:
                parsed_value = struct.unpack("<H", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_SignedDoubleWord:
                parsed_value = struct.unpack("<i", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_UnsignedDoubleWord:
                parsed_value = struct.unpack("<I", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_SignedQuadWord:
                parsed_value = struct.unpack("<q", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_UnsignedQuadWord:
                parsed_value = struct.unpack("<Q", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_Float:
                parsed_value = struct.unpack("<f", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_Double:
                parsed_value = struct.unpack("<d", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_LongDouble:
                parsed_value = struct.unpack("<d", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_Void:
                return
            elif self.typ == NKT_DBFUNDTYPE_AnsiChar:
                parsed_value = struct.unpack("<B", val)[0]
            elif self.typ == NKT_DBFUNDTYPE_WideChar:
                try:
                    parsed_value = val.decode("utf-16")
                except Exception:
                    parsed_value = u"\x00"
            self.val = parsed_value

    def get_val(self):
        return self.val

    def __str__(self):
        # Compute string for each basic type
        if self.val is not None and self.typ <= NKT_DBFUNDTYPE_LongDouble:
            return ("%x" % (self.val))
        elif self.val is not None and self.typ == NKT_DBFUNDTYPE_AnsiChar:
            retval = ("%s" % chr(self.val))
            return retval
        elif self.val is not None and self.typ == NKT_DBFUNDTYPE_WideChar:
            return ("%s" % (self.val))
        elif self.typ == NKT_DBFUNDTYPE_Void:
            if self.val is None:
                return "(void)"
            else:
                return ("(void)%x" % (self.val))
        else:
            return "Error - BasicArgument not valid type"


class Struct(AbstractArgument):

    def __init__(self,
                 arg_name,
                 typ,
                 name,
                 size,
                 align,
                 flags,
                 pgd=None,
                 addr=None,
                 val=None,
                 is_out=False,
                 arg_num=0):

        AbstractArgument.__init__(self, is_out, arg_num)

        if addr is None and val is None:
            raise Exception(
                "Struct: Must provide addr or val to init function")

        self.addr = addr
        self.pgd = pgd
        self.val = val
        self.typ = typ
        self.size = size / 8

        if type(name) is unicode:
            self.name = unicodedata.normalize(
                'NFKD', name).encode('ascii', 'ignore')
        else:
            self.name = name

        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name

        self.align = align
        self.flags = flags
        self.fields = []

    def get_id(self):
        return self.typ

    def __len__(self):
        return self.size

    def add_field(self, offset, field):
        # Add field to the structure (added in generate_arg
        self.fields.append((offset, field))

    def get_val(self):
        return self.val

    def dereference(self, argument_parser=None):
        for fi in self.fields:
            if fi[1] is not None:
                fi[1].dereference(argument_parser)

    def __str__(self):
        ret_str = "struct %s (%s):\n" % (self.arg_name, self.name)
        for fi in self.fields:
            ret_str += "    (+%x)-> %s: %s\n" % (
                fi[0], fi[1].get_arg_name(), fi[1].__str__())
        return ret_str


class Union(AbstractArgument):

    def __init__(self, arg_name, typ, name, size, align, flags, pgd=None, addr=None, val=None, is_out=False, arg_num=0):
        AbstractArgument.__init__(self, is_out, arg_num)
        if addr is None and val is None:
            raise Exception("Union: Must provide addr or val to init function")
        self.addr = addr
        self.pgd = pgd
        self.val = val
        self.typ = typ
        self.size = size / 8
        if type(name) is unicode:
            self.name = unicodedata.normalize(
                'NFKD', name).encode('ascii', 'ignore')
        else:
            self.name = name
        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name
        self.align = align
        self.flags = flags
        self.fields = []

    def get_id(self):
        return self.typ

    def __len__(self):
        return self.size

    def add_field(self, offset, field):
        self.fields.append((offset, field))

    def get_val(self):
        return self.val

    def dereference(self, argument_parser=None):
        for fi in self.fields:
            if fi[1] is not None:
                fi[1].dereference(argument_parser)

    def __str__(self):
        ret_str = "union %s (%s):\n" % (self.arg_name, self.name)
        for fi in self.fields:
            ret_str += "    (+%x)-> %s: %s\n" % (
                fi[0], fi[1].get_arg_name(), fi[1].__str__())
        return ret_str


class Typedef(AbstractArgument):

    def __init__(self, arg_name, typ, equivalent_arg, pgd=None, addr=None, val=None, is_out=False, arg_num=0):
        AbstractArgument.__init__(self, is_out, arg_num)
        if addr is None and val is None:
            raise Exception(
                "Typedef: Must provide addr or val to init function")
        self.addr = addr
        self.pgd = pgd
        self.val = val
        self.typ = typ
        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name
        self.equivalent_arg = equivalent_arg

    def get_id(self):
        return self.typ

    def __len__(self):
        return len(self.equivalent_arg)

    def get_val(self):
        if self.equivalent_arg is not None:
            return self.equivalent_arg.get_val()
        else:
            return None

    def dereference(self, argument_parser=None):
        if self.equivalent_arg is not None:
            self.equivalent_arg.dereference(argument_parser)

    def __str__(self):
        if self.arg_name != "":
            return "%s" % (self.equivalent_arg.__str__())
        else:
            try:
                # use .__str__() instead of str() due to error while unpickling
                return "%s" % self.equivalent_arg.__str__()
            except Exception:
                print (self.equivalent_arg.__class__.__name__)


class Array(AbstractArgument):

    def __init__(self, arg_name, typ, max, size, align, pgd=None, addr=None, val=None, is_out=False, arg_num=0):
        AbstractArgument.__init__(self, is_out, arg_num)
        if addr is None and val is None:
            raise Exception("Array: Must provide addr or val to init function")
        self.addr = addr
        self.pgd = pgd
        self.val = val
        self.typ = typ
        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name
        self.max = max
        self.size = size
        self.align = align
        self.fields = []

    def get_id(self):
        return self.typ

    def __len__(self):
        return self.size

    def add_field(self, i, field):
        self.fields.append((i, field))

    def dereference(self, argument_parser=None):
        for fi in self.fields:
            if fi[1] is not None:
                fi[1].dereference(argument_parser)

    def get_val(self):
        return self.val

    def __str__(self):
        ret_str = "array %s:\n" % (self.arg_name)
        for fi in self.fields:
            ret_str += "    [%d]-> %s: %s\n" % (
                fi[0], fi[1].get_arg_name(), fi[1].__str__())
        return ret_str


class ParamStr(AbstractArgument):

    '''
    Helper to store and print string type pointers
    '''

    def __init__(self, arg_name, pgd=None, addr=None, val=None, is_out=False, arg_num=0):
        AbstractArgument.__init__(self, is_out, arg_num)
        if addr is None and val is None:
            raise Exception(
                "ParamStr: Must provide addr or val to init function")
        self.addr = addr
        self.pgd = pgd
        self.val = val
        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name
        self.fields = []

    def get_addr(self):
        return self.addr

    def __len__(self):
        if len(self.fields) == 0:
            return 0
        return len(self.fields) * len(self.fields[0])

    def add_field(self, field):
        self.fields.append(field)

    def clean_fields(self):
        self.fields = []

    def get_val(self):
        return self.val

    def dereference(self, argument_parser=None):
        for fi in self.fields:
            if fi is not None:
                fi.dereference(argument_parser)

    def __str__(self):
        ret_str = ""
        for fi in self.fields:
            ret_str += "%s" % (fi.__str__())
        return ret_str


class Pointer(AbstractArgument):

    def __init__(self,
                 arg_name,
                 typ,
                 size,
                 align,
                 deref_type_id,
                 deref_type_class,
                 is_out=False,
                 pgd=None,
                 addr=None,
                 val=None,
                 arg_num=0):

        AbstractArgument.__init__(self, is_out, arg_num)

        if addr is None and val is None:
            raise Exception(
                "Pointer: Must provide addr or val to init function")

        self.deref_type_id = deref_type_id
        self.deref_type_class = deref_type_class
        self.addr = addr
        self.pgd = pgd
        self.val = val
        self.typ = typ

        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name

        self.size = size / 8
        self.align = align
        self.i_was_dereferenced = False
        self.dereferenced_type = None

    def dereference(self, argument_parser=None):
        '''
        Dereference the pointer.
        '''
        self.i_was_dereferenced = True

        if self.addr is not None:
            deref_addr = struct.unpack("<I", read(self.pgd, self.addr, 4))[
                0] if self.size == 4 else struct.unpack("<Q", read(self.pgd, self.addr, 8))[0]
        else:
            deref_addr = self.val

        if "STR" in self.arg_name.upper() and deref_addr != 0 and "UNICODE_STRING" not in self.arg_name.upper():
            # Construct a ParamStr. The string itself will be read/dereferened
            # each time we call get_val()
            self.dereferenced_type = ParamStr(self.arg_name,
                                              pgd=self.pgd,
                                              addr=deref_addr,
                                              is_out=self.is_out,
                                              arg_num=self.arg_num)

            # If it is an str, parse the str with a maximum length of 512.
            self.dereferenced_type.clean_fields()
            num_chars = 0
            deref_addr = self.dereferenced_type.get_addr()
            while num_chars < 512:
                num_chars += 1
                # Need reference to argument parser
                c = argument_parser.generate_arg("",
                                                 self.deref_type_id,
                                                 self.deref_type_class,
                                                 self.is_out,
                                                 addr=deref_addr,
                                                 arg_num=self.arg_num)

                self.dereferenced_type.add_field(c)
                c.dereference(argument_parser)
                val = c.get_val()
                if (type(val) is int and val == 0) or \
                   (type(val) is str and val[0] == "\x00") or \
                   (type(val) is unicode and val[0] == u"\x00"):
                    break
                deref_addr += len(c)
        else:
            self.dereferenced_type = argument_parser.generate_arg("",
                                                                  self.deref_type_id,
                                                                  self.deref_type_class,
                                                                  self.is_out,
                                                                  addr=deref_addr,
                                                                  arg_num=self.arg_num)

            if self.dereferenced_type is not None:
                self.dereferenced_type.dereference(argument_parser)

    def get_id(self):
        return self.typ

    def __len__(self):
        return self.size

    def get_val(self):
        if self.dereferenced_type is not None:
            return self.dereferenced_type.get_val()
        else:
            return None

    def __str__(self):
        if self.dereferenced_type is None:
            return "None"
        else:
            return "%s" % (self.dereferenced_type.__str__())


class Reference(AbstractArgument):

    def __init__(self,
                 arg_name,
                 typ,
                 size,
                 align,
                 dereferenced_type,
                 is_out=False,
                 pgd=None,
                 addr=None,
                 val=None,
                 arg_num=0):

        AbstractArgument.__init__(self, is_out, arg_num)

        if addr is None and val is None:
            raise Exception(
                "Reference: Must provide addr or val to init function")

        self.addr = addr
        self.pgd = pgd
        self.val = val
        self.typ = typ

        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name

        self.size = size / 8
        self.align = align
        self.dereferenced_type = dereferenced_type

    def get_id(self):
        return self.typ

    def __len__(self):
        return self.size

    def dereference(self, argument_parser=None):
        if self.dereferenced_type is not None:
            self.dereferenced_type.dereference(argument_parser)

    def get_val(self):
        if self.dereferenced_type is not None:
            return self.dereferenced_type.get_val()
        else:
            return None

    def __str__(self):
        # return "r_%s: %s" % (self.arg_name,self.dereferenced_type.__str__())
        return "%s" % (self.dereferenced_type.__str__())


class Enumeration(AbstractArgument):

    def __init__(self,
                 arg_name,
                 typ,
                 name,
                 size,
                 pgd=None,
                 addr=None,
                 val=None,
                 is_out=False,
                 arg_num=0):

        AbstractArgument.__init__(self, is_out, arg_num)
        if addr is None and val is None:
            raise Exception(
                "Enumeration: Must provide addr or val to init function")
        self.addr = addr
        self.pgd = pgd
        self.val = val
        # Name of the argument
        if type(arg_name) is unicode:
            self.arg_name = unicodedata.normalize(
                'NFKD', arg_name).encode('ascii', 'ignore')
        else:
            self.arg_name = arg_name
        self.typ = typ
        # Name of the enumeration value
        self.name = name
        self.size = size / 8

    def __len__(self):
        return self.size

    def dereference(self, argument_parser=None):
        from mw_monitor_classes import mwmon
        if self.val is None:
            self.val = struct.unpack("<I", read(self.pgd, self.addr, 4))[
                0] if self.size == 4 else struct.unpack("<Q", read(self.pgd, self.addr, 8))[0]
        cur = mwmon.db.get_c()
        cur.execute("select EnumId,Id,Name,Value from EnumerationsValues where EnumId = %d and Value = %d" %
                    (self.typ, self.val))
        enum_val = cur.fetchone()
        if enum_val is not None:
            self.name = enum_val[2]
        else:
            self.name = None

    def get_val(self):
        return self.val

    def __str__(self):
        return "%s(%d)" % (self.name, self.val)


class ArgumentParser:

    '''
    Given a function call, parses the database and reads the arguments for the function.
    '''

    def __init__(self, db, cpu, addr, mod, fun):
        # Address of stack at the moment of the call
        self.addr = addr
        self.pgd = cpu.CR3
        self.cpu = cpu
        self.func_id = None
        self.eax = None
        self.mod = mod
        self.fun = fun
        self.c = db.get_c()
        self.__in_db = False
        # Get function id in database
        query = ("select F.Id,F.Class,F.Flags,F.ReturnTypeId,F.ReturnClass " +
                 "from Functions as F,Modules as M,ModulesFuncs as MF " +
                 "where F.Id == MF.FuncId and M.Id = MF.ModId and F.Name " +
                 "like '%{fu}%' and M.Name like '%{mo}%';").format(
                 fu=fun, mo=mod)
        self.c.execute(query)
        results = self.c.fetchall()
        # Get the first result, if any
        if len(results) > 0:
            self.func_id = results[0][0]
            self.func_class = results[0][1]
            self.func_flags = results[0][2]
            self.func_ret_typeid = results[0][3]
            self.func_ret_class = results[0][4]
            self.args = []
            self.ret = None
            self.populate_args()
            self.__in_db = True
        else:
            self.__in_db = False
            f = open("api_tracer_warnings.log", "a")
            f.write("Function not present in DB: %s:%s:%x\n" %
                    (mod, fun, addr))
            f.close()

    def in_db(self):
        return self.__in_db

    def generate_arg(self,
                     arg_name,
                     arg_typ,
                     arg_class,
                     is_out,
                     addr=None,
                     val=None,
                     arg_num=0):

        # Return None for null pointers
        if addr is not None and addr == 0:
            return None

        # TODO - FIX - We need to correct the arg_class, because it seems that
        # the db has some errors
        while arg_class >= 65536:
            arg_class -= 65536

        if arg_class == NKT_DBOBJCLASS_Fundamental:
            return BasicArgument(arg_name,
                                 arg_typ,
                                 pgd=self.pgd,
                                 addr=addr,
                                 val=val,
                                 is_out=is_out,
                                 arg_num=arg_num)

        elif arg_class == NKT_DBOBJCLASS_Struct:
            self.c.execute(
                "select Id,Name,Size,Align,Flags from Structs where Id = %d" % (arg_typ))
            res = self.c.fetchone()
            if res is not None:
                new_struct = Struct(arg_name,
                                    res[0],
                                    res[1],
                                    res[2],
                                    res[3],
                                    res[4],
                                    pgd=self.pgd,
                                    addr=addr,
                                    val=val,
                                    is_out=is_out,
                                    arg_num=arg_num)

                if addr is not None:
                    self.c.execute("select StructId,Id,Name,Offset,Bits,Flags,TypeId,TypeClass" +
                                   " from StructsMembers where StructId = %d order by Id ASC" % (arg_typ))
                    sub_fields = self.c.fetchall()
                    for sub_field in sub_fields:

                        # Skip incorrect blank fields in the db
                        if sub_field[3] == 0 and sub_field[1] > 1:
                            continue

                        offset = sub_field[3] / 8

                        new_struct.add_field(offset,
                                             self.generate_arg(sub_field[2],
                                                               sub_field[6],
                                                               sub_field[7],
                                                               is_out, addr=addr +
                                                               offset,
                                                               val=None,
                                                               arg_num=arg_num))
                else:
                    mwmon.printer("Unsupported type: A struct has been returned as" +
                                  "return value (EAX/RAX), or as register parameter (RCX/RDX/R8/R9).")
                return new_struct
            else:
                return None

        elif arg_class == NKT_DBOBJCLASS_Union:
            self.c.execute(
                "select Id,Name,Size,Align,Flags from Unions where Id = %d" % (arg_typ))
            res = self.c.fetchone()
            if res is not None:
                new_union = Union(arg_name,
                                  res[0],
                                  res[1],
                                  res[2],
                                  res[3],
                                  res[4],
                                  pgd=self.pgd,
                                  addr=addr,
                                  val=val,
                                  is_out=is_out,
                                  arg_num=arg_num)

                if addr is not None:
                    self.c.execute("select UnionId,Id,Name,Offset,Bits,Flags,TypeId,TypeClass " +
                                   "from UnionsMembers where UnionId =  %d order by Id ASC" % (arg_typ))
                    sub_fields = self.c.fetchall()
                    for sub_field in sub_fields:
                        offset = sub_field[3] / 8
                        new_union.add_field(offset,
                                            self.generate_arg(sub_field[2],
                                                              sub_field[6],
                                                              sub_field[7],
                                                              is_out,
                                                              addr=addr +
                                                              offset,
                                                              arg_num=arg_num))
                else:
                    mwmon.printer("Unsupported type: A union has been returned as" +
                                  "return value (EAX/RAX), or as register parameter (RCX/RDX/R8/R9).")

                return new_union
            else:
                return None

        elif arg_class == NKT_DBOBJCLASS_Typedef:
            self.c.execute(
                "select Id,Name,TypeId,TypeClass from TypeDefs where Id = %d" % (arg_typ))
            res = self.c.fetchone()
            if res is not None:
                t = Typedef(arg_name,
                            res[0],
                            self.generate_arg(res[1],
                                              res[2],
                                              res[3],
                                              is_out,
                                              addr=addr,
                                              val=val,
                                              arg_num=arg_num),
                            addr=addr,
                            val=val,
                            is_out=is_out,
                            arg_num=arg_num)
                return t
            else:
                return None

        elif arg_class == NKT_DBOBJCLASS_Array:
            self.c.execute(
                "select Id,Max,Size,Align,TypeId,TypeClass from Arrays where Id = %d" % (arg_typ))
            res = self.c.fetchone()
            if res is not None:
                the_arr = Array(arg_name,
                                res[0],
                                res[1],
                                res[2],
                                res[3],
                                pgd=self.pgd,
                                addr=addr,
                                val=val,
                                is_out=is_out,
                                arg_num=arg_num)

                if addr is not None:
                    size_of_element = res[2] / res[1]
                    for i in range(0, res[1]):
                        the_arr.add_field(i,
                                          self.generate_arg("",
                                                            res[4],
                                                            res[5],
                                                            is_out,
                                                            addr=addr,
                                                            val=None,
                                                            arg_num=arg_num))
                        addr += size_of_element
                else:
                    mwmon.printer("Unsupported type: An array has been returned as" +
                                  "return value (EAX/RAX), or as register parameter (RCX/RDX/R8/R9).")
                return the_arr
            else:
                return None

        elif arg_class == NKT_DBOBJCLASS_Pointer:
            self.c.execute(
                "select Id,Size,Align,TypeId,TypeClass from Pointers where Id = %d" % (arg_typ))
            res = self.c.fetchone()
            if res is not None:
                # We let the Pointer class determine if it should dereference
                # or not the pointer
                the_pointer = Pointer(arg_name,
                                      arg_typ,
                                      res[1],
                                      res[2],
                                      res[3],
                                      res[4],
                                      is_out,
                                      pgd=self.pgd,
                                      addr=addr,
                                      val=val,
                                      arg_num=arg_num)
                return the_pointer

            else:
                return None

        elif arg_class == NKT_DBOBJCLASS_Reference:
            self.c.execute(
                "select Id,Size,Align,TypeId,TypeClass from XReferences where Id = %d" % (arg_typ))
            res = self.c.fetchone()
            if res is not None:
                if addr is not None:
                    # Dereference pointer. we can safely dereference it when the argument parser is created (function
                    # call) because the address will not change when the
                    # function returns if it is an output parameter.
                    deref_addr = struct.unpack("<I", read(self.pgd, addr, 4))[0] if res[
                        1] == 32 else struct.unpack("<Q", read(self.pgd, addr, 8))[0]
                else:
                    deref_addr = val
                the_pointer = Reference(arg_name,
                                        arg_typ,
                                        res[1],
                                        res[2],
                                        self.generate_arg("",
                                                          res[3],
                                                          res[4],
                                                          is_out,
                                                          addr=deref_addr,
                                                          arg_num=arg_num),
                                        pgd=self.pgd,
                                        addr=addr,
                                        val=val,
                                        arg_num=arg_num)
                return the_pointer
            else:
                return None

        elif arg_class == NKT_DBOBJCLASS_Enumeration:
            self.c.execute(
                "select Id,Name,Size,Align from Enumerations where Id = %d" % (arg_typ))
            res = self.c.fetchone()
            if res is not None:
                return Enumeration(arg_name,
                                   res[0],
                                   None,
                                   res[2],
                                   pgd=self.pgd,
                                   addr=addr,
                                   val=val,
                                   is_out=is_out,
                                   arg_num=arg_num)
            else:
                return None

    def populate_args(self):
        import api
        TARGET_LONG_SIZE = api.get_os_bits() / 8

        if self.func_id is None:
            return []
        self.c.execute(
            "select Id,Name,TypeId,TypeClass,IsOutput from FunctionsArgs where FuncId = %d order by Id ASC" % (self.func_id))
        params = self.c.fetchall()

        # Here, we need to use properly the addresses depending on the bitness
        # and the calling convention
        if TARGET_LONG_SIZE == 4:
            # Skip return address
            addr = self.addr + 4
            reg_params = []
        elif TARGET_LONG_SIZE == 8:
            # 4 slots for saving arguments + return address
            addr = self.addr + 8 * 5
            reg_params = [self.cpu.RCX, self.cpu.RDX, self.cpu.R8, self.cpu.R9]

        arg_num = 1
        for param in params:
            # Unfold the argument
            is_out = False if param[4] == 0 else True
            if TARGET_LONG_SIZE == 8 and arg_num <= 4:
                arg = self.generate_arg(param[1], param[2], param[
                                        3], is_out, val=reg_params[arg_num - 1], arg_num=arg_num)
            else:
                arg = self.generate_arg(
                    param[1], param[2], param[3], is_out, addr=addr, arg_num=arg_num)
                addr += len(arg)

            arg_num += 1
            # Point to next parameter in stack
            self.args.append(arg)

    def update_return(self, eax):
        self.eax = eax
        if self.eax is not None:
            # For the return argument, the arg_num is 0.
            self.ret = self.generate_arg(
                "Return value", self.func_ret_typeid, self.func_ret_class, True, val=self.eax, arg_num=0)

    def get_id(self):
        return self.func_id

    def get_out_args(self):
        try:
            for arg in self.args:
                if arg.is_output_arg():
                    arg.dereference(self)
                    yield arg
        except Exception as e:
            # There a few cases where the documented database might contain 
            # errors, ending up in infinite recursion of dereference. We
            # log this cases so that the user can correct theese entries
            # the database
            f = open("api_tracer_warnings.log", "a")
            f.write("Recursion depth limit exceeded for: %s:%s:%x, Check database correctness.\n" %
                    (self.mod, self.fun, self.addr))
            f.close()

    def get_in_args(self):
        try:
            for arg in self.args:
                if not arg.is_output_arg():
                    arg.dereference(self)
                    yield arg
        except Exception as e:
            # There a few cases where the documented database might contain 
            # errors, ending up in infinite recursion of dereference. We
            # log this cases so that the user can correct theese entries
            # the database
            f = open("api_tracer_warnings.log", "a")
            f.write("Recursion depth limit exceeded for: %s:%s:%x, Check database correctness.\n" %
                    (self.mod, self.fun, self.addr))
            f.close()

    def get_ret(self):
        try:
            self.ret.dereference(self)
            return self.ret
        except Exception as e:
            # There a few cases where the documented database might contain 
            # errors, ending up in infinite recursion of dereference. We
            # log this cases so that the user can correct theese entries
            # the database
            f = open("api_tracer_warnings.log", "a")
            f.write("Recursion depth limit exceeded for: %s:%s:%x, Check database correctness.\n" %
                    (self.mod, self.fun, self.addr))
            f.close()
