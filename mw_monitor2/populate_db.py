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
import xml.etree.ElementTree as ET
import sqlite3

conn = sqlite3.connect("deviare32_populated.sqlite")
c = conn.cursor()

tree = ET.parse('msdn_populated.xml')
root = tree.getroot()
count = 0
discarded = 0
not_in_db = 0
for child in root:
    if child.tag == "functions":
        for function in child:
            name = ""
            module = ""
            for fdesc in function:
                if fdesc.tag == "name":
                    name = fdesc.text
                elif fdesc.tag == "dll":
                    module = fdesc.text
            if module is None or name is None:
                continue
            for fdesc in function:
                if fdesc.tag == "arguments":
                    for arg in fdesc:
                        arg_name = ""
                        arg_type = ""
                        for arg_desc in arg:
                            if arg_desc.tag =="name":
                                arg_name = arg_desc.text
                                if arg_name is None:
                                    arg_name = ""
                            elif arg_desc.tag == "type":
                                arg_type = arg_desc.text
                                if arg_type is None:
                                    arg_type = ""
                        if arg_name != "" and arg_type != "":
                            if "out" in arg_type:
                                query = "select F.Id,A.Id from Functions as F,FunctionsArgs as A,Modules as M, ModulesFuncs as MF  where F.Id == A.FuncId and M.Id = MF.ModId and MF.FuncId = F.Id and upper(M.Name) like  '%s' and upper(F.Name) like '%s' and upper(A.Name) like '%s';" % (module.upper(),name.upper(),arg_name.upper())
                                c.execute(query)
                                res = c.fetchone()
                                if res is not None:
                                    fid = res[0]
                                    aid = res[1]
                                    update = "update FunctionsArgs set IsOutput = 1 where Id = %d and FuncId = %d;" % (aid,fid)
                                    c.execute(update)
                                    count += 1
                                else:
                                    not_in_db += 1
                                    print "%s:%s:%s" % (module.upper(),name.upper(),arg_name.upper())
                        else:
                            discarded += 1

print "%d elements updated" % count
print "discarded %d" % discarded
print "not in db %d" % not_in_db
conn.commit()
conn.close()
