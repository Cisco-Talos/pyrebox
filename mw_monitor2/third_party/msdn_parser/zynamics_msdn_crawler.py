# zynamics msdn-crawler (http://github.com/zynamics/msdn-crawler)
# Copyright (C) 2010
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import sys
import re

from os.path import join, getsize

def strip_html(string):
    r1 = re.compile("<.*?>")
    r2 = re.compile(" +")
    return r2.sub(" ", r1.sub("", string).replace("&nbsp;", " ").replace("\t", " ").replace("&)", ")").replace("&#8211;", "-").replace("&#8212;", "-"))

def parse_old_style(file, content):
    m = re.search("<ph:apidata><api>(.*)</api><name>(.*)</name></ph:apidata>", content)
    if m != None:
        dll = m.group(1).lower()
        function_name = m.group(2)
        
        m = re.search("<span></span><P>(.*?)</P>", content)
        if m != None:
            description = strip_html(m.group(1))
        else:
            print "Error: Could not retrieve function description from file %s" % file
            return None
        
        m = re.search("<P CLASS=\"clsRef\">Parameters</P><BLOCKQUOTE>(.*?)</BLOCKQUOTE>", content)
        if m != None:
#            argument_names = re.findall("<DT><I>(.*?)</I>", m.group(1))
            argument_names = re.findall("<DT><I>(.*?)</DT>", m.group(1))
            argument_names = [argument_name.replace("<I>", "") for argument_name in argument_names]
            argument_names = [argument_name.replace("</I>", "") for argument_name in argument_names]
            argument_names2 = []
            argument_types = []
            for argument_name in argument_names:
                t = re.search("\[(.*?)\]",argument_name)
                if t is not None:
                    typ = t.group(0)
                else:
                    typ = ""
                name = argument_name.replace(typ,"").strip()
                argument_names2.append(name)
                argument_types.append(typ)

            descriptions = [strip_html(string) for string in re.findall("<DD>(.*?)</DD>", m.group(1))]

            count = 0
            for desc in descriptions:
                if count >= len(argument_types):
                    break
                t = re.search("\[(.*?)\]",desc)
                if t is not None:
                    argument_types[count] = argument_types[count] + t.group(0)
                count+=1
            
            arguments = zip(argument_names2, argument_types,descriptions)
        else:
            # It's possible to have functions without arguments
            arguments = [ ]

        m = re.search("<P CLASS=\"clsRef\">Return Value</P><BLOCKQUOTE><P>(.*?)</P>", content)
        
        if m != None:
            return_value = strip_html(m.group(1))
        else:
            # If something has no return value it's not a function.
            return None
            
        print "Found function %s!%s" % (dll, function_name) 
            
        return [(dll, function_name, description, arguments, return_value)]
    else:
        return None

def parse_new_style(file, content):
    api_types = re.findall("<MSHelp:Attr Name=\"APIType\" Value=\"(.*?)\"[ /]*>", content) # Check for > not for /> because some docs are broken

    if api_types in ([], ["Schema"], ["UserDefined"], ["HeaderDef"], ["MOFDef"], ["NA"], ["LibDef"]):
        return None
    
    if not api_types in ([], ["COM"], ["DllExport"]):
        print "API Type: ", api_types
    
    function_names = re.findall("<MSHelp:Attr Name=\"APIName\" Value=\"(.*?)\"[ /]*>", content) # Check for > not for /> because some docs are broken
    
    if function_names != []:
        dll_names = re.findall("<MSHelp:Attr Name=\"APILocation\" Value=\"(.*?)\"[ /]*>", content) # Check for > not for /> because some docs are broken
        
        if dll_names == []:
            return None
        
        m = re.search("<meta name=\"Description\" content=\"(.*?)\"/>", content, re.IGNORECASE)
        if m != None:
            description = strip_html(m.group(1))
        else:
            print "Error: Could not retrieve function description from file %s" % file
            return None
            
        m = re.search("<P CLASS=\"clsRef\">Parameters</P><BLOCKQUOTE>(.*?)</BLOCKQUOTE>", content)
        if m != None:
            argument_names = re.findall("<DT><I>(.*?)</DT>", m.group(1))
            argument_names = [argument_name.replace("<I>", "") for argument_name in argument_names]
            argument_names = [argument_name.replace("</I>", "") for argument_name in argument_names]
#           argument_names = re.findall("<DT><I>(.*?)</I>", m.group(1))
            descriptions = [strip_html(string) for string in re.findall("<DD>(.*?)</DD>", m.group(1))]

            argument_names2 = []
            argument_types = []
            for argument_name in argument_names:
                t = re.search("\[(.*?)\]",argument_name)
                if t is not None:
                    typ = t.group(0)
                else:
                    typ = ""
                name = argument_name.replace(typ,"").strip()
                argument_names2.append(name)
                argument_types.append(typ)

            count = 0
            for desc in descriptions:
                if count >= len(argument_types):
                    break
                t = re.search("\[(.*?)\]",desc)
                if t is not None:
                    argument_types[count] = argument_types[count] + t.group(0)
                count+=1
            
            arguments = zip(argument_names2, argument_types, descriptions)
        else:
            m = re.search("<h3>Parameters</h3><dl>(.*?)</dl><h3>", content)
            if m != None:
                argument_names = re.findall("<dt><i>(.*?)</dt>", m.group(1))
                argument_names = [argument_name.replace("<i>", "") for argument_name in argument_names]
                argument_names = [argument_name.replace("</i>", "") for argument_name in argument_names]
                descriptions = [strip_html(string) for string in re.findall("<dd>(.*?)</dd>", m.group(1))]

                argument_names2 = []
                argument_types = []
                for argument_name in argument_names:
                    t = re.search("\[(.*?)\]",argument_name)
                    if t is not None:
                        typ = t.group(0)
                    else:
                        typ = ""
                    name = argument_name.replace(typ,"").strip()
                    argument_names2.append(name)
                    argument_types.append(typ)

                count = 0
                for desc in descriptions:
                    if count >= len(argument_types):
                        break
                    t = re.search("\[(.*?)\]",desc)
                    if t is not None:
                        argument_types[count] = argument_types[count] + t.group(0)
                    count+=1
                
                arguments = zip(argument_names2,argument_types, descriptions)
            else:
                # It's possible to have functions without arguments
                arguments = [ ]

        m = re.search("<h3>Return Value</h3><p>(.*?)</p>", content)
        
        if m != None:
            return_value = strip_html(m.group(1))
        else:
            # If something has no return value it's not a function.
            return None
            
        return_list = []
        
        for dll_name in dll_names:
            for function_name in function_names:
                print "Found function %s!%s" % (dll_name.lower(), function_name) 
                if not arguments:
                    print "No arguments: %s" % function_name
                return_list.append((dll_name.lower(), function_name, description, arguments, return_value))
                
        return return_list
    else:
        return None

def parse_file(file):
    print "Parsing %s" % file

    text_file = open(file, "r")
    content = text_file.read().translate(None, "\r\n")
    text_file.close()
    
    if content.find("ph:apidata") != -1:
        return parse_old_style(file, content)
    elif content.find("<MSHelp:Attr Name=\"APIName\"") != -1:
        return parse_new_style(file, content)
    else:
        return None

def to_xml(results):
    xml_string = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
    xml_string = xml_string + "<msdn>\n"
    xml_string = xml_string + "<functions>\n"

    for (dll_name, function_name, description, arguments, return_value) in results:
        xml_string = xml_string + "\t<function>\n"
        xml_string = xml_string + "\t\t<name>%s</name>\n" % function_name
        xml_string = xml_string + "\t\t<dll>%s</dll>\n" % dll_name
        xml_string = xml_string + "\t\t<description>%s</description>\n" % description
            
        xml_string = xml_string + "\t\t<arguments>\n"
            
        for (argument_name, argument_type, argument_description) in arguments:
            xml_string = xml_string + "\t\t\t<argument>\n"
            xml_string = xml_string + "\t\t\t\t<name>%s</name>\n" % argument_name
            xml_string = xml_string + "\t\t\t\t<type>%s</type>\n" % argument_type
            xml_string = xml_string + "\t\t\t\t<description>%s</description>\n" % argument_description
            xml_string = xml_string + "\t\t\t</argument>\n"
            
        xml_string = xml_string + "\t\t</arguments>\n"
        
        xml_string = xml_string + "\t\t<returns>%s</returns>\n" % return_value
        xml_string = xml_string + "\t</function>\n"

    xml_string = xml_string + "</functions>\n"
    xml_string = xml_string + "</msdn>"
    
    return xml_string

def exclude_dir(directory):
    exclude_dirs = [ "\\1033\\html", "\\1033\\workshop" ]
    
    for exclude_dir in exclude_dirs:
        if directory.find(exclude_dir) != -1:
            return True
            
    return False

def parse_files(msdn_directory):
    file_counter = 0
    results = [ ]
    
    for root, dirs, files in os.walk(msdn_directory):
        for file in files:
            if exclude_dir(root):
                continue
                
            if file.endswith('htm'):
                file_counter = file_counter + 1
                result = parse_file(join(root, file))
                if result != None:
                    results.append(result)
    return (file_counter, results)

def main():
    print "zynamics msdn-crawler - Copyright 2010"
    print "For updates please check http://github.com/zynamics/msdn-crawler"
    print
    if len(sys.argv) != 2:
        print "usage: %s path_to_msdn" % sys.argv[0]
        print "    where path_to_msdn is the path to the decompiled MSDN help files"
        sys.exit(0)

    msdn_directory = sys.argv[1] # 'C:\\Programme\\Microsoft SDKs\\Windows\\v7.0\\Help\\1033'

    (file_counter, results) = parse_files(msdn_directory)
    results = sum(results, [])

    print "Parsed %d files" % file_counter
    print "Extracted information about %d functions" % len(results)

    xml_file = open("msdn.xml", "w")
    xml_file.write(to_xml(results))
    xml_file.close()

if __name__ == "__main__":
    main()
