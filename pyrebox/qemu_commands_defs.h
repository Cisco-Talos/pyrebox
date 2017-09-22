/*-------------------------------------------------------------------------------

   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group

   PyREBox: Python scriptable Reverse Engineering Sandbox 
   Author: Xabier Ugarte-Pedrero 
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
   MA 02110-1301, USA.
   
-------------------------------------------------------------------------------*/

{
	.name		= "import_module",
	.args_type	= "modulename:s?",
	.cmd	= import_module,
	.params		= "[modulename]",
	.help		= "Import a python module"
},
{
	.name		= "unload_module",
	.args_type	= "modulehandle:i?",
	.cmd	= unload_module,
	.params		= "[modulehandle]",
	.help		= "Unload a python module, by handle"
},
{
	.name		= "reload_module",
	.args_type	= "modulehandle:i?",
	.cmd	= reload_module,
	.params		= "[modulehandle]",
	.help		= "Reload a python module, by handle"
},
{
	.name		= "list_modules",
	.args_type	= "",
	.cmd	= list_modules,
	.params		= "",
	.help		= "List all modules"
},
{
	.name		= "sh",
	.args_type	= "",
	.cmd	= pyrebox_shell,
	.params		= "",
	.help		= "Start a pyrebox shell"
},
