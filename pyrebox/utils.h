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

#ifndef UTILS_H
#define UTILS_H

//For info coming from pyrebox
#define GRN "\x1B[32m"
//For debug info coming from pyrebox
#define BLU "\x1B[34m"
//For warnings coming from pyrebox
#define YEL "\x1B[33m"
//For errors coming from pyrebox
#define RED "\x1B[31m"
//For output coming from pyrebox plugins
#define MAG "\x1B[35m"
//For future use
//#define CYN "\x1B[36m"
#define RESET "\x1B[0m"

//Forces the address to adopt 64 bit canonical format
pyrebox_target_ulong canonical_address(pyrebox_target_ulong addr);

void utils_print(const char *fmt, ...);
void utils_print_debug(const char *fmt, ...);
void utils_print_warning(const char *fmt, ...);
void utils_print_error(const char *fmt, ...);
void utils_print_plugin(const char *fmt, ...);

#endif
