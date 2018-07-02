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

#include <Python.h>
#include <stdio.h>
#include <inttypes.h>

#include "qemu_glue.h"
#include "utils.h"


//Forces the address to adopt 64 bit canonical format
pyrebox_target_ulong canonical_address(pyrebox_target_ulong addr){
#ifdef TARGET_X86_64
    //Ignore if we are in 32 bits
    if (sizeof(pyrebox_target_ulong) == sizeof(uint32_t)){
        return addr;
    }
    else{
        if (addr & (((pyrebox_target_ulong)0x1) << 47)){
            addr |= 0xFFFF000000000000;
        }
        else{
            addr &= 0x0000FFFFFFFFFFFF;
        }
    }
    return addr;
#else
    return addr;
#endif
}

void utils_print(const char *fmt, ...){
    va_list ap;
    va_start(ap, fmt);
    printf(GRN);
    vprintf(fmt, ap);
    printf(RESET);
    fflush(stdout);
    va_end(ap);
}

void utils_print_debug(const char *fmt, ...){
    va_list ap;
    va_start(ap, fmt);
    printf(BLU);
    vprintf(fmt, ap);
    printf(RESET);
    fflush(stdout);
    va_end(ap);
}

void utils_print_warning(const char *fmt, ...){
    va_list ap;
    va_start(ap, fmt);
    printf(YEL);
    vprintf(fmt, ap);
    printf(RESET);
    fflush(stdout);
    va_end(ap);
}

void utils_print_error(const char *fmt, ...){
    va_list ap;
    va_start(ap, fmt);
    printf(RED);
    vprintf(fmt, ap);
    printf(RESET);
    fflush(stdout);
    va_end(ap);
}

void utils_print_plugin(const char *fmt, ...){
    va_list ap;
    va_start(ap, fmt);
    printf(MAG);
    vprintf(fmt, ap);
    printf(RESET);
    fflush(stdout);
    va_end(ap);
}
