/*-------------------------------------------------------------------------------

   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group

   PyREBox: Python scriptable Reverse Engineering Sandbox 
   Author: Jonas Zaddach
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

#include <host_opcodes.h>

#ifndef PYREBOX_GUEST_64

#include <seh.h>

int check_for_pyrebox() {
    /* Wait until we're running in Pyrebox.
     * While not running in Pyrebox, the host_get_version() function will contain
     * an illegal instruction, which is caught by the structured exception handler.
     * When running in Pyrebox, the instruction will execute just fine and the function
     * will return normally.
     */
    __seh_try {
        fprintf(stderr, "Calling the get_version opcode.\n");
        host_get_version();
        return 1;
    }
    __seh_except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    __seh_end_except
}

#else

int check_for_pyrebox() {
    /* Libseh does not work properly for 64 bits, so we just let the program crash if not run
     * under pyrebox with the guest plugin loaded initialized */
    host_get_version();
    return 1;
}

#endif
