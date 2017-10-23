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

/* test.c - A simple program to print through stdout the list of arguments
 *          and environment variables */

#include <stdio.h>
#include <unistd.h>

#include <windows.h>

int main(int argc, char* argv[],char** envp) {
    int i = 0;
    for (i = 0; i < argc; i++){
        printf("[*] Argument %d: %s\n",i,argv[i]);
    }
    char** env;
    for (env = envp; *env != 0; env++){
        printf("Environment variable: %s\n", *env);
    }
    return(0);
}
