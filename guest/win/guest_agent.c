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

#include <stdio.h>
#include <unistd.h>

#include <windows.h>

#include <host_opcodes.h>
#include <check_pyrebox.h>

#include "guest_agent.h"

//Global buffer used to copy data back and forth
char agent_buffer[MAX_BUFFER_SIZE];

//Copy file operation
int copy_file() {
    int in_fd;
    FILE* out_fd;
    int fsize = 0;
    char file_name[MAX_BUFFER_SIZE];

    /* Get the file name to copy to 
     * This will activate our hook on the invalid opcode in the python script.
     */

    host_get_file_name(agent_buffer, sizeof(agent_buffer));
    strncpy(file_name,agent_buffer,sizeof(file_name));

    /* Open file on the host. */

    if ((in_fd = host_open(file_name)) == -1){
        fprintf(stderr, "Error opening file on host\n");
        return 2;
    }

    /* Read file from the host and output it on stdout. */
    if ((out_fd = fopen(file_name, "wb")) == NULL){
        fprintf(stderr, "Error opening file %s on guest for writing\n", file_name);
        return 3;
    }
     
    /* Data read loop */
    while (1) {
        int ret = host_read(in_fd, agent_buffer, sizeof(agent_buffer));
        if (ret == -1) {
            fprintf(stderr, "Error reading from host file\n");
            return 4;
        }
        else if (ret == 0) {
            break;
        }

        if (fwrite(agent_buffer, 1, ret, out_fd) != ret) {
            fprintf(stderr, "Error writing to file on guest\n");
            return 5;
        }

        fsize += ret;
    }

    /* Don't forget to close the file on the host. */
    host_close(in_fd);
    fclose(out_fd);

    fprintf(stderr, "File %s of size %d was successfully transferred\n", file_name, fsize);
    return 0;

}

int exec_file(){

    /* Local vars to keep path, args, and env variables */
    char path[MAX_BUFFER_SIZE];
    char args[MAX_BUFFER_SIZE];
    char env[MAX_BUFFER_SIZE];

    /* Sizes of copied data */
    int ret_path = 0;
    int ret_args = 0;
    int ret_env = 0;

    /* Call pyrebox to get the parameters for the execution operation */
    ret_path = host_request_exec_path(agent_buffer, MAX_BUFFER_SIZE);
    memcpy(path,agent_buffer,MAX_BUFFER_SIZE);
    ret_args = host_request_exec_args(agent_buffer, MAX_BUFFER_SIZE);
    memcpy(args,agent_buffer,MAX_BUFFER_SIZE);
    ret_env = host_request_exec_env(agent_buffer, MAX_BUFFER_SIZE);
    memcpy(env,agent_buffer,MAX_BUFFER_SIZE);

    /* Use Windows API CreateProcess because unlike execv* or fork(), 
     * allows the parent to exit while the child keeps running */
    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};

    si.cb = sizeof(si);
    if( ! CreateProcess( (path[0]) ? path : NULL, // lpApplicationName
                         (args[0]) ? args : NULL, // lpCommandLine
                         0,    // lpProcessAttributes
                         0,    // lpThreadAttributes
                         0,    // bInheritHandles
                         0,    // dwCreationFlags
                         (env[0]) ? env : NULL,
                         0,    // lpCurrentDirectory
                         &si,  // lpStartupInfo
                         &pi   // lpProcessInformation
                       ) ){
        fprintf(stderr, "The process creation failed %d under Pyrebox.\n", GetLastError());
    }
    else {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

int main(int argc, char* argv[]) {

    /* Check we're running in Pyrebox */
    if (!check_for_pyrebox()) {
        fprintf(stderr, "This program doesn't seem to be run under Pyrebox.\n");
        return 1;
    }

    /* Wait for Pyrebox to signal some command. Several commands can be executed
     * one after the other.
       This is also useful to stall execution to take a snapshot while the execution
       is here, and then resume from the snapshot and run some command when 
       asked for.
     */
    int cmd = CMD_WAIT;
    while ((cmd = host_get_command()) != CMD_EXIT) {
        switch(cmd) {
            case CMD_WAIT:
                sleep(1);
                break;
            case CMD_COPY:
                copy_file();
                break;
            case CMD_EXEC:
                exec_file();
                break;
            case CMD_EXIT:
                return 0;
            default:
                printf("Invalid command requested: %d\n",cmd);
                break;
        }
    }

}
