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
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

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

void copy_char_array_array(void* output_array, void* input_array)
{
    /* Copy the char** array, where the char* pointers point to strings that are contained in the buffer itself */

    //Count the number of elements in the array 
    uintptr_t array_p = *((uintptr_t*) input_array);
    int num_args = 0;
    while (array_p != 0) {
        num_args += 1;
        array_p = *((uintptr_t*) (((uintptr_t)input_array) + (num_args * sizeof(uintptr_t))));
    }

    //Copy the array pointers into arg strings
    for (int i = 0; i < num_args; i++){
        uintptr_t buffer_offset = ((uintptr_t)*((uintptr_t*) ((uintptr_t) input_array + (i * sizeof(uintptr_t))))) - ((uintptr_t) input_array);
        *((uintptr_t*)(((uintptr_t)output_array) + (i * sizeof(uintptr_t)))) = ((uintptr_t) output_array) + buffer_offset;
    }

    //Write last \x00 termination element
    *((uintptr_t*)(((uintptr_t)output_array) + (num_args * sizeof(uintptr_t)))) = ((uintptr_t) 0);

    //Copy the rest of the buffer
    memcpy((uintptr_t*)(((uintptr_t)output_array) + ((num_args + 1) * sizeof(uintptr_t))), (uintptr_t*)((uintptr_t) input_array + ((num_args + 1) * sizeof(uintptr_t))), MAX_BUFFER_SIZE - ((num_args + 1) * sizeof(uintptr_t)));

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


    ret_args = host_request_exec_args_linux(agent_buffer, MAX_BUFFER_SIZE);

    copy_char_array_array((void*) args, (void*) agent_buffer);

    ret_env = host_request_exec_env_linux(agent_buffer, MAX_BUFFER_SIZE);

    copy_char_array_array((void*) env, (void*) agent_buffer);


    /* Create a child process to execute the program */

    pid_t child_proc = fork();
    if (child_proc == 0){
        //Make sure the file has x permission
        char command[MAX_BUFFER_SIZE];
        snprintf(command, MAX_BUFFER_SIZE, "chmod +x %s", path);
        system(command);
        //Child process
        if (ret_env > 0){
            execvpe(path, (char**) args, (char**) env);
        } else {
            execvp(path, (char**) args);
        }
    } else if (child_proc > 0) {
        return 0;
    } else {
        perror("Process creation failed\n");
    }

    return 0;
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
