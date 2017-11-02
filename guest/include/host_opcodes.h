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

#ifndef HOST_OPCODES_H
#define HOST_OPCODES_H

#include <string.h>
#include <inttypes.h>

/* 
 "\x00\x00": self.handle_host_version,
 "\x00\x01": self.handle_host_message,
 "\x00\x02": self.handle_host_get_command,
 "\x10\x00": self.handle_host_open,
 "\x10\x01": self.handle_host_read,
 "\x10\x02": self.handle_host_close,
 "\x10\x03": self.handle_get_file_name,
 "\x20\x00": self.handle_host_request_exec_path,
 "\x20\x01": self.handle_host_request_exec_args,
 "\x20\x02": self.handle_host_request_exec_env
 "\x20\x03": self.handle_host_request_exec_args_linux,
 "\x20\x04": self.handle_host_request_exec_env_linux
*/

#define HOST_INSTRUCTION(v1, v2) \
    ".byte 0x0f, 0x3f\n"         \
    ".byte 0x00, " #v1 "\n"      \
    ".byte " #v2 ", 0x00\n"      \
    ".byte 0x00, 0x00, 0x00\n"   \
    ".byte 0x00\n"

static inline void touch_buffer(const char* buffer, int size) {
    volatile const char *b = buffer;
    int i;
    for (i = 0; i < size; ++i, ++b) {
        *b;
    }
}

/**
 * Get the host-guest interface version.
 * This call is currently used to figure out if we are running in Pyrebox.
 */
static inline int host_get_version() {
    int version = 0;

    __asm__ __volatile__(
        HOST_INSTRUCTION(0x00, 0x00) : "=a" (version));
    return version;
}

/**
 * Log a message to the host.
 * :arg msg: Message string.
 */
static inline void host_message(const char* msg) {
    touch_buffer(msg, strlen(msg));

    __asm__ __volatile__(
        HOST_INSTRUCTION(0x00, 0x01) : : "a" (msg));
}

/**
 * Wait for Pyrebox to signal that it wants some command
 * to be executed.
 */
static inline int host_get_command() {
     int command;
     __asm__ __volatile__(
        HOST_INSTRUCTION(0x00, 0x02) : "=a" (command));
     return command;
}


/**
 * Open a file on the host.
 * :arg name: The file's name. The name is mapped by the host to the actual
 *     path (as a security measure). \
 * :returns: A file descriptor which can be used to read from this file, or -1
 *     on error.
 */
static inline int host_open(const char* name) {
    int fd;

    touch_buffer(name, strlen(name) + 1);
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x10, 0x00)
        : "=a" (fd) : "a" (name));
    return fd;
}

/**
 * Read data from a file on the host (opened with host_open).
 * :arg fd: The file descriptor.
 * :arg buffer: A data buffer where the read data will be stored.
 * :arg size: Size of the data buffer.
 * :returns: The number of bytes read, or -1 on error.
 */
static inline int host_read(int fd, char* buffer, int size) {
    int ret;

    touch_buffer(buffer, size);
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x10, 0x01)
        : "=a" (ret) : "a" (fd), "b" (buffer), "c" (size));

    return ret;
}

/**
 * Close a host file descriptor.
 * :arg fd: The file descriptor.
 * :returns: 0 on success or -1 on error.
 */
static inline void host_close(int fd) {
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x10, 0x02)
        : : "a" (fd));
}

/**
 * Copies the file name for a file copy operation into a buffer.
 * :arg buffer: The output buffer in which the file name will be copied
 * :arg max_buffer_size: The size of the output buffer.
 * :returns: The length of the copied data.
 */
static inline int host_get_file_name(char* buffer, int max_buffer_size){
    int ret;
    memset(buffer, 0, max_buffer_size);
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x10, 0x03) : "=a" (ret) : 
            "a" (buffer), "b" (max_buffer_size));

    return ret;
}

/**
 * Copies the file path for a file execution operation into a buffer.
 * :arg buffer: The output buffer in which the file path will be copied.
 * :arg max_buffer_size: The size of the output buffer.
 * :returns: The length of the copied data.
 */
static inline int host_request_exec_path(char* buffer, int max_buffer_size){
    int ret;
    memset(buffer, 0, max_buffer_size);
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x20, 0x00) : "=a" (ret) : 
            "a" (buffer), "b" (max_buffer_size));

    return ret;
}

/**
 * Copies the argument list for a file execution operation into a buffer.
 * :arg buffer: The output buffer in which the argument list will be copied.
 * :arg max_buffer_size: The size of the output buffer.
 * :returns: The length of the copied data.
 */
static inline int host_request_exec_args(char* buffer, int max_buffer_size){
    int ret;
    memset(buffer, 0, max_buffer_size);
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x20, 0x01) : "=a" (ret) : 
            "a" (buffer), "b" (max_buffer_size));

    return ret;
}

/**
 * Copies the env variable list for a file execution operation into a buffer.
 * :arg buffer: The output buffer in which the env variable list will be copied.
 * :arg max_buffer_size: The size of the output buffer.
 * :returns: The length of the copied data.
 */
static inline int host_request_exec_env(char* buffer, int max_buffer_size){

    int ret;
    memset(buffer, 0, max_buffer_size);
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x20, 0x02) : "=a" (ret) : 
            "a" (buffer), "b" (max_buffer_size));

    return ret;
}

/**
 * Copies the argument list for a file execution operation into a buffer.
 * :arg buffer: The output buffer in which the argument list will be copied.
 * :arg max_buffer_size: The size of the output buffer.
 * :returns: The length of the copied data.
 */
static inline int host_request_exec_args_linux(char* buffer, int max_buffer_size){
    int ret;
    memset(buffer, 0, max_buffer_size);
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x20, 0x03) : "=a" (ret) : 
            "a" (buffer), "b" (max_buffer_size));

    return ret;
}

/**
 * Copies the env variable list for a file execution operation into a buffer.
 * :arg buffer: The output buffer in which the env variable list will be copied.
 * :arg max_buffer_size: The size of the output buffer.
 * :returns: The length of the copied data.
 */
static inline int host_request_exec_env_linux(char* buffer, int max_buffer_size){

    int ret;
    memset(buffer, 0, max_buffer_size);
    __asm__ __volatile__(
        HOST_INSTRUCTION(0x20, 0x04) : "=a" (ret) : 
            "a" (buffer), "b" (max_buffer_size));

    return ret;
}

        
#endif
