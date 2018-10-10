/*-------------------------------------------------------------------------------

   Copyright (C) 2018 Cisco Talos Security Intelligence and Research Group

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

#ifndef QEMU_GLUE_SLEUTHKIT_H
#define QEMU_GLUE_SLEUTHKIT_H

typedef enum {QEMU_GLUE_TSK_FILE, QEMU_GLUE_TSK_DIR} QEMU_GLUE_TSK_PATH_TYPE;

typedef struct {
    unsigned int number_of_filenames;
    char** filenames;
} QEMU_GLUE_TSK_DIR_INFO;

typedef struct {
    uint64_t size;
    char* filename;
    void* fs_file;
} QEMU_GLUE_TSK_FILE_INFO;

typedef struct {
  QEMU_GLUE_TSK_PATH_TYPE type;
  union {
      QEMU_GLUE_TSK_FILE_INFO file_info;
      QEMU_GLUE_TSK_DIR_INFO dir_info;
  } info;
} QEMU_GLUE_TSK_PATH_INFO;

typedef struct {
    int number;
    const char* fs_type;
    uint64_t size;
} QEMU_GLUE_TSK_FILESYSTEM;

// Functions exported to the rest of PyREBox, for TSK integration.
int qemu_glue_tsk_get_number_filesystems(void);
QEMU_GLUE_TSK_FILESYSTEM* qemu_glue_tsk_get_filesystem(int number);
void qemu_glue_tsk_free_filesystem(QEMU_GLUE_TSK_FILESYSTEM* filesystem);

QEMU_GLUE_TSK_PATH_INFO* qemu_glue_tsk_ls(unsigned int fs, char* path);
void qemu_glue_tsk_free_path_info(QEMU_GLUE_TSK_PATH_INFO* path_info);

uint32_t qemu_glue_tsk_read_file(QEMU_GLUE_TSK_PATH_INFO* path_info, uint64_t offset, uint32_t size, char* buffer);

#endif
