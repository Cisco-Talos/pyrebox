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
#include <Python.h>
#include <limits.h>

#include "tsk/libtsk.h"
//QEMU includes
#include "qemu/queue.h"
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/option.h"
#include "migration/vmstate.h"
#include "sysemu/sysemu.h"
#include "monitor/monitor.h"
#include "cpu.h"
#include "block/block.h"
#include "block/block_int.h"
#include "sysemu/block-backend.h"
#include "pyrebox/qemu_glue.h"
#include "pyrebox/qemu_glue_block.h"
#include "pyrebox/qemu_glue_sleuthkit.h"
#include "pyrebox/qemu_glue_sleuthkit_internal.h"
#include "pyrebox/utils.h"

disk_info_t disk_info_internal[MAX_DEVICES];
static int devices=0;

int pyrebox_bdrv_pread(void *opaque, int64_t offset, void *buf, int count) {
    return blk_pread(((BlockBackend*) opaque), offset, buf, count);
}

void pyrebox_bdrv_open(void *opaque){
    if (opaque == NULL || blk_bs((BlockBackend *)opaque) == NULL){
        return;
    }
    unsigned long img_size = blk_bs((BlockBackend *)opaque)->total_sectors * PYREBOX_TSK_SECTOR_SIZE;

    if(!qemu_pread)
        qemu_pread=(qemu_pread_t)pyrebox_bdrv_pread;

    utils_print("\n[SLEUTHKIT]\nOpening image - Size: %lu\n", img_size);

    void* bs = blk_bs((BlockBackend *)opaque);
    TSK_IMG_INFO* img = tsk_img_open(1, (const char **) &opaque, QEMU_IMG, 0);
    img->size = img_size;

    if (img==NULL) {
        utils_print_error("[!] Error while opening image\n");
        tsk_error_print(stdout);
        return;
    }

    TSK_VS_INFO* vs = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT);
    if (!vs){
        utils_print_error("[!] Error, could not open volume system\n");
        tsk_error_print(stdout);
        return;
    } else {
        utils_print("[*] Found volume system of type %s at %lx, number of partitions: %d\n", tsk_vs_type_todesc(vs->vstype), vs->offset, vs->part_count);
    }
    for (int i = 0; i < vs->part_count; ++i){
        const TSK_VS_PART_INFO* pi = tsk_vs_part_get(vs, i);
        utils_print("    [#] Partition %d - Start sector: %lx - Number of sectors: %lx - Desc: %s\n", i, pi->start, pi->len, pi->desc);
        if (pi != NULL){
            if ((pi->flags & TSK_VS_PART_FLAG_ALLOC) && !(pi->flags & TSK_VS_PART_FLAG_META)){
                TSK_FS_INFO *fs = tsk_fs_open_img(img, pi->start * PYREBOX_TSK_SECTOR_SIZE, TSK_FS_TYPE_DETECT);
                if (fs != NULL){
                    utils_print("        [+] Found file system type %s at %lx\n", tsk_fs_type_toname(fs->ftype), fs->offset);
                    // Now, we save the metadata
                    if (devices < MAX_DEVICES){
                        disk_info_internal[devices].bs = bs;
                        disk_info_internal[devices].img = img;
                        disk_info_internal[devices].vs = vs;
                        disk_info_internal[devices].pi = pi;
                        disk_info_internal[devices].fs = fs;
                        ++devices;
                    } else {
                        utils_print_error("        [!] Already saved metadata for %d (MAX_DEVICES) file systems, ignoring file system...\n", MAX_DEVICES);
                    }
                } else {
                    utils_print_error("        [!] Error, could not read the file system on partition %d\n", i);
                    tsk_error_print(stdout);
                }
            }
        } else {
            utils_print_error("    [!] Error, could not retrieve info for partition %d\n", i);
            tsk_error_print(stdout);
        }
    }
}

int qemu_glue_tsk_get_number_filesystems(void){
    return devices;
}

QEMU_GLUE_TSK_FILESYSTEM* qemu_glue_tsk_get_filesystem(int number){
    if (number >= devices){
        utils_print_error("[!] The file system number specified does not exist\n");
        return NULL;
    } else {
        // Retrieve file system and populate a QEMU_GLUE_TSK_FILESYSTEM structure
        QEMU_GLUE_TSK_FILESYSTEM* fs = (QEMU_GLUE_TSK_FILESYSTEM*)malloc(sizeof(QEMU_GLUE_TSK_FILESYSTEM));
        if (fs == NULL){
            return NULL;
        }
        fs->size = (uint64_t)  (disk_info_internal[number].fs->block_size * disk_info_internal[number].fs->block_count);
        fs->number = number;
        fs->fs_type = tsk_fs_type_toname(disk_info_internal[number].fs->ftype);
        return fs;
    }
}

void qemu_glue_tsk_free_filesystem(QEMU_GLUE_TSK_FILESYSTEM* filesystem){
    if (filesystem != NULL){
        free(filesystem);
    }
}

QEMU_GLUE_TSK_PATH_INFO* qemu_glue_tsk_ls(unsigned int fs_number, char* path){
    if(fs_number >= devices){
        utils_print_error("[!] The file system number specified does not exist\n");
        return NULL;
    }
    tsk_error_reset();
    TSK_FS_DIR* fs_dir = tsk_fs_dir_open(disk_info_internal[fs_number].fs, path);
    if(fs_dir != NULL){
        // It is a directory, get info and generate QEMU_GLUE_TSK_PATH_INFO structure
        QEMU_GLUE_TSK_PATH_INFO* res = (QEMU_GLUE_TSK_PATH_INFO*) malloc(sizeof(QEMU_GLUE_TSK_PATH_INFO));
        if (res != NULL){
            res->type = QEMU_GLUE_TSK_DIR;
            res->info.dir_info.filenames = (char**) malloc(sizeof(char*) * fs_dir->names_used);
            if (res->info.dir_info.filenames == NULL){
                utils_print_error("[!] Could not allocate structure QEMU_GLUE_TSK_PATH_INFO\n");
                free(res);
                return NULL;
            }
            res->info.dir_info.number_of_filenames = fs_dir->names_used;
            //Zero out
            for (int i = 0; i < fs_dir->names_used; ++i){
                res->info.dir_info.filenames[i] = NULL;
            }
            //Copy filenames
            for (int i = 0; i < fs_dir->names_used; ++i){
                res->info.dir_info.filenames[i] = (char*) malloc(fs_dir->names[i].name_size);
                if(res->info.dir_info.filenames[i] == NULL){
                    utils_print_error("[!] Could not allocate structure QEMU_GLUE_TSK_PATH_INFO\n");
                    // Free allocated names
                    for (int i = 0; i < fs_dir->names_used; ++i){
                        if (res->info.dir_info.filenames[i] != NULL){
                            free(res->info.dir_info.filenames[i]);
                            res->info.dir_info.filenames[i] = NULL;
                        }
                    }
                    // Free name array
                    free(res->info.dir_info.filenames);
                    // Free structure
                    free(res);
                    return NULL;
                }
                memcpy(res->info.dir_info.filenames[i], fs_dir->names[i].name, fs_dir->names[i].name_size);
            }
            return res;
        } else {
            utils_print_error("[!] Could not allocate structure QEMU_GLUE_TSK_PATH_INFO\n");
            return NULL;
        }
    } else {
        if (tsk_error_get_errno() == TSK_ERR_FS_ARG){
            // File or directory does not exist
            // If the file or directory does not exist, just return NULL
            // and do not log anything
            return NULL;
        } else if (tsk_error_get_errno() == TSK_ERR_FS_ATTR_NOTFOUND){
            // If it is not a directory, but a file
            TSK_FS_FILE* fs_file = tsk_fs_file_open(disk_info_internal[fs_number].fs, 0, path);
            if (fs_file == NULL){
                if (tsk_error_get_errno() == TSK_ERR_FS_ARG){
                    // File or directory does not exist
                    // If the file or directory does not exist, just return NULL
                    // and do not log anything
                    return NULL;
                } else {
                    utils_print_error("[!] Error while listing file or directory\n");
                    tsk_error_print(stdout);
                    return NULL;
                }
            } else {
                // It is a file, get info and generate QEMU_GLUE_TSK_PATH_INFO structure
                QEMU_GLUE_TSK_PATH_INFO* res = (QEMU_GLUE_TSK_PATH_INFO*) malloc(sizeof(QEMU_GLUE_TSK_PATH_INFO));
                if (res != NULL){
                    res->type = QEMU_GLUE_TSK_FILE;
                    res->info.file_info.fs_file = (void*)fs_file;
                    res->info.file_info.size = fs_file->meta->size;
                    res->info.file_info.filename = (char*)malloc(fs_file->name->name_size);
                    if(res->info.file_info.filename != NULL){
                        memcpy(res->info.file_info.filename, fs_file->name->name, fs_file->name->name_size);
                        return res;
                    } else {
                        free(res);
                        utils_print_error("[!] Could not allocate structure QEMU_GLUE_TSK_PATH_INFO\n");
                        return NULL;
                    }
                } else {
                    utils_print_error("[!] Could not allocate structure QEMU_GLUE_TSK_PATH_INFO\n");
                    return NULL;
                }
            }
        } else {
            utils_print_error("[!] Error while listing file or directory:\n");
            tsk_error_print(stdout);
            return NULL;
        }
    }
    return NULL;
}
void qemu_glue_tsk_free_path_info(QEMU_GLUE_TSK_PATH_INFO* path_info){
    if (path_info != NULL){
        if(path_info->type == QEMU_GLUE_TSK_DIR){
            if(path_info->info.dir_info.filenames != NULL){
                // Free allocated names
                for (int i = 0; i < path_info->info.dir_info.number_of_filenames; ++i){
                    if (path_info->info.dir_info.filenames[i] != NULL){
                        free(path_info->info.dir_info.filenames[i]);
                        path_info->info.dir_info.filenames[i] = NULL;
                    }
                }
                // Free name array
                free(path_info->info.dir_info.filenames);
            }
        } else if (path_info->type == QEMU_GLUE_TSK_FILE){
            if (path_info->info.file_info.filename != NULL){
                free(path_info->info.file_info.filename);
                path_info->info.file_info.filename = NULL;
            }
            if (path_info->info.file_info.fs_file != NULL){
                free(((TSK_FS_FILE*)(path_info->info.file_info.fs_file)));
            }
        } else {
            utils_print_error("[!] Unsupported QEMU_GLUE_TSK_PATH_INFO type on qemu_glue_tsk_free_path_info function.\n");
        }
    // Free structure
    free(path_info);
    }
}

// Reads data from a file, and returns the number of bytes read
// or 0 if file does not exist, or trying to read outside the contents,
// or the buffer is not properly allocated. In this last case,
// prints error message.
uint32_t qemu_glue_tsk_read_file(QEMU_GLUE_TSK_PATH_INFO* path_info, uint64_t offset, uint32_t size, char* buffer){
    if(path_info == NULL || path_info->type != QEMU_GLUE_TSK_FILE){
        utils_print_error("The path_info provided is either NULL or has an incorrect type\n");
        return 0;
    }
    if(buffer == NULL){
        utils_print_error("The buffer provided as parameter is NULL\n");
        return 0;
    }
    if(size == 0 || ((offset + (uint64_t)size) > path_info->info.file_info.size)){
        utils_print_error("Incorrect file offset or size\n");
        return 0;
    }
    if(path_info->info.file_info.fs_file == NULL){
        utils_print_error("TSK_FS_FILE structure not properly allocated\n");
        return 0;
    }
    ssize_t res = tsk_fs_file_read((TSK_FS_FILE*)(path_info->info.file_info.fs_file), (TSK_OFF_T)offset, buffer, (size_t) size, TSK_FS_FILE_READ_FLAG_NONE);
    if(res < 0){
        utils_print_error("[!] Error while reading file\n");
        tsk_error_print(stdout);
        return 0;
    } else {
        return (uint32_t) res;
    }
}

void pyrebox_test_read_disk(void){
    QEMU_GLUE_TSK_FILESYSTEM* fs = qemu_glue_tsk_get_filesystem(0);
    if (fs == NULL){
        printf("Could not obtain filesystem\n");
        return;
    }
    QEMU_GLUE_TSK_PATH_INFO* pi = qemu_glue_tsk_ls(fs->number, (char*)"boot.ini");
    if (pi == NULL){
        printf("Could not obtain path info\n");
    } else {
        char* buffer = (char*)malloc(pi->info.file_info.size);
        printf("Trying to read %lu bytes\n", pi->info.file_info.size);
        printf("Bytes_read: %d\n", qemu_glue_tsk_read_file(pi, 0, pi->info.file_info.size, buffer));
        printf("Buffer: %s\n", buffer);
        qemu_glue_tsk_free_path_info(pi);
        free(buffer);
    }

    pi = qemu_glue_tsk_ls(fs->number, (char*)"");
    if (pi == NULL){
        printf("Could not obtain path info\n");
    } else {
        for(int i = 0; i < pi->info.dir_info.number_of_filenames; i++){
            printf("Filename: %s\n", pi->info.dir_info.filenames[i]);
        }
        qemu_glue_tsk_free_path_info(pi);
    }
    qemu_glue_tsk_free_filesystem(fs);
}
