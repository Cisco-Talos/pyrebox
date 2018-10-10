/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */

/* 
 * Contains the single raw data file-specific functions and structures.
 */

#ifndef _RAW_H
#define _RAW_H

#include "img_writer.h"

#ifdef __cplusplus
extern "C" {
#endif
    /* PyREBox: This code was taken from DECAF: https://github.com/sycurelab/DECAF */
    //QCOW2 image open
    extern TSK_IMG_INFO *qemu_image_open(void *opaque, unsigned int a_ssize);

    extern TSK_IMG_INFO *raw_open(int a_num_img,
        const TSK_TCHAR * const a_images[], unsigned int a_ssize);

#define SPLIT_CACHE	15

    typedef struct {
#ifdef TSK_WIN32
        HANDLE fd;
#else
        int fd;
#endif
        int image;
        TSK_OFF_T seek_pos;
    } IMG_SPLIT_CACHE;

    typedef struct {
        TSK_IMG_INFO img_info;
        uint8_t is_winobj;
        TSK_IMG_WRITER *img_writer;

        // the following are protected by cache_lock in IMG_INFO
        TSK_OFF_T *max_off;
        int *cptr;              /* exists for each image - points to entry in cache */
        IMG_SPLIT_CACHE cache[SPLIT_CACHE];     /* small number of fds for open images */
        int next_slot;
    } IMG_RAW_INFO;

    /* PyREBox: This code was taken from DECAF: https://github.com/sycurelab/DECAF */
    // Image open struct
    typedef struct _IMG_QEMU_INFO IMG_QEMU_INFO;
  
    struct _IMG_QEMU_INFO {
       TSK_IMG_INFO img_info;
       void * opaque; 
    };

#ifdef __cplusplus
}
#endif
#endif
