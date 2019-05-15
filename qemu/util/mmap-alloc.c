/*
 * Support for RAM backed by mmaped host memory.
 *
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * Authors:
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/mmap-alloc.h"
#include "qemu/host-utils.h"

#define HUGETLBFS_MAGIC       0x958458f6

#ifdef CONFIG_LINUX
#include <sys/vfs.h>
#endif

size_t qemu_fd_getpagesize(int fd)
{
#ifdef CONFIG_LINUX
    struct statfs fs;
    int ret;

    if (fd != -1) {
        do {
            ret = fstatfs(fd, &fs);
        } while (ret != 0 && errno == EINTR);

        if (ret == 0 && fs.f_type == HUGETLBFS_MAGIC) {
            return fs.f_bsize;
        }
    }
#ifdef __sparc__
    /* SPARC Linux needs greater alignment than the pagesize */
    return QEMU_VMALLOC_ALIGN;
#endif
#endif

    return getpagesize();
}

size_t qemu_mempath_getpagesize(const char *mem_path)
{
#ifdef CONFIG_LINUX
    struct statfs fs;
    int ret;

    if (mem_path) {
        do {
            ret = statfs(mem_path, &fs);
        } while (ret != 0 && errno == EINTR);

        if (ret != 0) {
            fprintf(stderr, "Couldn't statfs() memory path: %s\n",
                    strerror(errno));
            exit(1);
        }

        if (fs.f_type == HUGETLBFS_MAGIC) {
            /* It's hugepage, return the huge page size */
            return fs.f_bsize;
        }
    }
#ifdef __sparc__
    /* SPARC Linux needs greater alignment than the pagesize */
    return QEMU_VMALLOC_ALIGN;
#endif
#endif

    return getpagesize();
}

void *qemu_ram_mmap(int fd, size_t size, size_t align, bool shared)
{
    int flags;
    int guardfd;
    size_t offset;
    size_t pagesize;
    size_t total;
    void *guardptr;
    void *ptr;

    /*
     * Note: this always allocates at least one extra page of virtual address
     * space, even if size is already aligned.
     */
    total = size + align;

#if defined(__powerpc64__) && defined(__linux__)
    /* On ppc64 mappings in the same segment (aka slice) must share the same
     * page size. Since we will be re-allocating part of this segment
     * from the supplied fd, we should make sure to use the same page size, to
     * this end we mmap the supplied fd.  In this case, set MAP_NORESERVE to
     * avoid allocating backing store memory.
     * We do this unless we are using the system page size, in which case
     * anonymous memory is OK.
     */
    flags = MAP_PRIVATE;
    pagesize = qemu_fd_getpagesize(fd);
    if (fd == -1 || pagesize == getpagesize()) {
        guardfd = -1;
        flags |= MAP_ANONYMOUS;
    } else {
        guardfd = fd;
        flags |= MAP_NORESERVE;
    }
#else
    guardfd = -1;
    pagesize = getpagesize();
    flags = MAP_PRIVATE | MAP_ANONYMOUS;
#endif

    guardptr = mmap(0, total, PROT_NONE, flags, guardfd, 0);

    if (guardptr == MAP_FAILED) {
        return MAP_FAILED;
    }

    assert(is_power_of_2(align));
    /* Always align to host page size */
    assert(align >= pagesize);

    flags = MAP_FIXED;
    flags |= fd == -1 ? MAP_ANONYMOUS : 0;
    flags |= shared ? MAP_SHARED : MAP_PRIVATE;
    offset = QEMU_ALIGN_UP((uintptr_t)guardptr, align) - (uintptr_t)guardptr;

    ptr = mmap(guardptr + offset, size, PROT_READ | PROT_WRITE, flags, fd, 0);

    if (ptr == MAP_FAILED) {
        munmap(guardptr, total);
        return MAP_FAILED;
    }

    if (offset > 0) {
        munmap(guardptr, offset);
    }

    /*
     * Leave a single PROT_NONE page allocated after the RAM block, to serve as
     * a guard page guarding against potential buffer overflows.
     */
    total -= offset;
    if (total > size + pagesize) {
        munmap(ptr + size + pagesize, total - size - pagesize);
    }

    return ptr;
}

void qemu_ram_munmap(int fd, void *ptr, size_t size)
{
    size_t pagesize;

    if (ptr) {
        /* Unmap both the RAM block and the guard page */
#if defined(__powerpc64__) && defined(__linux__)
        pagesize = qemu_fd_getpagesize(fd);
#else
        pagesize = getpagesize();
#endif
        munmap(ptr, size + pagesize);
    }
}
