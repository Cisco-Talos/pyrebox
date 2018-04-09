/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "chardev/char.h"
#include "io/channel-file.h"

#include "chardev/char-fd.h"
#include "chardev/char-io.h"
#include "pyrebox/pyrebox.h"

/* Called with chr_write_lock held.  */
static int fd_chr_write(Chardev *chr, const uint8_t *buf, int len)
{
    FDChardev *s = FD_CHARDEV(chr);

    return io_channel_send(s->ioc_out, buf, len);
}

static gboolean fd_chr_read(QIOChannel *chan, GIOCondition cond, void *opaque)
{
    // If the pyrebox_mutex is locked, we do not read any data, we just return.
    //
    // This must be done both on fd_chr_read and fd_chr_read_poll. Actually,
    // fd_chr_read_poll is called first, and it should return the number
    // of bytes available for read. So, if the pyrebox_mutex is locked, fd_chr_read_poll 
    // returns 0 (see the function), and this function is not even called.
    //
    // These functions conflict with ipython, which will receive/send 
    // control characters over stdin/stdout, causing both not to work properly
    // if run concurrently.
    //
    // Python callbacks can potenially enter the ipython shell, as the user-defined
    // callback routine may at any moment invoke the start_shell() function. 
    //
    // Therefore, we need to avoid running this fd-chardev reading function
    // whenever we are executing a python callback.
    //
    // pyrebox_mutex is acquired every time we execute a python function
    // that has the potential to open an ipython shell. Any callback that ends
    // up executing a user-defined python callback may end up starting a shell.
    //
    // Nevertheless, in this function we cannot just lock the pyrebox_mutex, because
    // it causes a dead-lock in the following conditions:
    //
    //     A python callback first aquires pyrebox_mutex and then
    //     starts a memory read/write operation over an address that corresponds
    //     to I/O memory (volatility usually does it). In that case, the memory 
    //     read operation will try to acquire the iothread mutex and wait for it 
    //     to be released. This mutex may have been locked 
    //     at the main_loop, which may call this function while holding the iothread
    //     mutex. This ends up in a dead-lock.
    //
    //     So, the thread executing the callback first locks pyrebox_mutex and then tries
    //     to lock iothread mutex, while this thread first locks iothread_mutex
    //     and afterwards tries to acquire the pyrebox_mutex. Since this thread
    //     keeps waiting for the pyrebox_mutex to be released, it locks
    //     the main-loop and prevents it from dealing with the IO memory r/w.
    //
    // The solution is to try to acquire the pyrebox_mutex lock, without waiting for
    // it. If it is locked, we just do not execute this fd_chr_read function,
    // (it will be called again sometime later), return TRUE, and keep running.
    //
    // We make sure that this function is only run when the pyrebox_mutex 
    // is not owned by any callback running in parallel.
    //
    // We also apply the same approach to fd_chr_read_poll,
    // which determines the number of bytes to read, and causes this function
    // to be called.

    int lock_result = pthread_mutex_trylock(&pyrebox_mutex);
    if (lock_result == EBUSY){
        return TRUE;
    } else if (lock_result > 0){
        printf("pthread_mutex_trylock(&pyrebox_mutex) returned %d, which should never happen!\n", lock_result);
        assert(0);
    }
    
    Chardev *chr = CHARDEV(opaque);
    FDChardev *s = FD_CHARDEV(opaque);
    int len;
    uint8_t buf[CHR_READ_BUF_LEN];
    ssize_t ret;

    len = sizeof(buf);
    if (len > s->max_size) {
        len = s->max_size;
    }
    if (len == 0) {
        //Unlock the pyrebox mutex
        pthread_mutex_unlock(&pyrebox_mutex);

        return TRUE;
    }

    ret = qio_channel_read(
        chan, (gchar *)buf, len, NULL);
    if (ret == 0) {
        remove_fd_in_watch(chr);
        qemu_chr_be_event(chr, CHR_EVENT_CLOSED);
        //Unlock the pyrebox mutex
        pthread_mutex_unlock(&pyrebox_mutex);

        return FALSE;
    }
    if (ret > 0) {
        qemu_chr_be_write(chr, buf, ret);
    }

    //Unlock the pyrebox mutex
    pthread_mutex_unlock(&pyrebox_mutex);

    return TRUE;

}

static int fd_chr_read_poll(void *opaque)
{
    // See comment on fd_chr_read for information
    // about pyrebox_mutex
    int lock_result = pthread_mutex_trylock(&pyrebox_mutex);
    if (lock_result == EBUSY){
        return 0;
    } else if (lock_result > 0){
        printf("pthread_mutex_trylock(&pyrebox_mutex) returned %d, which should never happen!\n", lock_result);
        assert(0);
    }

    Chardev *chr = CHARDEV(opaque);
    FDChardev *s = FD_CHARDEV(opaque);

    s->max_size = qemu_chr_be_can_write(chr);

    //Unlock the pyrebox mutex
    pthread_mutex_unlock(&pyrebox_mutex);

    return s->max_size;
}

static GSource *fd_chr_add_watch(Chardev *chr, GIOCondition cond)
{
    FDChardev *s = FD_CHARDEV(chr);
    return qio_channel_create_watch(s->ioc_out, cond);
}

static void fd_chr_update_read_handler(Chardev *chr)
{
    FDChardev *s = FD_CHARDEV(chr);

    remove_fd_in_watch(chr);
    if (s->ioc_in) {
        chr->gsource = io_add_watch_poll(chr, s->ioc_in,
                                           fd_chr_read_poll,
                                           fd_chr_read, chr,
                                           chr->gcontext);
    }
}

static void char_fd_finalize(Object *obj)
{
    Chardev *chr = CHARDEV(obj);
    FDChardev *s = FD_CHARDEV(obj);

    remove_fd_in_watch(chr);
    if (s->ioc_in) {
        object_unref(OBJECT(s->ioc_in));
    }
    if (s->ioc_out) {
        object_unref(OBJECT(s->ioc_out));
    }

    qemu_chr_be_event(chr, CHR_EVENT_CLOSED);
}

int qmp_chardev_open_file_source(char *src, int flags, Error **errp)
{
    int fd = -1;

    TFR(fd = qemu_open(src, flags, 0666));
    if (fd == -1) {
        error_setg_file_open(errp, errno, src);
    }
    return fd;
}

/* open a character device to a unix fd */
void qemu_chr_open_fd(Chardev *chr,
                      int fd_in, int fd_out)
{
    FDChardev *s = FD_CHARDEV(chr);
    char *name;

    s->ioc_in = QIO_CHANNEL(qio_channel_file_new_fd(fd_in));
    name = g_strdup_printf("chardev-file-in-%s", chr->label);
    qio_channel_set_name(QIO_CHANNEL(s->ioc_in), name);
    g_free(name);
    s->ioc_out = QIO_CHANNEL(qio_channel_file_new_fd(fd_out));
    name = g_strdup_printf("chardev-file-out-%s", chr->label);
    qio_channel_set_name(QIO_CHANNEL(s->ioc_out), name);
    g_free(name);
    qemu_set_nonblock(fd_out);
}

static void char_fd_class_init(ObjectClass *oc, void *data)
{
    ChardevClass *cc = CHARDEV_CLASS(oc);

    cc->chr_add_watch = fd_chr_add_watch;
    cc->chr_write = fd_chr_write;
    cc->chr_update_read_handler = fd_chr_update_read_handler;
}

static const TypeInfo char_fd_type_info = {
    .name = TYPE_CHARDEV_FD,
    .parent = TYPE_CHARDEV,
    .instance_size = sizeof(FDChardev),
    .instance_finalize = char_fd_finalize,
    .class_init = char_fd_class_init,
    .abstract = true,
};

static void register_types(void)
{
    type_register_static(&char_fd_type_info);
}

type_init(register_types);
