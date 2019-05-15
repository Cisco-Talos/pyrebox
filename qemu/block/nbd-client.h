#ifndef NBD_CLIENT_H
#define NBD_CLIENT_H

#include "qemu-common.h"
#include "block/nbd.h"
#include "block/block_int.h"
#include "io/channel-socket.h"

/* #define DEBUG_NBD */

#if defined(DEBUG_NBD)
#define logout(fmt, ...) \
    fprintf(stderr, "nbd\t%-24s" fmt, __func__, ##__VA_ARGS__)
#else
#define logout(fmt, ...) ((void)0)
#endif

#define MAX_NBD_REQUESTS    16

typedef struct {
    Coroutine *coroutine;
    uint64_t offset;        /* original offset of the request */
    bool receiving;         /* waiting for connection_co? */
} NBDClientRequest;

typedef struct NBDClientSession {
    QIOChannelSocket *sioc; /* The master data channel */
    QIOChannel *ioc; /* The current I/O channel which may differ (eg TLS) */
    NBDExportInfo info;

    CoMutex send_mutex;
    CoQueue free_sema;
    Coroutine *connection_co;
    int in_flight;

    NBDClientRequest requests[MAX_NBD_REQUESTS];
    NBDReply reply;
    BlockDriverState *bs;
    bool quit;
} NBDClientSession;

NBDClientSession *nbd_get_client_session(BlockDriverState *bs);

int nbd_client_init(BlockDriverState *bs,
                    SocketAddress *saddr,
                    const char *export_name,
                    QCryptoTLSCreds *tlscreds,
                    const char *hostname,
                    const char *x_dirty_bitmap,
                    Error **errp);
void nbd_client_close(BlockDriverState *bs);

int nbd_client_co_pdiscard(BlockDriverState *bs, int64_t offset, int bytes);
int nbd_client_co_flush(BlockDriverState *bs);
int nbd_client_co_pwritev(BlockDriverState *bs, uint64_t offset,
                          uint64_t bytes, QEMUIOVector *qiov, int flags);
int nbd_client_co_pwrite_zeroes(BlockDriverState *bs, int64_t offset,
                                int bytes, BdrvRequestFlags flags);
int nbd_client_co_preadv(BlockDriverState *bs, uint64_t offset,
                         uint64_t bytes, QEMUIOVector *qiov, int flags);

void nbd_client_detach_aio_context(BlockDriverState *bs);
void nbd_client_attach_aio_context(BlockDriverState *bs,
                                   AioContext *new_context);

int coroutine_fn nbd_client_co_block_status(BlockDriverState *bs,
                                            bool want_zero,
                                            int64_t offset, int64_t bytes,
                                            int64_t *pnum, int64_t *map,
                                            BlockDriverState **file);

#endif /* NBD_CLIENT_H */
