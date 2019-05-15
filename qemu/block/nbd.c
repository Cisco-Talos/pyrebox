/*
 * QEMU Block driver for  NBD
 *
 * Copyright (C) 2008 Bull S.A.S.
 *     Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 * Some parts:
 *    Copyright (C) 2007 Anthony Liguori <anthony@codemonkey.ws>
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
#include "nbd-client.h"
#include "block/qdict.h"
#include "qapi/error.h"
#include "qemu/uri.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qapi/qapi-visit-sockets.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/qobject-output-visitor.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/cutils.h"

#define EN_OPTSTR ":exportname="

typedef struct BDRVNBDState {
    NBDClientSession client;

    /* For nbd_refresh_filename() */
    SocketAddress *saddr;
    char *export, *tlscredsid;
} BDRVNBDState;

static int nbd_parse_uri(const char *filename, QDict *options)
{
    URI *uri;
    const char *p;
    QueryParams *qp = NULL;
    int ret = 0;
    bool is_unix;

    uri = uri_parse(filename);
    if (!uri) {
        return -EINVAL;
    }

    /* transport */
    if (!g_strcmp0(uri->scheme, "nbd")) {
        is_unix = false;
    } else if (!g_strcmp0(uri->scheme, "nbd+tcp")) {
        is_unix = false;
    } else if (!g_strcmp0(uri->scheme, "nbd+unix")) {
        is_unix = true;
    } else {
        ret = -EINVAL;
        goto out;
    }

    p = uri->path ? uri->path : "/";
    p += strspn(p, "/");
    if (p[0]) {
        qdict_put_str(options, "export", p);
    }

    qp = query_params_parse(uri->query);
    if (qp->n > 1 || (is_unix && !qp->n) || (!is_unix && qp->n)) {
        ret = -EINVAL;
        goto out;
    }

    if (is_unix) {
        /* nbd+unix:///export?socket=path */
        if (uri->server || uri->port || strcmp(qp->p[0].name, "socket")) {
            ret = -EINVAL;
            goto out;
        }
        qdict_put_str(options, "server.type", "unix");
        qdict_put_str(options, "server.path", qp->p[0].value);
    } else {
        QString *host;
        char *port_str;

        /* nbd[+tcp]://host[:port]/export */
        if (!uri->server) {
            ret = -EINVAL;
            goto out;
        }

        /* strip braces from literal IPv6 address */
        if (uri->server[0] == '[') {
            host = qstring_from_substr(uri->server, 1,
                                       strlen(uri->server) - 1);
        } else {
            host = qstring_from_str(uri->server);
        }

        qdict_put_str(options, "server.type", "inet");
        qdict_put(options, "server.host", host);

        port_str = g_strdup_printf("%d", uri->port ?: NBD_DEFAULT_PORT);
        qdict_put_str(options, "server.port", port_str);
        g_free(port_str);
    }

out:
    if (qp) {
        query_params_free(qp);
    }
    uri_free(uri);
    return ret;
}

static bool nbd_has_filename_options_conflict(QDict *options, Error **errp)
{
    const QDictEntry *e;

    for (e = qdict_first(options); e; e = qdict_next(options, e)) {
        if (!strcmp(e->key, "host") ||
            !strcmp(e->key, "port") ||
            !strcmp(e->key, "path") ||
            !strcmp(e->key, "export") ||
            strstart(e->key, "server.", NULL))
        {
            error_setg(errp, "Option '%s' cannot be used with a file name",
                       e->key);
            return true;
        }
    }

    return false;
}

static void nbd_parse_filename(const char *filename, QDict *options,
                               Error **errp)
{
    char *file;
    char *export_name;
    const char *host_spec;
    const char *unixpath;

    if (nbd_has_filename_options_conflict(options, errp)) {
        return;
    }

    if (strstr(filename, "://")) {
        int ret = nbd_parse_uri(filename, options);
        if (ret < 0) {
            error_setg(errp, "No valid URL specified");
        }
        return;
    }

    file = g_strdup(filename);

    export_name = strstr(file, EN_OPTSTR);
    if (export_name) {
        if (export_name[strlen(EN_OPTSTR)] == 0) {
            goto out;
        }
        export_name[0] = 0; /* truncate 'file' */
        export_name += strlen(EN_OPTSTR);

        qdict_put_str(options, "export", export_name);
    }

    /* extract the host_spec - fail if it's not nbd:... */
    if (!strstart(file, "nbd:", &host_spec)) {
        error_setg(errp, "File name string for NBD must start with 'nbd:'");
        goto out;
    }

    if (!*host_spec) {
        goto out;
    }

    /* are we a UNIX or TCP socket? */
    if (strstart(host_spec, "unix:", &unixpath)) {
        qdict_put_str(options, "server.type", "unix");
        qdict_put_str(options, "server.path", unixpath);
    } else {
        InetSocketAddress *addr = g_new(InetSocketAddress, 1);

        if (inet_parse(addr, host_spec, errp)) {
            goto out_inet;
        }

        qdict_put_str(options, "server.type", "inet");
        qdict_put_str(options, "server.host", addr->host);
        qdict_put_str(options, "server.port", addr->port);
    out_inet:
        qapi_free_InetSocketAddress(addr);
    }

out:
    g_free(file);
}

static bool nbd_process_legacy_socket_options(QDict *output_options,
                                              QemuOpts *legacy_opts,
                                              Error **errp)
{
    const char *path = qemu_opt_get(legacy_opts, "path");
    const char *host = qemu_opt_get(legacy_opts, "host");
    const char *port = qemu_opt_get(legacy_opts, "port");
    const QDictEntry *e;

    if (!path && !host && !port) {
        return true;
    }

    for (e = qdict_first(output_options); e; e = qdict_next(output_options, e))
    {
        if (strstart(e->key, "server.", NULL)) {
            error_setg(errp, "Cannot use 'server' and path/host/port at the "
                       "same time");
            return false;
        }
    }

    if (path && host) {
        error_setg(errp, "path and host may not be used at the same time");
        return false;
    } else if (path) {
        if (port) {
            error_setg(errp, "port may not be used without host");
            return false;
        }

        qdict_put_str(output_options, "server.type", "unix");
        qdict_put_str(output_options, "server.path", path);
    } else if (host) {
        qdict_put_str(output_options, "server.type", "inet");
        qdict_put_str(output_options, "server.host", host);
        qdict_put_str(output_options, "server.port",
                      port ?: stringify(NBD_DEFAULT_PORT));
    }

    return true;
}

static SocketAddress *nbd_config(BDRVNBDState *s, QDict *options,
                                 Error **errp)
{
    SocketAddress *saddr = NULL;
    QDict *addr = NULL;
    Visitor *iv = NULL;
    Error *local_err = NULL;

    qdict_extract_subqdict(options, &addr, "server.");
    if (!qdict_size(addr)) {
        error_setg(errp, "NBD server address missing");
        goto done;
    }

    iv = qobject_input_visitor_new_flat_confused(addr, errp);
    if (!iv) {
        goto done;
    }

    visit_type_SocketAddress(iv, NULL, &saddr, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto done;
    }

done:
    qobject_unref(addr);
    visit_free(iv);
    return saddr;
}

NBDClientSession *nbd_get_client_session(BlockDriverState *bs)
{
    BDRVNBDState *s = bs->opaque;
    return &s->client;
}

static QCryptoTLSCreds *nbd_get_tls_creds(const char *id, Error **errp)
{
    Object *obj;
    QCryptoTLSCreds *creds;

    obj = object_resolve_path_component(
        object_get_objects_root(), id);
    if (!obj) {
        error_setg(errp, "No TLS credentials with id '%s'",
                   id);
        return NULL;
    }
    creds = (QCryptoTLSCreds *)
        object_dynamic_cast(obj, TYPE_QCRYPTO_TLS_CREDS);
    if (!creds) {
        error_setg(errp, "Object with id '%s' is not TLS credentials",
                   id);
        return NULL;
    }

    if (creds->endpoint != QCRYPTO_TLS_CREDS_ENDPOINT_CLIENT) {
        error_setg(errp,
                   "Expecting TLS credentials with a client endpoint");
        return NULL;
    }
    object_ref(obj);
    return creds;
}


static QemuOptsList nbd_runtime_opts = {
    .name = "nbd",
    .head = QTAILQ_HEAD_INITIALIZER(nbd_runtime_opts.head),
    .desc = {
        {
            .name = "host",
            .type = QEMU_OPT_STRING,
            .help = "TCP host to connect to",
        },
        {
            .name = "port",
            .type = QEMU_OPT_STRING,
            .help = "TCP port to connect to",
        },
        {
            .name = "path",
            .type = QEMU_OPT_STRING,
            .help = "Unix socket path to connect to",
        },
        {
            .name = "export",
            .type = QEMU_OPT_STRING,
            .help = "Name of the NBD export to open",
        },
        {
            .name = "tls-creds",
            .type = QEMU_OPT_STRING,
            .help = "ID of the TLS credentials to use",
        },
        {
            .name = "x-dirty-bitmap",
            .type = QEMU_OPT_STRING,
            .help = "experimental: expose named dirty bitmap in place of "
                    "block status",
        },
        { /* end of list */ }
    },
};

static int nbd_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    BDRVNBDState *s = bs->opaque;
    QemuOpts *opts = NULL;
    Error *local_err = NULL;
    QCryptoTLSCreds *tlscreds = NULL;
    const char *hostname = NULL;
    int ret = -EINVAL;

    opts = qemu_opts_create(&nbd_runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto error;
    }

    /* Translate @host, @port, and @path to a SocketAddress */
    if (!nbd_process_legacy_socket_options(options, opts, errp)) {
        goto error;
    }

    /* Pop the config into our state object. Exit if invalid. */
    s->saddr = nbd_config(s, options, errp);
    if (!s->saddr) {
        goto error;
    }

    s->export = g_strdup(qemu_opt_get(opts, "export"));

    s->tlscredsid = g_strdup(qemu_opt_get(opts, "tls-creds"));
    if (s->tlscredsid) {
        tlscreds = nbd_get_tls_creds(s->tlscredsid, errp);
        if (!tlscreds) {
            goto error;
        }

        /* TODO SOCKET_ADDRESS_KIND_FD where fd has AF_INET or AF_INET6 */
        if (s->saddr->type != SOCKET_ADDRESS_TYPE_INET) {
            error_setg(errp, "TLS only supported over IP sockets");
            goto error;
        }
        hostname = s->saddr->u.inet.host;
    }

    /* NBD handshake */
    ret = nbd_client_init(bs, s->saddr, s->export, tlscreds, hostname,
                          qemu_opt_get(opts, "x-dirty-bitmap"), errp);

 error:
    if (tlscreds) {
        object_unref(OBJECT(tlscreds));
    }
    if (ret < 0) {
        qapi_free_SocketAddress(s->saddr);
        g_free(s->export);
        g_free(s->tlscredsid);
    }
    qemu_opts_del(opts);
    return ret;
}

static int nbd_co_flush(BlockDriverState *bs)
{
    return nbd_client_co_flush(bs);
}

static void nbd_refresh_limits(BlockDriverState *bs, Error **errp)
{
    NBDClientSession *s = nbd_get_client_session(bs);
    uint32_t min = s->info.min_block;
    uint32_t max = MIN_NON_ZERO(NBD_MAX_BUFFER_SIZE, s->info.max_block);

    /*
     * If the server did not advertise an alignment:
     * - a size that is not sector-aligned implies that an alignment
     *   of 1 can be used to access those tail bytes
     * - advertisement of block status requires an alignment of 1, so
     *   that we don't violate block layer constraints that block
     *   status is always aligned (as we can't control whether the
     *   server will report sub-sector extents, such as a hole at EOF
     *   on an unaligned POSIX file)
     * - otherwise, assume the server is so old that we are safer avoiding
     *   sub-sector requests
     */
    if (!min) {
        min = (!QEMU_IS_ALIGNED(s->info.size, BDRV_SECTOR_SIZE) ||
               s->info.base_allocation) ? 1 : BDRV_SECTOR_SIZE;
    }

    bs->bl.request_alignment = min;
    bs->bl.max_pdiscard = max;
    bs->bl.max_pwrite_zeroes = max;
    bs->bl.max_transfer = max;

    if (s->info.opt_block &&
        s->info.opt_block > bs->bl.opt_transfer) {
        bs->bl.opt_transfer = s->info.opt_block;
    }
}

static void nbd_close(BlockDriverState *bs)
{
    BDRVNBDState *s = bs->opaque;

    nbd_client_close(bs);

    qapi_free_SocketAddress(s->saddr);
    g_free(s->export);
    g_free(s->tlscredsid);
}

static int64_t nbd_getlength(BlockDriverState *bs)
{
    BDRVNBDState *s = bs->opaque;

    return s->client.info.size;
}

static void nbd_detach_aio_context(BlockDriverState *bs)
{
    nbd_client_detach_aio_context(bs);
}

static void nbd_attach_aio_context(BlockDriverState *bs,
                                   AioContext *new_context)
{
    nbd_client_attach_aio_context(bs, new_context);
}

static void nbd_refresh_filename(BlockDriverState *bs)
{
    BDRVNBDState *s = bs->opaque;
    const char *host = NULL, *port = NULL, *path = NULL;

    if (s->saddr->type == SOCKET_ADDRESS_TYPE_INET) {
        const InetSocketAddress *inet = &s->saddr->u.inet;
        if (!inet->has_ipv4 && !inet->has_ipv6 && !inet->has_to) {
            host = inet->host;
            port = inet->port;
        }
    } else if (s->saddr->type == SOCKET_ADDRESS_TYPE_UNIX) {
        path = s->saddr->u.q_unix.path;
    } /* else can't represent as pseudo-filename */

    if (path && s->export) {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename),
                 "nbd+unix:///%s?socket=%s", s->export, path);
    } else if (path && !s->export) {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename),
                 "nbd+unix://?socket=%s", path);
    } else if (host && s->export) {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename),
                 "nbd://%s:%s/%s", host, port, s->export);
    } else if (host && !s->export) {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename),
                 "nbd://%s:%s", host, port);
    }
}

static char *nbd_dirname(BlockDriverState *bs, Error **errp)
{
    /* The generic bdrv_dirname() implementation is able to work out some
     * directory name for NBD nodes, but that would be wrong. So far there is no
     * specification for how "export paths" would work, so NBD does not have
     * directory names. */
    error_setg(errp, "Cannot generate a base directory for NBD nodes");
    return NULL;
}

static const char *const nbd_strong_runtime_opts[] = {
    "path",
    "host",
    "port",
    "export",
    "tls-creds",
    "server.",

    NULL
};

static BlockDriver bdrv_nbd = {
    .format_name                = "nbd",
    .protocol_name              = "nbd",
    .instance_size              = sizeof(BDRVNBDState),
    .bdrv_parse_filename        = nbd_parse_filename,
    .bdrv_file_open             = nbd_open,
    .bdrv_co_preadv             = nbd_client_co_preadv,
    .bdrv_co_pwritev            = nbd_client_co_pwritev,
    .bdrv_co_pwrite_zeroes      = nbd_client_co_pwrite_zeroes,
    .bdrv_close                 = nbd_close,
    .bdrv_co_flush_to_os        = nbd_co_flush,
    .bdrv_co_pdiscard           = nbd_client_co_pdiscard,
    .bdrv_refresh_limits        = nbd_refresh_limits,
    .bdrv_getlength             = nbd_getlength,
    .bdrv_detach_aio_context    = nbd_detach_aio_context,
    .bdrv_attach_aio_context    = nbd_attach_aio_context,
    .bdrv_refresh_filename      = nbd_refresh_filename,
    .bdrv_co_block_status       = nbd_client_co_block_status,
    .bdrv_dirname               = nbd_dirname,
    .strong_runtime_opts        = nbd_strong_runtime_opts,
};

static BlockDriver bdrv_nbd_tcp = {
    .format_name                = "nbd",
    .protocol_name              = "nbd+tcp",
    .instance_size              = sizeof(BDRVNBDState),
    .bdrv_parse_filename        = nbd_parse_filename,
    .bdrv_file_open             = nbd_open,
    .bdrv_co_preadv             = nbd_client_co_preadv,
    .bdrv_co_pwritev            = nbd_client_co_pwritev,
    .bdrv_co_pwrite_zeroes      = nbd_client_co_pwrite_zeroes,
    .bdrv_close                 = nbd_close,
    .bdrv_co_flush_to_os        = nbd_co_flush,
    .bdrv_co_pdiscard           = nbd_client_co_pdiscard,
    .bdrv_refresh_limits        = nbd_refresh_limits,
    .bdrv_getlength             = nbd_getlength,
    .bdrv_detach_aio_context    = nbd_detach_aio_context,
    .bdrv_attach_aio_context    = nbd_attach_aio_context,
    .bdrv_refresh_filename      = nbd_refresh_filename,
    .bdrv_co_block_status       = nbd_client_co_block_status,
    .bdrv_dirname               = nbd_dirname,
    .strong_runtime_opts        = nbd_strong_runtime_opts,
};

static BlockDriver bdrv_nbd_unix = {
    .format_name                = "nbd",
    .protocol_name              = "nbd+unix",
    .instance_size              = sizeof(BDRVNBDState),
    .bdrv_parse_filename        = nbd_parse_filename,
    .bdrv_file_open             = nbd_open,
    .bdrv_co_preadv             = nbd_client_co_preadv,
    .bdrv_co_pwritev            = nbd_client_co_pwritev,
    .bdrv_co_pwrite_zeroes      = nbd_client_co_pwrite_zeroes,
    .bdrv_close                 = nbd_close,
    .bdrv_co_flush_to_os        = nbd_co_flush,
    .bdrv_co_pdiscard           = nbd_client_co_pdiscard,
    .bdrv_refresh_limits        = nbd_refresh_limits,
    .bdrv_getlength             = nbd_getlength,
    .bdrv_detach_aio_context    = nbd_detach_aio_context,
    .bdrv_attach_aio_context    = nbd_attach_aio_context,
    .bdrv_refresh_filename      = nbd_refresh_filename,
    .bdrv_co_block_status       = nbd_client_co_block_status,
    .bdrv_dirname               = nbd_dirname,
    .strong_runtime_opts        = nbd_strong_runtime_opts,
};

static void bdrv_nbd_init(void)
{
    bdrv_register(&bdrv_nbd);
    bdrv_register(&bdrv_nbd_tcp);
    bdrv_register(&bdrv_nbd_unix);
}

block_init(bdrv_nbd_init);
