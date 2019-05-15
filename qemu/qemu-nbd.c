/*
 *  Copyright (C) 2005  Anthony Liguori <anthony@codemonkey.ws>
 *
 *  Network Block Device
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include <getopt.h>
#include <libgen.h>
#include <pthread.h>

#include "qapi/error.h"
#include "qemu/cutils.h"
#include "sysemu/block-backend.h"
#include "block/block_int.h"
#include "block/nbd.h"
#include "qemu/main-loop.h"
#include "qemu/option.h"
#include "qemu/error-report.h"
#include "qemu/config-file.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/systemd.h"
#include "block/snapshot.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qom/object_interfaces.h"
#include "io/channel-socket.h"
#include "io/net-listener.h"
#include "crypto/init.h"
#include "trace/control.h"
#include "qemu-version.h"

#ifdef __linux__
#define HAVE_NBD_DEVICE 1
#else
#define HAVE_NBD_DEVICE 0
#endif

#define SOCKET_PATH                "/var/lock/qemu-nbd-%s"
#define QEMU_NBD_OPT_CACHE         256
#define QEMU_NBD_OPT_AIO           257
#define QEMU_NBD_OPT_DISCARD       258
#define QEMU_NBD_OPT_DETECT_ZEROES 259
#define QEMU_NBD_OPT_OBJECT        260
#define QEMU_NBD_OPT_TLSCREDS      261
#define QEMU_NBD_OPT_IMAGE_OPTS    262
#define QEMU_NBD_OPT_FORK          263
#define QEMU_NBD_OPT_TLSAUTHZ      264

#define MBR_SIZE 512

static NBDExport *export;
static int verbose;
static char *srcpath;
static SocketAddress *saddr;
static int persistent = 0;
static enum { RUNNING, TERMINATE, TERMINATING, TERMINATED } state;
static int shared = 1;
static int nb_fds;
static QIONetListener *server;
static QCryptoTLSCreds *tlscreds;
static const char *tlsauthz;

static void usage(const char *name)
{
    (printf) (
"Usage: %s [OPTIONS] FILE\n"
"  or:  %s -L [OPTIONS]\n"
"QEMU Disk Network Block Device Utility\n"
"\n"
"  -h, --help                display this help and exit\n"
"  -V, --version             output version information and exit\n"
"\n"
"Connection properties:\n"
"  -p, --port=PORT           port to listen on (default `%d')\n"
"  -b, --bind=IFACE          interface to bind to (default `0.0.0.0')\n"
"  -k, --socket=PATH         path to the unix socket\n"
"                            (default '"SOCKET_PATH"')\n"
"  -e, --shared=NUM          device can be shared by NUM clients (default '1')\n"
"  -t, --persistent          don't exit on the last connection\n"
"  -v, --verbose             display extra debugging information\n"
"  -x, --export-name=NAME    expose export by name (default is empty string)\n"
"  -D, --description=TEXT    export a human-readable description\n"
"\n"
"Exposing part of the image:\n"
"  -o, --offset=OFFSET       offset into the image\n"
"  -P, --partition=NUM       only expose partition NUM\n"
"  -B, --bitmap=NAME         expose a persistent dirty bitmap\n"
"\n"
"General purpose options:\n"
"  -L, --list                list exports available from another NBD server\n"
"  --object type,id=ID,...   define an object such as 'secret' for providing\n"
"                            passwords and/or encryption keys\n"
"  --tls-creds=ID            use id of an earlier --object to provide TLS\n"
"  --tls-authz=ID            use id of an earlier --object to provide\n"
"                            authorization\n"
"  -T, --trace [[enable=]<pattern>][,events=<file>][,file=<file>]\n"
"                            specify tracing options\n"
"  --fork                    fork off the server process and exit the parent\n"
"                            once the server is running\n"
#if HAVE_NBD_DEVICE
"\n"
"Kernel NBD client support:\n"
"  -c, --connect=DEV         connect FILE to the local NBD device DEV\n"
"  -d, --disconnect          disconnect the specified device\n"
#endif
"\n"
"Block device options:\n"
"  -f, --format=FORMAT       set image format (raw, qcow2, ...)\n"
"  -r, --read-only           export read-only\n"
"  -s, --snapshot            use FILE as an external snapshot, create a temporary\n"
"                            file with backing_file=FILE, redirect the write to\n"
"                            the temporary one\n"
"  -l, --load-snapshot=SNAPSHOT_PARAM\n"
"                            load an internal snapshot inside FILE and export it\n"
"                            as an read-only device, SNAPSHOT_PARAM format is\n"
"                            'snapshot.id=[ID],snapshot.name=[NAME]', or\n"
"                            '[ID_OR_NAME]'\n"
"  -n, --nocache             disable host cache\n"
"      --cache=MODE          set cache mode (none, writeback, ...)\n"
"      --aio=MODE            set AIO mode (native or threads)\n"
"      --discard=MODE        set discard mode (ignore, unmap)\n"
"      --detect-zeroes=MODE  set detect-zeroes mode (off, on, unmap)\n"
"      --image-opts          treat FILE as a full set of image options\n"
"\n"
QEMU_HELP_BOTTOM "\n"
    , name, name, NBD_DEFAULT_PORT, "DEVICE");
}

static void version(const char *name)
{
    printf(
"%s " QEMU_FULL_VERSION "\n"
"Written by Anthony Liguori.\n"
"\n"
QEMU_COPYRIGHT "\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
    , name);
}

struct partition_record
{
    uint8_t bootable;
    uint8_t start_head;
    uint32_t start_cylinder;
    uint8_t start_sector;
    uint8_t system;
    uint8_t end_head;
    uint8_t end_cylinder;
    uint8_t end_sector;
    uint32_t start_sector_abs;
    uint32_t nb_sectors_abs;
};

static void read_partition(uint8_t *p, struct partition_record *r)
{
    r->bootable = p[0];
    r->start_head = p[1];
    r->start_cylinder = p[3] | ((p[2] << 2) & 0x0300);
    r->start_sector = p[2] & 0x3f;
    r->system = p[4];
    r->end_head = p[5];
    r->end_cylinder = p[7] | ((p[6] << 2) & 0x300);
    r->end_sector = p[6] & 0x3f;

    r->start_sector_abs = ldl_le_p(p + 8);
    r->nb_sectors_abs   = ldl_le_p(p + 12);
}

static int find_partition(BlockBackend *blk, int partition,
                          uint64_t *offset, uint64_t *size)
{
    struct partition_record mbr[4];
    uint8_t data[MBR_SIZE];
    int i;
    int ext_partnum = 4;
    int ret;

    ret = blk_pread(blk, 0, data, sizeof(data));
    if (ret < 0) {
        error_report("error while reading: %s", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    if (data[510] != 0x55 || data[511] != 0xaa) {
        return -EINVAL;
    }

    for (i = 0; i < 4; i++) {
        read_partition(&data[446 + 16 * i], &mbr[i]);

        if (!mbr[i].system || !mbr[i].nb_sectors_abs) {
            continue;
        }

        if (mbr[i].system == 0xF || mbr[i].system == 0x5) {
            struct partition_record ext[4];
            uint8_t data1[MBR_SIZE];
            int j;

            ret = blk_pread(blk, mbr[i].start_sector_abs * MBR_SIZE,
                            data1, sizeof(data1));
            if (ret < 0) {
                error_report("error while reading: %s", strerror(-ret));
                exit(EXIT_FAILURE);
            }

            for (j = 0; j < 4; j++) {
                read_partition(&data1[446 + 16 * j], &ext[j]);
                if (!ext[j].system || !ext[j].nb_sectors_abs) {
                    continue;
                }

                if ((ext_partnum + j + 1) == partition) {
                    *offset = (uint64_t)ext[j].start_sector_abs << 9;
                    *size = (uint64_t)ext[j].nb_sectors_abs << 9;
                    return 0;
                }
            }
            ext_partnum += 4;
        } else if ((i + 1) == partition) {
            *offset = (uint64_t)mbr[i].start_sector_abs << 9;
            *size = (uint64_t)mbr[i].nb_sectors_abs << 9;
            return 0;
        }
    }

    return -ENOENT;
}

static void termsig_handler(int signum)
{
    atomic_cmpxchg(&state, RUNNING, TERMINATE);
    qemu_notify_event();
}


static int qemu_nbd_client_list(SocketAddress *saddr, QCryptoTLSCreds *tls,
                                const char *hostname)
{
    int ret = EXIT_FAILURE;
    int rc;
    Error *err = NULL;
    QIOChannelSocket *sioc;
    NBDExportInfo *list;
    int i, j;

    sioc = qio_channel_socket_new();
    if (qio_channel_socket_connect_sync(sioc, saddr, &err) < 0) {
        error_report_err(err);
        return EXIT_FAILURE;
    }
    rc = nbd_receive_export_list(QIO_CHANNEL(sioc), tls, hostname, &list,
                                 &err);
    if (rc < 0) {
        if (err) {
            error_report_err(err);
        }
        goto out;
    }
    printf("exports available: %d\n", rc);
    for (i = 0; i < rc; i++) {
        printf(" export: '%s'\n", list[i].name);
        if (list[i].description && *list[i].description) {
            printf("  description: %s\n", list[i].description);
        }
        if (list[i].flags & NBD_FLAG_HAS_FLAGS) {
            printf("  size:  %" PRIu64 "\n", list[i].size);
            printf("  flags: 0x%x (", list[i].flags);
            if (list[i].flags & NBD_FLAG_READ_ONLY) {
                printf(" readonly");
            }
            if (list[i].flags & NBD_FLAG_SEND_FLUSH) {
                printf(" flush");
            }
            if (list[i].flags & NBD_FLAG_SEND_FUA) {
                printf(" fua");
            }
            if (list[i].flags & NBD_FLAG_ROTATIONAL) {
                printf(" rotational");
            }
            if (list[i].flags & NBD_FLAG_SEND_TRIM) {
                printf(" trim");
            }
            if (list[i].flags & NBD_FLAG_SEND_WRITE_ZEROES) {
                printf(" zeroes");
            }
            if (list[i].flags & NBD_FLAG_SEND_DF) {
                printf(" df");
            }
            if (list[i].flags & NBD_FLAG_CAN_MULTI_CONN) {
                printf(" multi");
            }
            if (list[i].flags & NBD_FLAG_SEND_RESIZE) {
                printf(" resize");
            }
            if (list[i].flags & NBD_FLAG_SEND_CACHE) {
                printf(" cache");
            }
            printf(" )\n");
        }
        if (list[i].min_block) {
            printf("  min block: %u\n", list[i].min_block);
            printf("  opt block: %u\n", list[i].opt_block);
            printf("  max block: %u\n", list[i].max_block);
        }
        if (list[i].n_contexts) {
            printf("  available meta contexts: %d\n", list[i].n_contexts);
            for (j = 0; j < list[i].n_contexts; j++) {
                printf("   %s\n", list[i].contexts[j]);
            }
        }
    }
    nbd_free_export_list(list, rc);

    ret = EXIT_SUCCESS;
 out:
    object_unref(OBJECT(sioc));
    return ret;
}


#if HAVE_NBD_DEVICE
static void *show_parts(void *arg)
{
    char *device = arg;
    int nbd;

    /* linux just needs an open() to trigger
     * the partition table update
     * but remember to load the module with max_part != 0 :
     *     modprobe nbd max_part=63
     */
    nbd = open(device, O_RDWR);
    if (nbd >= 0) {
        close(nbd);
    }
    return NULL;
}

static void *nbd_client_thread(void *arg)
{
    char *device = arg;
    NBDExportInfo info = { .request_sizes = false, .name = g_strdup("") };
    QIOChannelSocket *sioc;
    int fd;
    int ret;
    pthread_t show_parts_thread;
    Error *local_error = NULL;

    sioc = qio_channel_socket_new();
    if (qio_channel_socket_connect_sync(sioc,
                                        saddr,
                                        &local_error) < 0) {
        error_report_err(local_error);
        goto out;
    }

    ret = nbd_receive_negotiate(QIO_CHANNEL(sioc),
                                NULL, NULL, NULL, &info, &local_error);
    if (ret < 0) {
        if (local_error) {
            error_report_err(local_error);
        }
        goto out_socket;
    }

    fd = open(device, O_RDWR);
    if (fd < 0) {
        /* Linux-only, we can use %m in printf.  */
        error_report("Failed to open %s: %m", device);
        goto out_socket;
    }

    ret = nbd_init(fd, sioc, &info, &local_error);
    if (ret < 0) {
        error_report_err(local_error);
        goto out_fd;
    }

    /* update partition table */
    pthread_create(&show_parts_thread, NULL, show_parts, device);

    if (verbose) {
        fprintf(stderr, "NBD device %s is now connected to %s\n",
                device, srcpath);
    } else {
        /* Close stderr so that the qemu-nbd process exits.  */
        dup2(STDOUT_FILENO, STDERR_FILENO);
    }

    ret = nbd_client(fd);
    if (ret) {
        goto out_fd;
    }
    close(fd);
    object_unref(OBJECT(sioc));
    g_free(info.name);
    kill(getpid(), SIGTERM);
    return (void *) EXIT_SUCCESS;

out_fd:
    close(fd);
out_socket:
    object_unref(OBJECT(sioc));
out:
    g_free(info.name);
    kill(getpid(), SIGTERM);
    return (void *) EXIT_FAILURE;
}
#endif /* HAVE_NBD_DEVICE */

static int nbd_can_accept(void)
{
    return state == RUNNING && nb_fds < shared;
}

static void nbd_export_closed(NBDExport *export)
{
    assert(state == TERMINATING);
    state = TERMINATED;
}

static void nbd_update_server_watch(void);

static void nbd_client_closed(NBDClient *client, bool negotiated)
{
    nb_fds--;
    if (negotiated && nb_fds == 0 && !persistent && state == RUNNING) {
        state = TERMINATE;
    }
    nbd_update_server_watch();
    nbd_client_put(client);
}

static void nbd_accept(QIONetListener *listener, QIOChannelSocket *cioc,
                       gpointer opaque)
{
    if (state >= TERMINATE) {
        return;
    }

    nb_fds++;
    nbd_update_server_watch();
    nbd_client_new(cioc, tlscreds, tlsauthz, nbd_client_closed);
}

static void nbd_update_server_watch(void)
{
    if (nbd_can_accept()) {
        qio_net_listener_set_client_func(server, nbd_accept, NULL, NULL);
    } else {
        qio_net_listener_set_client_func(server, NULL, NULL, NULL);
    }
}


static SocketAddress *nbd_build_socket_address(const char *sockpath,
                                               const char *bindto,
                                               const char *port)
{
    SocketAddress *saddr;

    saddr = g_new0(SocketAddress, 1);
    if (sockpath) {
        saddr->type = SOCKET_ADDRESS_TYPE_UNIX;
        saddr->u.q_unix.path = g_strdup(sockpath);
    } else {
        InetSocketAddress *inet;
        saddr->type = SOCKET_ADDRESS_TYPE_INET;
        inet = &saddr->u.inet;
        inet->host = g_strdup(bindto);
        if (port) {
            inet->port = g_strdup(port);
        } else  {
            inet->port = g_strdup_printf("%d", NBD_DEFAULT_PORT);
        }
    }

    return saddr;
}


static QemuOptsList file_opts = {
    .name = "file",
    .implied_opt_name = "file",
    .head = QTAILQ_HEAD_INITIALIZER(file_opts.head),
    .desc = {
        /* no elements => accept any params */
        { /* end of list */ }
    },
};

static QemuOptsList qemu_object_opts = {
    .name = "object",
    .implied_opt_name = "qom-type",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_object_opts.head),
    .desc = {
        { }
    },
};



static QCryptoTLSCreds *nbd_get_tls_creds(const char *id, bool list,
                                          Error **errp)
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

    if (list) {
        if (creds->endpoint != QCRYPTO_TLS_CREDS_ENDPOINT_CLIENT) {
            error_setg(errp,
                       "Expecting TLS credentials with a client endpoint");
            return NULL;
        }
    } else {
        if (creds->endpoint != QCRYPTO_TLS_CREDS_ENDPOINT_SERVER) {
            error_setg(errp,
                       "Expecting TLS credentials with a server endpoint");
            return NULL;
        }
    }
    object_ref(obj);
    return creds;
}

static void setup_address_and_port(const char **address, const char **port)
{
    if (*address == NULL) {
        *address = "0.0.0.0";
    }

    if (*port == NULL) {
        *port = stringify(NBD_DEFAULT_PORT);
    }
}

/*
 * Check socket parameters compatibility when socket activation is used.
 */
static const char *socket_activation_validate_opts(const char *device,
                                                   const char *sockpath,
                                                   const char *address,
                                                   const char *port,
                                                   bool list)
{
    if (device != NULL) {
        return "NBD device can't be set when using socket activation";
    }

    if (sockpath != NULL) {
        return "Unix socket can't be set when using socket activation";
    }

    if (address != NULL) {
        return "The interface can't be set when using socket activation";
    }

    if (port != NULL) {
        return "TCP port number can't be set when using socket activation";
    }

    if (list) {
        return "List mode is incompatible with socket activation";
    }

    return NULL;
}

static void qemu_nbd_shutdown(void)
{
    job_cancel_sync_all();
    bdrv_close_all();
}

int main(int argc, char **argv)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    uint64_t dev_offset = 0;
    uint16_t nbdflags = 0;
    bool disconnect = false;
    const char *bindto = NULL;
    const char *port = NULL;
    char *sockpath = NULL;
    char *device = NULL;
    int64_t fd_size;
    QemuOpts *sn_opts = NULL;
    const char *sn_id_or_name = NULL;
    const char *sopt = "hVb:o:p:rsnP:c:dvk:e:f:tl:x:T:D:B:L";
    struct option lopt[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { "bind", required_argument, NULL, 'b' },
        { "port", required_argument, NULL, 'p' },
        { "socket", required_argument, NULL, 'k' },
        { "offset", required_argument, NULL, 'o' },
        { "read-only", no_argument, NULL, 'r' },
        { "partition", required_argument, NULL, 'P' },
        { "bitmap", required_argument, NULL, 'B' },
        { "connect", required_argument, NULL, 'c' },
        { "disconnect", no_argument, NULL, 'd' },
        { "list", no_argument, NULL, 'L' },
        { "snapshot", no_argument, NULL, 's' },
        { "load-snapshot", required_argument, NULL, 'l' },
        { "nocache", no_argument, NULL, 'n' },
        { "cache", required_argument, NULL, QEMU_NBD_OPT_CACHE },
        { "aio", required_argument, NULL, QEMU_NBD_OPT_AIO },
        { "discard", required_argument, NULL, QEMU_NBD_OPT_DISCARD },
        { "detect-zeroes", required_argument, NULL,
          QEMU_NBD_OPT_DETECT_ZEROES },
        { "shared", required_argument, NULL, 'e' },
        { "format", required_argument, NULL, 'f' },
        { "persistent", no_argument, NULL, 't' },
        { "verbose", no_argument, NULL, 'v' },
        { "object", required_argument, NULL, QEMU_NBD_OPT_OBJECT },
        { "export-name", required_argument, NULL, 'x' },
        { "description", required_argument, NULL, 'D' },
        { "tls-creds", required_argument, NULL, QEMU_NBD_OPT_TLSCREDS },
        { "tls-authz", required_argument, NULL, QEMU_NBD_OPT_TLSAUTHZ },
        { "image-opts", no_argument, NULL, QEMU_NBD_OPT_IMAGE_OPTS },
        { "trace", required_argument, NULL, 'T' },
        { "fork", no_argument, NULL, QEMU_NBD_OPT_FORK },
        { NULL, 0, NULL, 0 }
    };
    int ch;
    int opt_ind = 0;
    int flags = BDRV_O_RDWR;
    int partition = 0;
    int ret = 0;
    bool seen_cache = false;
    bool seen_discard = false;
    bool seen_aio = false;
    pthread_t client_thread;
    const char *fmt = NULL;
    Error *local_err = NULL;
    BlockdevDetectZeroesOptions detect_zeroes = BLOCKDEV_DETECT_ZEROES_OPTIONS_OFF;
    QDict *options = NULL;
    const char *export_name = NULL; /* defaults to "" later for server mode */
    const char *export_description = NULL;
    const char *bitmap = NULL;
    const char *tlscredsid = NULL;
    bool imageOpts = false;
    bool writethrough = true;
    char *trace_file = NULL;
    bool fork_process = false;
    bool list = false;
    int old_stderr = -1;
    unsigned socket_activation;

    /* The client thread uses SIGTERM to interrupt the server.  A signal
     * handler ensures that "qemu-nbd -v -c" exits with a nice status code.
     */
    struct sigaction sa_sigterm;
    memset(&sa_sigterm, 0, sizeof(sa_sigterm));
    sa_sigterm.sa_handler = termsig_handler;
    sigaction(SIGTERM, &sa_sigterm, NULL);

#ifdef CONFIG_POSIX
    signal(SIGPIPE, SIG_IGN);
#endif

    module_call_init(MODULE_INIT_TRACE);
    error_set_progname(argv[0]);
    qcrypto_init(&error_fatal);

    module_call_init(MODULE_INIT_QOM);
    qemu_add_opts(&qemu_object_opts);
    qemu_add_opts(&qemu_trace_opts);
    qemu_init_exec_dir(argv[0]);

    while ((ch = getopt_long(argc, argv, sopt, lopt, &opt_ind)) != -1) {
        switch (ch) {
        case 's':
            flags |= BDRV_O_SNAPSHOT;
            break;
        case 'n':
            optarg = (char *) "none";
            /* fallthrough */
        case QEMU_NBD_OPT_CACHE:
            if (seen_cache) {
                error_report("-n and --cache can only be specified once");
                exit(EXIT_FAILURE);
            }
            seen_cache = true;
            if (bdrv_parse_cache_mode(optarg, &flags, &writethrough) == -1) {
                error_report("Invalid cache mode `%s'", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case QEMU_NBD_OPT_AIO:
            if (seen_aio) {
                error_report("--aio can only be specified once");
                exit(EXIT_FAILURE);
            }
            seen_aio = true;
            if (!strcmp(optarg, "native")) {
                flags |= BDRV_O_NATIVE_AIO;
            } else if (!strcmp(optarg, "threads")) {
                /* this is the default */
            } else {
               error_report("invalid aio mode `%s'", optarg);
               exit(EXIT_FAILURE);
            }
            break;
        case QEMU_NBD_OPT_DISCARD:
            if (seen_discard) {
                error_report("--discard can only be specified once");
                exit(EXIT_FAILURE);
            }
            seen_discard = true;
            if (bdrv_parse_discard_flags(optarg, &flags) == -1) {
                error_report("Invalid discard mode `%s'", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case QEMU_NBD_OPT_DETECT_ZEROES:
            detect_zeroes =
                qapi_enum_parse(&BlockdevDetectZeroesOptions_lookup,
                                optarg,
                                BLOCKDEV_DETECT_ZEROES_OPTIONS_OFF,
                                &local_err);
            if (local_err) {
                error_reportf_err(local_err,
                                  "Failed to parse detect_zeroes mode: ");
                exit(EXIT_FAILURE);
            }
            if (detect_zeroes == BLOCKDEV_DETECT_ZEROES_OPTIONS_UNMAP &&
                !(flags & BDRV_O_UNMAP)) {
                error_report("setting detect-zeroes to unmap is not allowed "
                             "without setting discard operation to unmap");
                exit(EXIT_FAILURE);
            }
            break;
        case 'b':
            bindto = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'o':
            if (qemu_strtou64(optarg, NULL, 0, &dev_offset) < 0) {
                error_report("Invalid offset '%s'", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'l':
            if (strstart(optarg, SNAPSHOT_OPT_BASE, NULL)) {
                sn_opts = qemu_opts_parse_noisily(&internal_snapshot_opts,
                                                  optarg, false);
                if (!sn_opts) {
                    error_report("Failed in parsing snapshot param `%s'",
                                 optarg);
                    exit(EXIT_FAILURE);
                }
            } else {
                sn_id_or_name = optarg;
            }
            /* fall through */
        case 'r':
            nbdflags |= NBD_FLAG_READ_ONLY;
            flags &= ~BDRV_O_RDWR;
            break;
        case 'P':
            warn_report("The '-P' option is deprecated; use --image-opts with "
                        "a raw device wrapper for subset exports instead");
            if (qemu_strtoi(optarg, NULL, 0, &partition) < 0 ||
                partition < 1 || partition > 8) {
                error_report("Invalid partition '%s'", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'B':
            bitmap = optarg;
            break;
        case 'k':
            sockpath = optarg;
            if (sockpath[0] != '/') {
                error_report("socket path must be absolute");
                exit(EXIT_FAILURE);
            }
            break;
        case 'd':
            disconnect = true;
            break;
        case 'c':
            device = optarg;
            break;
        case 'e':
            if (qemu_strtoi(optarg, NULL, 0, &shared) < 0 ||
                shared < 1) {
                error_report("Invalid shared device number '%s'", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'f':
            fmt = optarg;
            break;
        case 't':
            persistent = 1;
            break;
        case 'x':
            export_name = optarg;
            break;
        case 'D':
            export_description = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'V':
            version(argv[0]);
            exit(0);
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
            break;
        case '?':
            error_report("Try `%s --help' for more information.", argv[0]);
            exit(EXIT_FAILURE);
        case QEMU_NBD_OPT_OBJECT: {
            QemuOpts *opts;
            opts = qemu_opts_parse_noisily(&qemu_object_opts,
                                           optarg, true);
            if (!opts) {
                exit(EXIT_FAILURE);
            }
        }   break;
        case QEMU_NBD_OPT_TLSCREDS:
            tlscredsid = optarg;
            break;
        case QEMU_NBD_OPT_IMAGE_OPTS:
            imageOpts = true;
            break;
        case 'T':
            g_free(trace_file);
            trace_file = trace_opt_parse(optarg);
            break;
        case QEMU_NBD_OPT_TLSAUTHZ:
            tlsauthz = optarg;
            break;
        case QEMU_NBD_OPT_FORK:
            fork_process = true;
            break;
        case 'L':
            list = true;
            break;
        }
    }

    if (list) {
        if (argc != optind) {
            error_report("List mode is incompatible with a file name");
            exit(EXIT_FAILURE);
        }
        if (export_name || export_description || dev_offset || partition ||
            device || disconnect || fmt || sn_id_or_name || bitmap ||
            seen_aio || seen_discard || seen_cache) {
            error_report("List mode is incompatible with per-device settings");
            exit(EXIT_FAILURE);
        }
        if (fork_process) {
            error_report("List mode is incompatible with forking");
            exit(EXIT_FAILURE);
        }
    } else if ((argc - optind) != 1) {
        error_report("Invalid number of arguments");
        error_printf("Try `%s --help' for more information.\n", argv[0]);
        exit(EXIT_FAILURE);
    } else if (!export_name) {
        export_name = "";
    }

    qemu_opts_foreach(&qemu_object_opts,
                      user_creatable_add_opts_foreach,
                      NULL, &error_fatal);

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file(trace_file);
    qemu_set_log(LOG_TRACE);

    socket_activation = check_socket_activation();
    if (socket_activation == 0) {
        setup_address_and_port(&bindto, &port);
    } else {
        /* Using socket activation - check user didn't use -p etc. */
        const char *err_msg = socket_activation_validate_opts(device, sockpath,
                                                              bindto, port,
                                                              list);
        if (err_msg != NULL) {
            error_report("%s", err_msg);
            exit(EXIT_FAILURE);
        }

        /* qemu-nbd can only listen on a single socket.  */
        if (socket_activation > 1) {
            error_report("qemu-nbd does not support socket activation with %s > 1",
                         "LISTEN_FDS");
            exit(EXIT_FAILURE);
        }
    }

    if (tlscredsid) {
        if (sockpath) {
            error_report("TLS is only supported with IPv4/IPv6");
            exit(EXIT_FAILURE);
        }
        if (device) {
            error_report("TLS is not supported with a host device");
            exit(EXIT_FAILURE);
        }
        if (tlsauthz && list) {
            error_report("TLS authorization is incompatible with export list");
            exit(EXIT_FAILURE);
        }
        tlscreds = nbd_get_tls_creds(tlscredsid, list, &local_err);
        if (local_err) {
            error_report("Failed to get TLS creds %s",
                         error_get_pretty(local_err));
            exit(EXIT_FAILURE);
        }
    } else {
        if (tlsauthz) {
            error_report("--tls-authz is not permitted without --tls-creds");
            exit(EXIT_FAILURE);
        }
    }

    if (list) {
        saddr = nbd_build_socket_address(sockpath, bindto, port);
        return qemu_nbd_client_list(saddr, tlscreds, bindto);
    }

#if !HAVE_NBD_DEVICE
    if (disconnect || device) {
        error_report("Kernel /dev/nbdN support not available");
        exit(EXIT_FAILURE);
    }
#else /* HAVE_NBD_DEVICE */
    if (disconnect) {
        int nbdfd = open(argv[optind], O_RDWR);
        if (nbdfd < 0) {
            error_report("Cannot open %s: %s", argv[optind],
                         strerror(errno));
            exit(EXIT_FAILURE);
        }
        nbd_disconnect(nbdfd);

        close(nbdfd);

        printf("%s disconnected\n", argv[optind]);

        return 0;
    }
#endif

    if ((device && !verbose) || fork_process) {
        int stderr_fd[2];
        pid_t pid;
        int ret;

        if (qemu_pipe(stderr_fd) < 0) {
            error_report("Error setting up communication pipe: %s",
                         strerror(errno));
            exit(EXIT_FAILURE);
        }

        /* Now daemonize, but keep a communication channel open to
         * print errors and exit with the proper status code.
         */
        pid = fork();
        if (pid < 0) {
            error_report("Failed to fork: %s", strerror(errno));
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            close(stderr_fd[0]);
            ret = qemu_daemon(1, 0);

            /* Temporarily redirect stderr to the parent's pipe...  */
            old_stderr = dup(STDERR_FILENO);
            dup2(stderr_fd[1], STDERR_FILENO);
            if (ret < 0) {
                error_report("Failed to daemonize: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            /* ... close the descriptor we inherited and go on.  */
            close(stderr_fd[1]);
        } else {
            bool errors = false;
            char *buf;

            /* In the parent.  Print error messages from the child until
             * it closes the pipe.
             */
            close(stderr_fd[1]);
            buf = g_malloc(1024);
            while ((ret = read(stderr_fd[0], buf, 1024)) > 0) {
                errors = true;
                ret = qemu_write_full(STDERR_FILENO, buf, ret);
                if (ret < 0) {
                    exit(EXIT_FAILURE);
                }
            }
            if (ret < 0) {
                error_report("Cannot read from daemon: %s",
                             strerror(errno));
                exit(EXIT_FAILURE);
            }

            /* Usually the daemon should not print any message.
             * Exit with zero status in that case.
             */
            exit(errors);
        }
    }

    if (device != NULL && sockpath == NULL) {
        sockpath = g_malloc(128);
        snprintf(sockpath, 128, SOCKET_PATH, basename(device));
    }

    server = qio_net_listener_new();
    if (socket_activation == 0) {
        saddr = nbd_build_socket_address(sockpath, bindto, port);
        if (qio_net_listener_open_sync(server, saddr, &local_err) < 0) {
            object_unref(OBJECT(server));
            error_report_err(local_err);
            exit(EXIT_FAILURE);
        }
    } else {
        size_t i;
        /* See comment in check_socket_activation above. */
        for (i = 0; i < socket_activation; i++) {
            QIOChannelSocket *sioc;
            sioc = qio_channel_socket_new_fd(FIRST_SOCKET_ACTIVATION_FD + i,
                                             &local_err);
            if (sioc == NULL) {
                object_unref(OBJECT(server));
                error_report("Failed to use socket activation: %s",
                             error_get_pretty(local_err));
                exit(EXIT_FAILURE);
            }
            qio_net_listener_add(server, sioc);
            object_unref(OBJECT(sioc));
        }
    }

    if (qemu_init_main_loop(&local_err)) {
        error_report_err(local_err);
        exit(EXIT_FAILURE);
    }
    bdrv_init();
    atexit(qemu_nbd_shutdown);

    srcpath = argv[optind];
    if (imageOpts) {
        QemuOpts *opts;
        if (fmt) {
            error_report("--image-opts and -f are mutually exclusive");
            exit(EXIT_FAILURE);
        }
        opts = qemu_opts_parse_noisily(&file_opts, srcpath, true);
        if (!opts) {
            qemu_opts_reset(&file_opts);
            exit(EXIT_FAILURE);
        }
        options = qemu_opts_to_qdict(opts, NULL);
        qemu_opts_reset(&file_opts);
        blk = blk_new_open(NULL, NULL, options, flags, &local_err);
    } else {
        if (fmt) {
            options = qdict_new();
            qdict_put_str(options, "driver", fmt);
        }
        blk = blk_new_open(srcpath, NULL, options, flags, &local_err);
    }

    if (!blk) {
        error_reportf_err(local_err, "Failed to blk_new_open '%s': ",
                          argv[optind]);
        exit(EXIT_FAILURE);
    }
    bs = blk_bs(blk);

    blk_set_enable_write_cache(blk, !writethrough);

    if (sn_opts) {
        ret = bdrv_snapshot_load_tmp(bs,
                                     qemu_opt_get(sn_opts, SNAPSHOT_OPT_ID),
                                     qemu_opt_get(sn_opts, SNAPSHOT_OPT_NAME),
                                     &local_err);
    } else if (sn_id_or_name) {
        ret = bdrv_snapshot_load_tmp_by_id_or_name(bs, sn_id_or_name,
                                                   &local_err);
    }
    if (ret < 0) {
        error_reportf_err(local_err, "Failed to load snapshot: ");
        exit(EXIT_FAILURE);
    }

    bs->detect_zeroes = detect_zeroes;
    fd_size = blk_getlength(blk);
    if (fd_size < 0) {
        error_report("Failed to determine the image length: %s",
                     strerror(-fd_size));
        exit(EXIT_FAILURE);
    }

    if (dev_offset >= fd_size) {
        error_report("Offset (%" PRIu64 ") has to be smaller than the image "
                     "size (%" PRId64 ")", dev_offset, fd_size);
        exit(EXIT_FAILURE);
    }
    fd_size -= dev_offset;

    if (partition) {
        uint64_t limit;

        if (dev_offset) {
            error_report("Cannot request partition and offset together");
            exit(EXIT_FAILURE);
        }
        ret = find_partition(blk, partition, &dev_offset, &limit);
        if (ret < 0) {
            error_report("Could not find partition %d: %s", partition,
                         strerror(-ret));
            exit(EXIT_FAILURE);
        }
        /*
         * MBR partition limits are (32-bit << 9); this assert lets
         * the compiler know that we can't overflow 64 bits.
         */
        assert(dev_offset + limit >= dev_offset);
        if (dev_offset + limit > fd_size) {
            error_report("Discovered partition %d at offset %" PRIu64
                         " size %" PRIu64 ", but size exceeds file length %"
                         PRId64, partition, dev_offset, limit, fd_size);
            exit(EXIT_FAILURE);
        }
        fd_size = limit;
    }

    export = nbd_export_new(bs, dev_offset, fd_size, export_name,
                            export_description, bitmap, nbdflags,
                            nbd_export_closed, writethrough, NULL,
                            &error_fatal);

    if (device) {
#if HAVE_NBD_DEVICE
        int ret;

        ret = pthread_create(&client_thread, NULL, nbd_client_thread, device);
        if (ret != 0) {
            error_report("Failed to create client thread: %s", strerror(ret));
            exit(EXIT_FAILURE);
        }
#endif
    } else {
        /* Shut up GCC warnings.  */
        memset(&client_thread, 0, sizeof(client_thread));
    }

    nbd_update_server_watch();

    /* now when the initialization is (almost) complete, chdir("/")
     * to free any busy filesystems */
    if (chdir("/") < 0) {
        error_report("Could not chdir to root directory: %s",
                     strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (fork_process) {
        dup2(old_stderr, STDERR_FILENO);
        close(old_stderr);
    }

    state = RUNNING;
    do {
        main_loop_wait(false);
        if (state == TERMINATE) {
            state = TERMINATING;
            nbd_export_close(export);
            nbd_export_put(export);
            export = NULL;
        }
    } while (state != TERMINATED);

    blk_unref(blk);
    if (sockpath) {
        unlink(sockpath);
    }

    qemu_opts_del(sn_opts);

    if (device) {
        void *ret;
        pthread_join(client_thread, &ret);
        exit(ret != NULL);
    } else {
        exit(EXIT_SUCCESS);
    }
}
