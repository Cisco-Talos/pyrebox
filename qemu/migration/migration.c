/*
 * QEMU live migration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "migration/blocker.h"
#include "exec.h"
#include "fd.h"
#include "socket.h"
#include "rdma.h"
#include "ram.h"
#include "migration/global_state.h"
#include "migration/misc.h"
#include "migration.h"
#include "savevm.h"
#include "qemu-file-channel.h"
#include "qemu-file.h"
#include "migration/vmstate.h"
#include "block/block.h"
#include "qapi/error.h"
#include "qapi/clone-visitor.h"
#include "qapi/qapi-visit-sockets.h"
#include "qapi/qapi-commands-migration.h"
#include "qapi/qapi-events-migration.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qmp/qnull.h"
#include "qemu/rcu.h"
#include "block.h"
#include "postcopy-ram.h"
#include "qemu/thread.h"
#include "trace.h"
#include "exec/target_page.h"
#include "io/channel-buffer.h"
#include "migration/colo.h"
#include "hw/boards.h"
#include "monitor/monitor.h"
#include "net/announce.h"

#define MAX_THROTTLE  (32 << 20)      /* Migration transfer speed throttling */

/* Amount of time to allocate to each "chunk" of bandwidth-throttled
 * data. */
#define BUFFER_DELAY     100
#define XFER_LIMIT_RATIO (1000 / BUFFER_DELAY)

/* Time in milliseconds we are allowed to stop the source,
 * for sending the last part */
#define DEFAULT_MIGRATE_SET_DOWNTIME 300

/* Maximum migrate downtime set to 2000 seconds */
#define MAX_MIGRATE_DOWNTIME_SECONDS 2000
#define MAX_MIGRATE_DOWNTIME (MAX_MIGRATE_DOWNTIME_SECONDS * 1000)

/* Default compression thread count */
#define DEFAULT_MIGRATE_COMPRESS_THREAD_COUNT 8
/* Default decompression thread count, usually decompression is at
 * least 4 times as fast as compression.*/
#define DEFAULT_MIGRATE_DECOMPRESS_THREAD_COUNT 2
/*0: means nocompress, 1: best speed, ... 9: best compress ratio */
#define DEFAULT_MIGRATE_COMPRESS_LEVEL 1
/* Define default autoconverge cpu throttle migration parameters */
#define DEFAULT_MIGRATE_CPU_THROTTLE_INITIAL 20
#define DEFAULT_MIGRATE_CPU_THROTTLE_INCREMENT 10
#define DEFAULT_MIGRATE_MAX_CPU_THROTTLE 99

/* Migration XBZRLE default cache size */
#define DEFAULT_MIGRATE_XBZRLE_CACHE_SIZE (64 * 1024 * 1024)

/* The delay time (in ms) between two COLO checkpoints */
#define DEFAULT_MIGRATE_X_CHECKPOINT_DELAY (200 * 100)
#define DEFAULT_MIGRATE_MULTIFD_CHANNELS 2

/* Background transfer rate for postcopy, 0 means unlimited, note
 * that page requests can still exceed this limit.
 */
#define DEFAULT_MIGRATE_MAX_POSTCOPY_BANDWIDTH 0

/*
 * Parameters for self_announce_delay giving a stream of RARP/ARP
 * packets after migration.
 */
#define DEFAULT_MIGRATE_ANNOUNCE_INITIAL  50
#define DEFAULT_MIGRATE_ANNOUNCE_MAX     550
#define DEFAULT_MIGRATE_ANNOUNCE_ROUNDS    5
#define DEFAULT_MIGRATE_ANNOUNCE_STEP    100

static NotifierList migration_state_notifiers =
    NOTIFIER_LIST_INITIALIZER(migration_state_notifiers);

static bool deferred_incoming;

/* Messages sent on the return path from destination to source */
enum mig_rp_message_type {
    MIG_RP_MSG_INVALID = 0,  /* Must be 0 */
    MIG_RP_MSG_SHUT,         /* sibling will not send any more RP messages */
    MIG_RP_MSG_PONG,         /* Response to a PING; data (seq: be32 ) */

    MIG_RP_MSG_REQ_PAGES_ID, /* data (start: be64, len: be32, id: string) */
    MIG_RP_MSG_REQ_PAGES,    /* data (start: be64, len: be32) */
    MIG_RP_MSG_RECV_BITMAP,  /* send recved_bitmap back to source */
    MIG_RP_MSG_RESUME_ACK,   /* tell source that we are ready to resume */

    MIG_RP_MSG_MAX
};

/* When we add fault tolerance, we could have several
   migrations at once.  For now we don't need to add
   dynamic creation of migration */

static MigrationState *current_migration;
static MigrationIncomingState *current_incoming;

static bool migration_object_check(MigrationState *ms, Error **errp);
static int migration_maybe_pause(MigrationState *s,
                                 int *current_active_state,
                                 int new_state);
static void migrate_fd_cancel(MigrationState *s);

void migration_object_init(void)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    Error *err = NULL;

    /* This can only be called once. */
    assert(!current_migration);
    current_migration = MIGRATION_OBJ(object_new(TYPE_MIGRATION));

    /*
     * Init the migrate incoming object as well no matter whether
     * we'll use it or not.
     */
    assert(!current_incoming);
    current_incoming = g_new0(MigrationIncomingState, 1);
    current_incoming->state = MIGRATION_STATUS_NONE;
    current_incoming->postcopy_remote_fds =
        g_array_new(FALSE, TRUE, sizeof(struct PostCopyFD));
    qemu_mutex_init(&current_incoming->rp_mutex);
    qemu_event_init(&current_incoming->main_thread_load_event, false);
    qemu_sem_init(&current_incoming->postcopy_pause_sem_dst, 0);
    qemu_sem_init(&current_incoming->postcopy_pause_sem_fault, 0);

    init_dirty_bitmap_incoming_migration();

    if (!migration_object_check(current_migration, &err)) {
        error_report_err(err);
        exit(1);
    }

    /*
     * We cannot really do this in migration_instance_init() since at
     * that time global properties are not yet applied, then this
     * value will be definitely replaced by something else.
     */
    if (ms->enforce_config_section) {
        current_migration->send_configuration = true;
    }
}

void migration_shutdown(void)
{
    /*
     * Cancel the current migration - that will (eventually)
     * stop the migration using this structure
     */
    migrate_fd_cancel(current_migration);
    object_unref(OBJECT(current_migration));
}

/* For outgoing */
MigrationState *migrate_get_current(void)
{
    /* This can only be called after the object created. */
    assert(current_migration);
    return current_migration;
}

MigrationIncomingState *migration_incoming_get_current(void)
{
    assert(current_incoming);
    return current_incoming;
}

void migration_incoming_state_destroy(void)
{
    struct MigrationIncomingState *mis = migration_incoming_get_current();

    if (mis->to_src_file) {
        /* Tell source that we are done */
        migrate_send_rp_shut(mis, qemu_file_get_error(mis->from_src_file) != 0);
        qemu_fclose(mis->to_src_file);
        mis->to_src_file = NULL;
    }

    if (mis->from_src_file) {
        qemu_fclose(mis->from_src_file);
        mis->from_src_file = NULL;
    }
    if (mis->postcopy_remote_fds) {
        g_array_free(mis->postcopy_remote_fds, TRUE);
        mis->postcopy_remote_fds = NULL;
    }

    qemu_event_reset(&mis->main_thread_load_event);

    if (mis->socket_address_list) {
        qapi_free_SocketAddressList(mis->socket_address_list);
        mis->socket_address_list = NULL;
    }
}

static void migrate_generate_event(int new_state)
{
    if (migrate_use_events()) {
        qapi_event_send_migration(new_state);
    }
}

static bool migrate_late_block_activate(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[
        MIGRATION_CAPABILITY_LATE_BLOCK_ACTIVATE];
}

/*
 * Called on -incoming with a defer: uri.
 * The migration can be started later after any parameters have been
 * changed.
 */
static void deferred_incoming_migration(Error **errp)
{
    if (deferred_incoming) {
        error_setg(errp, "Incoming migration already deferred");
    }
    deferred_incoming = true;
}

/*
 * Send a message on the return channel back to the source
 * of the migration.
 */
static int migrate_send_rp_message(MigrationIncomingState *mis,
                                   enum mig_rp_message_type message_type,
                                   uint16_t len, void *data)
{
    int ret = 0;

    trace_migrate_send_rp_message((int)message_type, len);
    qemu_mutex_lock(&mis->rp_mutex);

    /*
     * It's possible that the file handle got lost due to network
     * failures.
     */
    if (!mis->to_src_file) {
        ret = -EIO;
        goto error;
    }

    qemu_put_be16(mis->to_src_file, (unsigned int)message_type);
    qemu_put_be16(mis->to_src_file, len);
    qemu_put_buffer(mis->to_src_file, data, len);
    qemu_fflush(mis->to_src_file);

    /* It's possible that qemu file got error during sending */
    ret = qemu_file_get_error(mis->to_src_file);

error:
    qemu_mutex_unlock(&mis->rp_mutex);
    return ret;
}

/* Request a range of pages from the source VM at the given
 * start address.
 *   rbname: Name of the RAMBlock to request the page in, if NULL it's the same
 *           as the last request (a name must have been given previously)
 *   Start: Address offset within the RB
 *   Len: Length in bytes required - must be a multiple of pagesize
 */
int migrate_send_rp_req_pages(MigrationIncomingState *mis, const char *rbname,
                              ram_addr_t start, size_t len)
{
    uint8_t bufc[12 + 1 + 255]; /* start (8), len (4), rbname up to 256 */
    size_t msglen = 12; /* start + len */
    enum mig_rp_message_type msg_type;

    *(uint64_t *)bufc = cpu_to_be64((uint64_t)start);
    *(uint32_t *)(bufc + 8) = cpu_to_be32((uint32_t)len);

    if (rbname) {
        int rbname_len = strlen(rbname);
        assert(rbname_len < 256);

        bufc[msglen++] = rbname_len;
        memcpy(bufc + msglen, rbname, rbname_len);
        msglen += rbname_len;
        msg_type = MIG_RP_MSG_REQ_PAGES_ID;
    } else {
        msg_type = MIG_RP_MSG_REQ_PAGES;
    }

    return migrate_send_rp_message(mis, msg_type, msglen, bufc);
}

static bool migration_colo_enabled;
bool migration_incoming_colo_enabled(void)
{
    return migration_colo_enabled;
}

void migration_incoming_disable_colo(void)
{
    migration_colo_enabled = false;
}

void migration_incoming_enable_colo(void)
{
    migration_colo_enabled = true;
}

void migrate_add_address(SocketAddress *address)
{
    MigrationIncomingState *mis = migration_incoming_get_current();
    SocketAddressList *addrs;

    addrs = g_new0(SocketAddressList, 1);
    addrs->next = mis->socket_address_list;
    mis->socket_address_list = addrs;
    addrs->value = QAPI_CLONE(SocketAddress, address);
}

void qemu_start_incoming_migration(const char *uri, Error **errp)
{
    const char *p;

    qapi_event_send_migration(MIGRATION_STATUS_SETUP);
    if (!strcmp(uri, "defer")) {
        deferred_incoming_migration(errp);
    } else if (strstart(uri, "tcp:", &p)) {
        tcp_start_incoming_migration(p, errp);
#ifdef CONFIG_RDMA
    } else if (strstart(uri, "rdma:", &p)) {
        rdma_start_incoming_migration(p, errp);
#endif
    } else if (strstart(uri, "exec:", &p)) {
        exec_start_incoming_migration(p, errp);
    } else if (strstart(uri, "unix:", &p)) {
        unix_start_incoming_migration(p, errp);
    } else if (strstart(uri, "fd:", &p)) {
        fd_start_incoming_migration(p, errp);
    } else {
        error_setg(errp, "unknown migration protocol: %s", uri);
    }
}

static void process_incoming_migration_bh(void *opaque)
{
    Error *local_err = NULL;
    MigrationIncomingState *mis = opaque;

    /* If capability late_block_activate is set:
     * Only fire up the block code now if we're going to restart the
     * VM, else 'cont' will do it.
     * This causes file locking to happen; so we don't want it to happen
     * unless we really are starting the VM.
     */
    if (!migrate_late_block_activate() ||
         (autostart && (!global_state_received() ||
            global_state_get_runstate() == RUN_STATE_RUNNING))) {
        /* Make sure all file formats flush their mutable metadata.
         * If we get an error here, just don't restart the VM yet. */
        bdrv_invalidate_cache_all(&local_err);
        if (local_err) {
            error_report_err(local_err);
            local_err = NULL;
            autostart = false;
        }
    }

    /*
     * This must happen after all error conditions are dealt with and
     * we're sure the VM is going to be running on this host.
     */
    qemu_announce_self(&mis->announce_timer, migrate_announce_params());

    if (multifd_load_cleanup(&local_err) != 0) {
        error_report_err(local_err);
        autostart = false;
    }
    /* If global state section was not received or we are in running
       state, we need to obey autostart. Any other state is set with
       runstate_set. */

    dirty_bitmap_mig_before_vm_start();

    if (!global_state_received() ||
        global_state_get_runstate() == RUN_STATE_RUNNING) {
        if (autostart) {
            vm_start();
        } else {
            runstate_set(RUN_STATE_PAUSED);
        }
    } else if (migration_incoming_colo_enabled()) {
        migration_incoming_disable_colo();
        vm_start();
    } else {
        runstate_set(global_state_get_runstate());
    }
    /*
     * This must happen after any state changes since as soon as an external
     * observer sees this event they might start to prod at the VM assuming
     * it's ready to use.
     */
    migrate_set_state(&mis->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_COMPLETED);
    qemu_bh_delete(mis->bh);
    migration_incoming_state_destroy();
}

static void process_incoming_migration_co(void *opaque)
{
    MigrationIncomingState *mis = migration_incoming_get_current();
    PostcopyState ps;
    int ret;
    Error *local_err = NULL;

    assert(mis->from_src_file);
    mis->migration_incoming_co = qemu_coroutine_self();
    mis->largest_page_size = qemu_ram_pagesize_largest();
    postcopy_state_set(POSTCOPY_INCOMING_NONE);
    migrate_set_state(&mis->state, MIGRATION_STATUS_NONE,
                      MIGRATION_STATUS_ACTIVE);
    ret = qemu_loadvm_state(mis->from_src_file);

    ps = postcopy_state_get();
    trace_process_incoming_migration_co_end(ret, ps);
    if (ps != POSTCOPY_INCOMING_NONE) {
        if (ps == POSTCOPY_INCOMING_ADVISE) {
            /*
             * Where a migration had postcopy enabled (and thus went to advise)
             * but managed to complete within the precopy period, we can use
             * the normal exit.
             */
            postcopy_ram_incoming_cleanup(mis);
        } else if (ret >= 0) {
            /*
             * Postcopy was started, cleanup should happen at the end of the
             * postcopy thread.
             */
            trace_process_incoming_migration_co_postcopy_end_main();
            return;
        }
        /* Else if something went wrong then just fall out of the normal exit */
    }

    /* we get COLO info, and know if we are in COLO mode */
    if (!ret && migration_incoming_colo_enabled()) {
        /* Make sure all file formats flush their mutable metadata */
        bdrv_invalidate_cache_all(&local_err);
        if (local_err) {
            error_report_err(local_err);
            goto fail;
        }

        if (colo_init_ram_cache() < 0) {
            error_report("Init ram cache failed");
            goto fail;
        }

        qemu_thread_create(&mis->colo_incoming_thread, "COLO incoming",
             colo_process_incoming_thread, mis, QEMU_THREAD_JOINABLE);
        mis->have_colo_incoming_thread = true;
        qemu_coroutine_yield();

        /* Wait checkpoint incoming thread exit before free resource */
        qemu_thread_join(&mis->colo_incoming_thread);
        /* We hold the global iothread lock, so it is safe here */
        colo_release_ram_cache();
    }

    if (ret < 0) {
        error_report("load of migration failed: %s", strerror(-ret));
        goto fail;
    }
    mis->bh = qemu_bh_new(process_incoming_migration_bh, mis);
    qemu_bh_schedule(mis->bh);
    mis->migration_incoming_co = NULL;
    return;
fail:
    local_err = NULL;
    migrate_set_state(&mis->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_FAILED);
    qemu_fclose(mis->from_src_file);
    if (multifd_load_cleanup(&local_err) != 0) {
        error_report_err(local_err);
    }
    exit(EXIT_FAILURE);
}

static void migration_incoming_setup(QEMUFile *f)
{
    MigrationIncomingState *mis = migration_incoming_get_current();

    if (multifd_load_setup() != 0) {
        /* We haven't been able to create multifd threads
           nothing better to do */
        exit(EXIT_FAILURE);
    }

    if (!mis->from_src_file) {
        mis->from_src_file = f;
    }
    qemu_file_set_blocking(f, false);
}

void migration_incoming_process(void)
{
    Coroutine *co = qemu_coroutine_create(process_incoming_migration_co, NULL);
    qemu_coroutine_enter(co);
}

/* Returns true if recovered from a paused migration, otherwise false */
static bool postcopy_try_recover(QEMUFile *f)
{
    MigrationIncomingState *mis = migration_incoming_get_current();

    if (mis->state == MIGRATION_STATUS_POSTCOPY_PAUSED) {
        /* Resumed from a paused postcopy migration */

        mis->from_src_file = f;
        /* Postcopy has standalone thread to do vm load */
        qemu_file_set_blocking(f, true);

        /* Re-configure the return path */
        mis->to_src_file = qemu_file_get_return_path(f);

        migrate_set_state(&mis->state, MIGRATION_STATUS_POSTCOPY_PAUSED,
                          MIGRATION_STATUS_POSTCOPY_RECOVER);

        /*
         * Here, we only wake up the main loading thread (while the
         * fault thread will still be waiting), so that we can receive
         * commands from source now, and answer it if needed. The
         * fault thread will be woken up afterwards until we are sure
         * that source is ready to reply to page requests.
         */
        qemu_sem_post(&mis->postcopy_pause_sem_dst);
        return true;
    }

    return false;
}

void migration_fd_process_incoming(QEMUFile *f)
{
    if (postcopy_try_recover(f)) {
        return;
    }

    migration_incoming_setup(f);
    migration_incoming_process();
}

void migration_ioc_process_incoming(QIOChannel *ioc, Error **errp)
{
    MigrationIncomingState *mis = migration_incoming_get_current();
    bool start_migration;

    if (!mis->from_src_file) {
        /* The first connection (multifd may have multiple) */
        QEMUFile *f = qemu_fopen_channel_input(ioc);

        /* If it's a recovery, we're done */
        if (postcopy_try_recover(f)) {
            return;
        }

        migration_incoming_setup(f);

        /*
         * Common migration only needs one channel, so we can start
         * right now.  Multifd needs more than one channel, we wait.
         */
        start_migration = !migrate_use_multifd();
    } else {
        Error *local_err = NULL;
        /* Multiple connections */
        assert(migrate_use_multifd());
        start_migration = multifd_recv_new_channel(ioc, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            return;
        }
    }

    if (start_migration) {
        migration_incoming_process();
    }
}

/**
 * @migration_has_all_channels: We have received all channels that we need
 *
 * Returns true when we have got connections to all the channels that
 * we need for migration.
 */
bool migration_has_all_channels(void)
{
    MigrationIncomingState *mis = migration_incoming_get_current();
    bool all_channels;

    all_channels = multifd_recv_all_channels_created();

    return all_channels && mis->from_src_file != NULL;
}

/*
 * Send a 'SHUT' message on the return channel with the given value
 * to indicate that we've finished with the RP.  Non-0 value indicates
 * error.
 */
void migrate_send_rp_shut(MigrationIncomingState *mis,
                          uint32_t value)
{
    uint32_t buf;

    buf = cpu_to_be32(value);
    migrate_send_rp_message(mis, MIG_RP_MSG_SHUT, sizeof(buf), &buf);
}

/*
 * Send a 'PONG' message on the return channel with the given value
 * (normally in response to a 'PING')
 */
void migrate_send_rp_pong(MigrationIncomingState *mis,
                          uint32_t value)
{
    uint32_t buf;

    buf = cpu_to_be32(value);
    migrate_send_rp_message(mis, MIG_RP_MSG_PONG, sizeof(buf), &buf);
}

void migrate_send_rp_recv_bitmap(MigrationIncomingState *mis,
                                 char *block_name)
{
    char buf[512];
    int len;
    int64_t res;

    /*
     * First, we send the header part. It contains only the len of
     * idstr, and the idstr itself.
     */
    len = strlen(block_name);
    buf[0] = len;
    memcpy(buf + 1, block_name, len);

    if (mis->state != MIGRATION_STATUS_POSTCOPY_RECOVER) {
        error_report("%s: MSG_RP_RECV_BITMAP only used for recovery",
                     __func__);
        return;
    }

    migrate_send_rp_message(mis, MIG_RP_MSG_RECV_BITMAP, len + 1, buf);

    /*
     * Next, we dump the received bitmap to the stream.
     *
     * TODO: currently we are safe since we are the only one that is
     * using the to_src_file handle (fault thread is still paused),
     * and it's ok even not taking the mutex. However the best way is
     * to take the lock before sending the message header, and release
     * the lock after sending the bitmap.
     */
    qemu_mutex_lock(&mis->rp_mutex);
    res = ramblock_recv_bitmap_send(mis->to_src_file, block_name);
    qemu_mutex_unlock(&mis->rp_mutex);

    trace_migrate_send_rp_recv_bitmap(block_name, res);
}

void migrate_send_rp_resume_ack(MigrationIncomingState *mis, uint32_t value)
{
    uint32_t buf;

    buf = cpu_to_be32(value);
    migrate_send_rp_message(mis, MIG_RP_MSG_RESUME_ACK, sizeof(buf), &buf);
}

MigrationCapabilityStatusList *qmp_query_migrate_capabilities(Error **errp)
{
    MigrationCapabilityStatusList *head = NULL;
    MigrationCapabilityStatusList *caps;
    MigrationState *s = migrate_get_current();
    int i;

    caps = NULL; /* silence compiler warning */
    for (i = 0; i < MIGRATION_CAPABILITY__MAX; i++) {
#ifndef CONFIG_LIVE_BLOCK_MIGRATION
        if (i == MIGRATION_CAPABILITY_BLOCK) {
            continue;
        }
#endif
        if (head == NULL) {
            head = g_malloc0(sizeof(*caps));
            caps = head;
        } else {
            caps->next = g_malloc0(sizeof(*caps));
            caps = caps->next;
        }
        caps->value =
            g_malloc(sizeof(*caps->value));
        caps->value->capability = i;
        caps->value->state = s->enabled_capabilities[i];
    }

    return head;
}

MigrationParameters *qmp_query_migrate_parameters(Error **errp)
{
    MigrationParameters *params;
    MigrationState *s = migrate_get_current();

    /* TODO use QAPI_CLONE() instead of duplicating it inline */
    params = g_malloc0(sizeof(*params));
    params->has_compress_level = true;
    params->compress_level = s->parameters.compress_level;
    params->has_compress_threads = true;
    params->compress_threads = s->parameters.compress_threads;
    params->has_compress_wait_thread = true;
    params->compress_wait_thread = s->parameters.compress_wait_thread;
    params->has_decompress_threads = true;
    params->decompress_threads = s->parameters.decompress_threads;
    params->has_cpu_throttle_initial = true;
    params->cpu_throttle_initial = s->parameters.cpu_throttle_initial;
    params->has_cpu_throttle_increment = true;
    params->cpu_throttle_increment = s->parameters.cpu_throttle_increment;
    params->has_tls_creds = true;
    params->tls_creds = g_strdup(s->parameters.tls_creds);
    params->has_tls_hostname = true;
    params->tls_hostname = g_strdup(s->parameters.tls_hostname);
    params->has_tls_authz = true;
    params->tls_authz = g_strdup(s->parameters.tls_authz);
    params->has_max_bandwidth = true;
    params->max_bandwidth = s->parameters.max_bandwidth;
    params->has_downtime_limit = true;
    params->downtime_limit = s->parameters.downtime_limit;
    params->has_x_checkpoint_delay = true;
    params->x_checkpoint_delay = s->parameters.x_checkpoint_delay;
    params->has_block_incremental = true;
    params->block_incremental = s->parameters.block_incremental;
    params->has_multifd_channels = true;
    params->multifd_channels = s->parameters.multifd_channels;
    params->has_xbzrle_cache_size = true;
    params->xbzrle_cache_size = s->parameters.xbzrle_cache_size;
    params->has_max_postcopy_bandwidth = true;
    params->max_postcopy_bandwidth = s->parameters.max_postcopy_bandwidth;
    params->has_max_cpu_throttle = true;
    params->max_cpu_throttle = s->parameters.max_cpu_throttle;
    params->has_announce_initial = true;
    params->announce_initial = s->parameters.announce_initial;
    params->has_announce_max = true;
    params->announce_max = s->parameters.announce_max;
    params->has_announce_rounds = true;
    params->announce_rounds = s->parameters.announce_rounds;
    params->has_announce_step = true;
    params->announce_step = s->parameters.announce_step;

    return params;
}

AnnounceParameters *migrate_announce_params(void)
{
    static AnnounceParameters ap;

    MigrationState *s = migrate_get_current();

    ap.initial = s->parameters.announce_initial;
    ap.max = s->parameters.announce_max;
    ap.rounds = s->parameters.announce_rounds;
    ap.step = s->parameters.announce_step;

    return &ap;
}

/*
 * Return true if we're already in the middle of a migration
 * (i.e. any of the active or setup states)
 */
bool migration_is_setup_or_active(int state)
{
    switch (state) {
    case MIGRATION_STATUS_ACTIVE:
    case MIGRATION_STATUS_POSTCOPY_ACTIVE:
    case MIGRATION_STATUS_POSTCOPY_PAUSED:
    case MIGRATION_STATUS_POSTCOPY_RECOVER:
    case MIGRATION_STATUS_SETUP:
    case MIGRATION_STATUS_PRE_SWITCHOVER:
    case MIGRATION_STATUS_DEVICE:
        return true;

    default:
        return false;

    }
}

static void populate_ram_info(MigrationInfo *info, MigrationState *s)
{
    info->has_ram = true;
    info->ram = g_malloc0(sizeof(*info->ram));
    info->ram->transferred = ram_counters.transferred;
    info->ram->total = ram_bytes_total();
    info->ram->duplicate = ram_counters.duplicate;
    /* legacy value.  It is not used anymore */
    info->ram->skipped = 0;
    info->ram->normal = ram_counters.normal;
    info->ram->normal_bytes = ram_counters.normal *
        qemu_target_page_size();
    info->ram->mbps = s->mbps;
    info->ram->dirty_sync_count = ram_counters.dirty_sync_count;
    info->ram->postcopy_requests = ram_counters.postcopy_requests;
    info->ram->page_size = qemu_target_page_size();
    info->ram->multifd_bytes = ram_counters.multifd_bytes;
    info->ram->pages_per_second = s->pages_per_second;

    if (migrate_use_xbzrle()) {
        info->has_xbzrle_cache = true;
        info->xbzrle_cache = g_malloc0(sizeof(*info->xbzrle_cache));
        info->xbzrle_cache->cache_size = migrate_xbzrle_cache_size();
        info->xbzrle_cache->bytes = xbzrle_counters.bytes;
        info->xbzrle_cache->pages = xbzrle_counters.pages;
        info->xbzrle_cache->cache_miss = xbzrle_counters.cache_miss;
        info->xbzrle_cache->cache_miss_rate = xbzrle_counters.cache_miss_rate;
        info->xbzrle_cache->overflow = xbzrle_counters.overflow;
    }

    if (migrate_use_compression()) {
        info->has_compression = true;
        info->compression = g_malloc0(sizeof(*info->compression));
        info->compression->pages = compression_counters.pages;
        info->compression->busy = compression_counters.busy;
        info->compression->busy_rate = compression_counters.busy_rate;
        info->compression->compressed_size =
                                    compression_counters.compressed_size;
        info->compression->compression_rate =
                                    compression_counters.compression_rate;
    }

    if (cpu_throttle_active()) {
        info->has_cpu_throttle_percentage = true;
        info->cpu_throttle_percentage = cpu_throttle_get_percentage();
    }

    if (s->state != MIGRATION_STATUS_COMPLETED) {
        info->ram->remaining = ram_bytes_remaining();
        info->ram->dirty_pages_rate = ram_counters.dirty_pages_rate;
    }
}

static void populate_disk_info(MigrationInfo *info)
{
    if (blk_mig_active()) {
        info->has_disk = true;
        info->disk = g_malloc0(sizeof(*info->disk));
        info->disk->transferred = blk_mig_bytes_transferred();
        info->disk->remaining = blk_mig_bytes_remaining();
        info->disk->total = blk_mig_bytes_total();
    }
}

static void fill_source_migration_info(MigrationInfo *info)
{
    MigrationState *s = migrate_get_current();

    switch (s->state) {
    case MIGRATION_STATUS_NONE:
        /* no migration has happened ever */
        /* do not overwrite destination migration status */
        return;
        break;
    case MIGRATION_STATUS_SETUP:
        info->has_status = true;
        info->has_total_time = false;
        break;
    case MIGRATION_STATUS_ACTIVE:
    case MIGRATION_STATUS_CANCELLING:
    case MIGRATION_STATUS_POSTCOPY_ACTIVE:
    case MIGRATION_STATUS_PRE_SWITCHOVER:
    case MIGRATION_STATUS_DEVICE:
    case MIGRATION_STATUS_POSTCOPY_PAUSED:
    case MIGRATION_STATUS_POSTCOPY_RECOVER:
         /* TODO add some postcopy stats */
        info->has_status = true;
        info->has_total_time = true;
        info->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME)
            - s->start_time;
        info->has_expected_downtime = true;
        info->expected_downtime = s->expected_downtime;
        info->has_setup_time = true;
        info->setup_time = s->setup_time;

        populate_ram_info(info, s);
        populate_disk_info(info);
        break;
    case MIGRATION_STATUS_COLO:
        info->has_status = true;
        /* TODO: display COLO specific information (checkpoint info etc.) */
        break;
    case MIGRATION_STATUS_COMPLETED:
        info->has_status = true;
        info->has_total_time = true;
        info->total_time = s->total_time;
        info->has_downtime = true;
        info->downtime = s->downtime;
        info->has_setup_time = true;
        info->setup_time = s->setup_time;

        populate_ram_info(info, s);
        break;
    case MIGRATION_STATUS_FAILED:
        info->has_status = true;
        if (s->error) {
            info->has_error_desc = true;
            info->error_desc = g_strdup(error_get_pretty(s->error));
        }
        break;
    case MIGRATION_STATUS_CANCELLED:
        info->has_status = true;
        break;
    }
    info->status = s->state;
}

/**
 * @migration_caps_check - check capability validity
 *
 * @cap_list: old capability list, array of bool
 * @params: new capabilities to be applied soon
 * @errp: set *errp if the check failed, with reason
 *
 * Returns true if check passed, otherwise false.
 */
static bool migrate_caps_check(bool *cap_list,
                               MigrationCapabilityStatusList *params,
                               Error **errp)
{
    MigrationCapabilityStatusList *cap;
    bool old_postcopy_cap;
    MigrationIncomingState *mis = migration_incoming_get_current();

    old_postcopy_cap = cap_list[MIGRATION_CAPABILITY_POSTCOPY_RAM];

    for (cap = params; cap; cap = cap->next) {
        cap_list[cap->value->capability] = cap->value->state;
    }

#ifndef CONFIG_LIVE_BLOCK_MIGRATION
    if (cap_list[MIGRATION_CAPABILITY_BLOCK]) {
        error_setg(errp, "QEMU compiled without old-style (blk/-b, inc/-i) "
                   "block migration");
        error_append_hint(errp, "Use drive_mirror+NBD instead.\n");
        return false;
    }
#endif

#ifndef CONFIG_REPLICATION
    if (cap_list[MIGRATION_CAPABILITY_X_COLO]) {
        error_setg(errp, "QEMU compiled without replication module"
                   " can't enable COLO");
        error_append_hint(errp, "Please enable replication before COLO.\n");
        return false;
    }
#endif

    if (cap_list[MIGRATION_CAPABILITY_POSTCOPY_RAM]) {
        if (cap_list[MIGRATION_CAPABILITY_COMPRESS]) {
            /* The decompression threads asynchronously write into RAM
             * rather than use the atomic copies needed to avoid
             * userfaulting.  It should be possible to fix the decompression
             * threads for compatibility in future.
             */
            error_setg(errp, "Postcopy is not currently compatible "
                       "with compression");
            return false;
        }

        /* This check is reasonably expensive, so only when it's being
         * set the first time, also it's only the destination that needs
         * special support.
         */
        if (!old_postcopy_cap && runstate_check(RUN_STATE_INMIGRATE) &&
            !postcopy_ram_supported_by_host(mis)) {
            /* postcopy_ram_supported_by_host will have emitted a more
             * detailed message
             */
            error_setg(errp, "Postcopy is not supported");
            return false;
        }

        if (cap_list[MIGRATION_CAPABILITY_X_IGNORE_SHARED]) {
            error_setg(errp, "Postcopy is not compatible with ignore-shared");
            return false;
        }
    }

    return true;
}

static void fill_destination_migration_info(MigrationInfo *info)
{
    MigrationIncomingState *mis = migration_incoming_get_current();

    if (mis->socket_address_list) {
        info->has_socket_address = true;
        info->socket_address =
            QAPI_CLONE(SocketAddressList, mis->socket_address_list);
    }

    switch (mis->state) {
    case MIGRATION_STATUS_NONE:
        return;
        break;
    case MIGRATION_STATUS_SETUP:
    case MIGRATION_STATUS_CANCELLING:
    case MIGRATION_STATUS_CANCELLED:
    case MIGRATION_STATUS_ACTIVE:
    case MIGRATION_STATUS_POSTCOPY_ACTIVE:
    case MIGRATION_STATUS_POSTCOPY_PAUSED:
    case MIGRATION_STATUS_POSTCOPY_RECOVER:
    case MIGRATION_STATUS_FAILED:
    case MIGRATION_STATUS_COLO:
        info->has_status = true;
        break;
    case MIGRATION_STATUS_COMPLETED:
        info->has_status = true;
        fill_destination_postcopy_migration_info(info);
        break;
    }
    info->status = mis->state;
}

MigrationInfo *qmp_query_migrate(Error **errp)
{
    MigrationInfo *info = g_malloc0(sizeof(*info));

    fill_destination_migration_info(info);
    fill_source_migration_info(info);

    return info;
}

void qmp_migrate_set_capabilities(MigrationCapabilityStatusList *params,
                                  Error **errp)
{
    MigrationState *s = migrate_get_current();
    MigrationCapabilityStatusList *cap;
    bool cap_list[MIGRATION_CAPABILITY__MAX];

    if (migration_is_setup_or_active(s->state)) {
        error_setg(errp, QERR_MIGRATION_ACTIVE);
        return;
    }

    memcpy(cap_list, s->enabled_capabilities, sizeof(cap_list));
    if (!migrate_caps_check(cap_list, params, errp)) {
        return;
    }

    for (cap = params; cap; cap = cap->next) {
        s->enabled_capabilities[cap->value->capability] = cap->value->state;
    }
}

/*
 * Check whether the parameters are valid. Error will be put into errp
 * (if provided). Return true if valid, otherwise false.
 */
static bool migrate_params_check(MigrationParameters *params, Error **errp)
{
    if (params->has_compress_level &&
        (params->compress_level > 9)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "compress_level",
                   "is invalid, it should be in the range of 0 to 9");
        return false;
    }

    if (params->has_compress_threads && (params->compress_threads < 1)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "compress_threads",
                   "is invalid, it should be in the range of 1 to 255");
        return false;
    }

    if (params->has_decompress_threads && (params->decompress_threads < 1)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "decompress_threads",
                   "is invalid, it should be in the range of 1 to 255");
        return false;
    }

    if (params->has_cpu_throttle_initial &&
        (params->cpu_throttle_initial < 1 ||
         params->cpu_throttle_initial > 99)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "cpu_throttle_initial",
                   "an integer in the range of 1 to 99");
        return false;
    }

    if (params->has_cpu_throttle_increment &&
        (params->cpu_throttle_increment < 1 ||
         params->cpu_throttle_increment > 99)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "cpu_throttle_increment",
                   "an integer in the range of 1 to 99");
        return false;
    }

    if (params->has_max_bandwidth && (params->max_bandwidth > SIZE_MAX)) {
        error_setg(errp, "Parameter 'max_bandwidth' expects an integer in the"
                         " range of 0 to %zu bytes/second", SIZE_MAX);
        return false;
    }

    if (params->has_downtime_limit &&
        (params->downtime_limit > MAX_MIGRATE_DOWNTIME)) {
        error_setg(errp, "Parameter 'downtime_limit' expects an integer in "
                         "the range of 0 to %d milliseconds",
                         MAX_MIGRATE_DOWNTIME);
        return false;
    }

    /* x_checkpoint_delay is now always positive */

    if (params->has_multifd_channels && (params->multifd_channels < 1)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "multifd_channels",
                   "is invalid, it should be in the range of 1 to 255");
        return false;
    }

    if (params->has_xbzrle_cache_size &&
        (params->xbzrle_cache_size < qemu_target_page_size() ||
         !is_power_of_2(params->xbzrle_cache_size))) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "xbzrle_cache_size",
                   "is invalid, it should be bigger than target page size"
                   " and a power of two");
        return false;
    }

    if (params->has_max_cpu_throttle &&
        (params->max_cpu_throttle < params->cpu_throttle_initial ||
         params->max_cpu_throttle > 99)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "max_cpu_throttle",
                   "an integer in the range of cpu_throttle_initial to 99");
        return false;
    }

    if (params->has_announce_initial &&
        params->announce_initial > 100000) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "announce_initial",
                   "is invalid, it must be less than 100000 ms");
        return false;
    }
    if (params->has_announce_max &&
        params->announce_max > 100000) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "announce_max",
                   "is invalid, it must be less than 100000 ms");
       return false;
    }
    if (params->has_announce_rounds &&
        params->announce_rounds > 1000) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "announce_rounds",
                   "is invalid, it must be in the range of 0 to 1000");
       return false;
    }
    if (params->has_announce_step &&
        (params->announce_step < 1 ||
        params->announce_step > 10000)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "announce_step",
                   "is invalid, it must be in the range of 1 to 10000 ms");
       return false;
    }
    return true;
}

static void migrate_params_test_apply(MigrateSetParameters *params,
                                      MigrationParameters *dest)
{
    *dest = migrate_get_current()->parameters;

    /* TODO use QAPI_CLONE() instead of duplicating it inline */

    if (params->has_compress_level) {
        dest->compress_level = params->compress_level;
    }

    if (params->has_compress_threads) {
        dest->compress_threads = params->compress_threads;
    }

    if (params->has_compress_wait_thread) {
        dest->compress_wait_thread = params->compress_wait_thread;
    }

    if (params->has_decompress_threads) {
        dest->decompress_threads = params->decompress_threads;
    }

    if (params->has_cpu_throttle_initial) {
        dest->cpu_throttle_initial = params->cpu_throttle_initial;
    }

    if (params->has_cpu_throttle_increment) {
        dest->cpu_throttle_increment = params->cpu_throttle_increment;
    }

    if (params->has_tls_creds) {
        assert(params->tls_creds->type == QTYPE_QSTRING);
        dest->tls_creds = g_strdup(params->tls_creds->u.s);
    }

    if (params->has_tls_hostname) {
        assert(params->tls_hostname->type == QTYPE_QSTRING);
        dest->tls_hostname = g_strdup(params->tls_hostname->u.s);
    }

    if (params->has_max_bandwidth) {
        dest->max_bandwidth = params->max_bandwidth;
    }

    if (params->has_downtime_limit) {
        dest->downtime_limit = params->downtime_limit;
    }

    if (params->has_x_checkpoint_delay) {
        dest->x_checkpoint_delay = params->x_checkpoint_delay;
    }

    if (params->has_block_incremental) {
        dest->block_incremental = params->block_incremental;
    }
    if (params->has_multifd_channels) {
        dest->multifd_channels = params->multifd_channels;
    }
    if (params->has_xbzrle_cache_size) {
        dest->xbzrle_cache_size = params->xbzrle_cache_size;
    }
    if (params->has_max_postcopy_bandwidth) {
        dest->max_postcopy_bandwidth = params->max_postcopy_bandwidth;
    }
    if (params->has_max_cpu_throttle) {
        dest->max_cpu_throttle = params->max_cpu_throttle;
    }
    if (params->has_announce_initial) {
        dest->announce_initial = params->announce_initial;
    }
    if (params->has_announce_max) {
        dest->announce_max = params->announce_max;
    }
    if (params->has_announce_rounds) {
        dest->announce_rounds = params->announce_rounds;
    }
    if (params->has_announce_step) {
        dest->announce_step = params->announce_step;
    }
}

static void migrate_params_apply(MigrateSetParameters *params, Error **errp)
{
    MigrationState *s = migrate_get_current();

    /* TODO use QAPI_CLONE() instead of duplicating it inline */

    if (params->has_compress_level) {
        s->parameters.compress_level = params->compress_level;
    }

    if (params->has_compress_threads) {
        s->parameters.compress_threads = params->compress_threads;
    }

    if (params->has_compress_wait_thread) {
        s->parameters.compress_wait_thread = params->compress_wait_thread;
    }

    if (params->has_decompress_threads) {
        s->parameters.decompress_threads = params->decompress_threads;
    }

    if (params->has_cpu_throttle_initial) {
        s->parameters.cpu_throttle_initial = params->cpu_throttle_initial;
    }

    if (params->has_cpu_throttle_increment) {
        s->parameters.cpu_throttle_increment = params->cpu_throttle_increment;
    }

    if (params->has_tls_creds) {
        g_free(s->parameters.tls_creds);
        assert(params->tls_creds->type == QTYPE_QSTRING);
        s->parameters.tls_creds = g_strdup(params->tls_creds->u.s);
    }

    if (params->has_tls_hostname) {
        g_free(s->parameters.tls_hostname);
        assert(params->tls_hostname->type == QTYPE_QSTRING);
        s->parameters.tls_hostname = g_strdup(params->tls_hostname->u.s);
    }

    if (params->has_tls_authz) {
        g_free(s->parameters.tls_authz);
        assert(params->tls_authz->type == QTYPE_QSTRING);
        s->parameters.tls_authz = g_strdup(params->tls_authz->u.s);
    }

    if (params->has_max_bandwidth) {
        s->parameters.max_bandwidth = params->max_bandwidth;
        if (s->to_dst_file && !migration_in_postcopy()) {
            qemu_file_set_rate_limit(s->to_dst_file,
                                s->parameters.max_bandwidth / XFER_LIMIT_RATIO);
        }
    }

    if (params->has_downtime_limit) {
        s->parameters.downtime_limit = params->downtime_limit;
    }

    if (params->has_x_checkpoint_delay) {
        s->parameters.x_checkpoint_delay = params->x_checkpoint_delay;
        if (migration_in_colo_state()) {
            colo_checkpoint_notify(s);
        }
    }

    if (params->has_block_incremental) {
        s->parameters.block_incremental = params->block_incremental;
    }
    if (params->has_multifd_channels) {
        s->parameters.multifd_channels = params->multifd_channels;
    }
    if (params->has_xbzrle_cache_size) {
        s->parameters.xbzrle_cache_size = params->xbzrle_cache_size;
        xbzrle_cache_resize(params->xbzrle_cache_size, errp);
    }
    if (params->has_max_postcopy_bandwidth) {
        s->parameters.max_postcopy_bandwidth = params->max_postcopy_bandwidth;
        if (s->to_dst_file && migration_in_postcopy()) {
            qemu_file_set_rate_limit(s->to_dst_file,
                    s->parameters.max_postcopy_bandwidth / XFER_LIMIT_RATIO);
        }
    }
    if (params->has_max_cpu_throttle) {
        s->parameters.max_cpu_throttle = params->max_cpu_throttle;
    }
    if (params->has_announce_initial) {
        s->parameters.announce_initial = params->announce_initial;
    }
    if (params->has_announce_max) {
        s->parameters.announce_max = params->announce_max;
    }
    if (params->has_announce_rounds) {
        s->parameters.announce_rounds = params->announce_rounds;
    }
    if (params->has_announce_step) {
        s->parameters.announce_step = params->announce_step;
    }
}

void qmp_migrate_set_parameters(MigrateSetParameters *params, Error **errp)
{
    MigrationParameters tmp;

    /* TODO Rewrite "" to null instead */
    if (params->has_tls_creds
        && params->tls_creds->type == QTYPE_QNULL) {
        qobject_unref(params->tls_creds->u.n);
        params->tls_creds->type = QTYPE_QSTRING;
        params->tls_creds->u.s = strdup("");
    }
    /* TODO Rewrite "" to null instead */
    if (params->has_tls_hostname
        && params->tls_hostname->type == QTYPE_QNULL) {
        qobject_unref(params->tls_hostname->u.n);
        params->tls_hostname->type = QTYPE_QSTRING;
        params->tls_hostname->u.s = strdup("");
    }

    migrate_params_test_apply(params, &tmp);

    if (!migrate_params_check(&tmp, errp)) {
        /* Invalid parameter */
        return;
    }

    migrate_params_apply(params, errp);
}


void qmp_migrate_start_postcopy(Error **errp)
{
    MigrationState *s = migrate_get_current();

    if (!migrate_postcopy()) {
        error_setg(errp, "Enable postcopy with migrate_set_capability before"
                         " the start of migration");
        return;
    }

    if (s->state == MIGRATION_STATUS_NONE) {
        error_setg(errp, "Postcopy must be started after migration has been"
                         " started");
        return;
    }
    /*
     * we don't error if migration has finished since that would be racy
     * with issuing this command.
     */
    atomic_set(&s->start_postcopy, true);
}

/* shared migration helpers */

void migrate_set_state(int *state, int old_state, int new_state)
{
    assert(new_state < MIGRATION_STATUS__MAX);
    if (atomic_cmpxchg(state, old_state, new_state) == old_state) {
        trace_migrate_set_state(MigrationStatus_str(new_state));
        migrate_generate_event(new_state);
    }
}

static MigrationCapabilityStatusList *migrate_cap_add(
    MigrationCapabilityStatusList *list,
    MigrationCapability index,
    bool state)
{
    MigrationCapabilityStatusList *cap;

    cap = g_new0(MigrationCapabilityStatusList, 1);
    cap->value = g_new0(MigrationCapabilityStatus, 1);
    cap->value->capability = index;
    cap->value->state = state;
    cap->next = list;

    return cap;
}

void migrate_set_block_enabled(bool value, Error **errp)
{
    MigrationCapabilityStatusList *cap;

    cap = migrate_cap_add(NULL, MIGRATION_CAPABILITY_BLOCK, value);
    qmp_migrate_set_capabilities(cap, errp);
    qapi_free_MigrationCapabilityStatusList(cap);
}

static void migrate_set_block_incremental(MigrationState *s, bool value)
{
    s->parameters.block_incremental = value;
}

static void block_cleanup_parameters(MigrationState *s)
{
    if (s->must_remove_block_options) {
        /* setting to false can never fail */
        migrate_set_block_enabled(false, &error_abort);
        migrate_set_block_incremental(s, false);
        s->must_remove_block_options = false;
    }
}

static void migrate_fd_cleanup(void *opaque)
{
    MigrationState *s = opaque;

    qemu_bh_delete(s->cleanup_bh);
    s->cleanup_bh = NULL;

    qemu_savevm_state_cleanup();

    if (s->to_dst_file) {
        QEMUFile *tmp;

        trace_migrate_fd_cleanup();
        qemu_mutex_unlock_iothread();
        if (s->migration_thread_running) {
            qemu_thread_join(&s->thread);
            s->migration_thread_running = false;
        }
        qemu_mutex_lock_iothread();

        multifd_save_cleanup();
        qemu_mutex_lock(&s->qemu_file_lock);
        tmp = s->to_dst_file;
        s->to_dst_file = NULL;
        qemu_mutex_unlock(&s->qemu_file_lock);
        /*
         * Close the file handle without the lock to make sure the
         * critical section won't block for long.
         */
        qemu_fclose(tmp);
    }

    assert((s->state != MIGRATION_STATUS_ACTIVE) &&
           (s->state != MIGRATION_STATUS_POSTCOPY_ACTIVE));

    if (s->state == MIGRATION_STATUS_CANCELLING) {
        migrate_set_state(&s->state, MIGRATION_STATUS_CANCELLING,
                          MIGRATION_STATUS_CANCELLED);
    }

    if (s->error) {
        /* It is used on info migrate.  We can't free it */
        error_report_err(error_copy(s->error));
    }
    notifier_list_notify(&migration_state_notifiers, s);
    block_cleanup_parameters(s);
}

void migrate_set_error(MigrationState *s, const Error *error)
{
    qemu_mutex_lock(&s->error_mutex);
    if (!s->error) {
        s->error = error_copy(error);
    }
    qemu_mutex_unlock(&s->error_mutex);
}

void migrate_fd_error(MigrationState *s, const Error *error)
{
    trace_migrate_fd_error(error_get_pretty(error));
    assert(s->to_dst_file == NULL);
    migrate_set_state(&s->state, MIGRATION_STATUS_SETUP,
                      MIGRATION_STATUS_FAILED);
    migrate_set_error(s, error);
}

static void migrate_fd_cancel(MigrationState *s)
{
    int old_state ;
    QEMUFile *f = migrate_get_current()->to_dst_file;
    trace_migrate_fd_cancel();

    if (s->rp_state.from_dst_file) {
        /* shutdown the rp socket, so causing the rp thread to shutdown */
        qemu_file_shutdown(s->rp_state.from_dst_file);
    }

    do {
        old_state = s->state;
        if (!migration_is_setup_or_active(old_state)) {
            break;
        }
        /* If the migration is paused, kick it out of the pause */
        if (old_state == MIGRATION_STATUS_PRE_SWITCHOVER) {
            qemu_sem_post(&s->pause_sem);
        }
        migrate_set_state(&s->state, old_state, MIGRATION_STATUS_CANCELLING);
    } while (s->state != MIGRATION_STATUS_CANCELLING);

    /*
     * If we're unlucky the migration code might be stuck somewhere in a
     * send/write while the network has failed and is waiting to timeout;
     * if we've got shutdown(2) available then we can force it to quit.
     * The outgoing qemu file gets closed in migrate_fd_cleanup that is
     * called in a bh, so there is no race against this cancel.
     */
    if (s->state == MIGRATION_STATUS_CANCELLING && f) {
        qemu_file_shutdown(f);
    }
    if (s->state == MIGRATION_STATUS_CANCELLING && s->block_inactive) {
        Error *local_err = NULL;

        bdrv_invalidate_cache_all(&local_err);
        if (local_err) {
            error_report_err(local_err);
        } else {
            s->block_inactive = false;
        }
    }
}

void add_migration_state_change_notifier(Notifier *notify)
{
    notifier_list_add(&migration_state_notifiers, notify);
}

void remove_migration_state_change_notifier(Notifier *notify)
{
    notifier_remove(notify);
}

bool migration_in_setup(MigrationState *s)
{
    return s->state == MIGRATION_STATUS_SETUP;
}

bool migration_has_finished(MigrationState *s)
{
    return s->state == MIGRATION_STATUS_COMPLETED;
}

bool migration_has_failed(MigrationState *s)
{
    return (s->state == MIGRATION_STATUS_CANCELLED ||
            s->state == MIGRATION_STATUS_FAILED);
}

bool migration_in_postcopy(void)
{
    MigrationState *s = migrate_get_current();

    return (s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE);
}

bool migration_in_postcopy_after_devices(MigrationState *s)
{
    return migration_in_postcopy() && s->postcopy_after_devices;
}

bool migration_is_idle(void)
{
    MigrationState *s = current_migration;

    if (!s) {
        return true;
    }

    switch (s->state) {
    case MIGRATION_STATUS_NONE:
    case MIGRATION_STATUS_CANCELLED:
    case MIGRATION_STATUS_COMPLETED:
    case MIGRATION_STATUS_FAILED:
        return true;
    case MIGRATION_STATUS_SETUP:
    case MIGRATION_STATUS_CANCELLING:
    case MIGRATION_STATUS_ACTIVE:
    case MIGRATION_STATUS_POSTCOPY_ACTIVE:
    case MIGRATION_STATUS_COLO:
    case MIGRATION_STATUS_PRE_SWITCHOVER:
    case MIGRATION_STATUS_DEVICE:
        return false;
    case MIGRATION_STATUS__MAX:
        g_assert_not_reached();
    }

    return false;
}

void migrate_init(MigrationState *s)
{
    /*
     * Reinitialise all migration state, except
     * parameters/capabilities that the user set, and
     * locks.
     */
    s->bytes_xfer = 0;
    s->xfer_limit = 0;
    s->cleanup_bh = 0;
    s->to_dst_file = NULL;
    s->state = MIGRATION_STATUS_NONE;
    s->rp_state.from_dst_file = NULL;
    s->rp_state.error = false;
    s->mbps = 0.0;
    s->pages_per_second = 0.0;
    s->downtime = 0;
    s->expected_downtime = 0;
    s->setup_time = 0;
    s->start_postcopy = false;
    s->postcopy_after_devices = false;
    s->migration_thread_running = false;
    error_free(s->error);
    s->error = NULL;

    migrate_set_state(&s->state, MIGRATION_STATUS_NONE, MIGRATION_STATUS_SETUP);

    s->start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    s->total_time = 0;
    s->vm_was_running = false;
    s->iteration_initial_bytes = 0;
    s->threshold_size = 0;
}

static GSList *migration_blockers;

int migrate_add_blocker(Error *reason, Error **errp)
{
    if (only_migratable) {
        error_propagate_prepend(errp, error_copy(reason),
                                "disallowing migration blocker "
                                "(--only_migratable) for: ");
        return -EACCES;
    }

    if (migration_is_idle()) {
        migration_blockers = g_slist_prepend(migration_blockers, reason);
        return 0;
    }

    error_propagate_prepend(errp, error_copy(reason),
                            "disallowing migration blocker "
                            "(migration in progress) for: ");
    return -EBUSY;
}

void migrate_del_blocker(Error *reason)
{
    migration_blockers = g_slist_remove(migration_blockers, reason);
}

void qmp_migrate_incoming(const char *uri, Error **errp)
{
    Error *local_err = NULL;
    static bool once = true;

    if (!deferred_incoming) {
        error_setg(errp, "For use with '-incoming defer'");
        return;
    }
    if (!once) {
        error_setg(errp, "The incoming migration has already been started");
    }

    qemu_start_incoming_migration(uri, &local_err);

    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    once = false;
}

void qmp_migrate_recover(const char *uri, Error **errp)
{
    MigrationIncomingState *mis = migration_incoming_get_current();

    if (mis->state != MIGRATION_STATUS_POSTCOPY_PAUSED) {
        error_setg(errp, "Migrate recover can only be run "
                   "when postcopy is paused.");
        return;
    }

    if (atomic_cmpxchg(&mis->postcopy_recover_triggered,
                       false, true) == true) {
        error_setg(errp, "Migrate recovery is triggered already");
        return;
    }

    /*
     * Note that this call will never start a real migration; it will
     * only re-setup the migration stream and poke existing migration
     * to continue using that newly established channel.
     */
    qemu_start_incoming_migration(uri, errp);
}

void qmp_migrate_pause(Error **errp)
{
    MigrationState *ms = migrate_get_current();
    MigrationIncomingState *mis = migration_incoming_get_current();
    int ret;

    if (ms->state == MIGRATION_STATUS_POSTCOPY_ACTIVE) {
        /* Source side, during postcopy */
        qemu_mutex_lock(&ms->qemu_file_lock);
        ret = qemu_file_shutdown(ms->to_dst_file);
        qemu_mutex_unlock(&ms->qemu_file_lock);
        if (ret) {
            error_setg(errp, "Failed to pause source migration");
        }
        return;
    }

    if (mis->state == MIGRATION_STATUS_POSTCOPY_ACTIVE) {
        ret = qemu_file_shutdown(mis->from_src_file);
        if (ret) {
            error_setg(errp, "Failed to pause destination migration");
        }
        return;
    }

    error_setg(errp, "migrate-pause is currently only supported "
               "during postcopy-active state");
}

bool migration_is_blocked(Error **errp)
{
    if (qemu_savevm_state_blocked(errp)) {
        return true;
    }

    if (migration_blockers) {
        error_propagate(errp, error_copy(migration_blockers->data));
        return true;
    }

    return false;
}

/* Returns true if continue to migrate, or false if error detected */
static bool migrate_prepare(MigrationState *s, bool blk, bool blk_inc,
                            bool resume, Error **errp)
{
    Error *local_err = NULL;

    if (resume) {
        if (s->state != MIGRATION_STATUS_POSTCOPY_PAUSED) {
            error_setg(errp, "Cannot resume if there is no "
                       "paused migration");
            return false;
        }

        /*
         * Postcopy recovery won't work well with release-ram
         * capability since release-ram will drop the page buffer as
         * long as the page is put into the send buffer.  So if there
         * is a network failure happened, any page buffers that have
         * not yet reached the destination VM but have already been
         * sent from the source VM will be lost forever.  Let's refuse
         * the client from resuming such a postcopy migration.
         * Luckily release-ram was designed to only be used when src
         * and destination VMs are on the same host, so it should be
         * fine.
         */
        if (migrate_release_ram()) {
            error_setg(errp, "Postcopy recovery cannot work "
                       "when release-ram capability is set");
            return false;
        }

        /* This is a resume, skip init status */
        return true;
    }

    if (migration_is_setup_or_active(s->state) ||
        s->state == MIGRATION_STATUS_CANCELLING ||
        s->state == MIGRATION_STATUS_COLO) {
        error_setg(errp, QERR_MIGRATION_ACTIVE);
        return false;
    }

    if (runstate_check(RUN_STATE_INMIGRATE)) {
        error_setg(errp, "Guest is waiting for an incoming migration");
        return false;
    }

    if (migration_is_blocked(errp)) {
        return false;
    }

    if (blk || blk_inc) {
        if (migrate_use_block() || migrate_use_block_incremental()) {
            error_setg(errp, "Command options are incompatible with "
                       "current migration capabilities");
            return false;
        }
        migrate_set_block_enabled(true, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            return false;
        }
        s->must_remove_block_options = true;
    }

    if (blk_inc) {
        migrate_set_block_incremental(s, true);
    }

    migrate_init(s);

    return true;
}

void qmp_migrate(const char *uri, bool has_blk, bool blk,
                 bool has_inc, bool inc, bool has_detach, bool detach,
                 bool has_resume, bool resume, Error **errp)
{
    Error *local_err = NULL;
    MigrationState *s = migrate_get_current();
    const char *p;

    if (!migrate_prepare(s, has_blk && blk, has_inc && inc,
                         has_resume && resume, errp)) {
        /* Error detected, put into errp */
        return;
    }

    if (strstart(uri, "tcp:", &p)) {
        tcp_start_outgoing_migration(s, p, &local_err);
#ifdef CONFIG_RDMA
    } else if (strstart(uri, "rdma:", &p)) {
        rdma_start_outgoing_migration(s, p, &local_err);
#endif
    } else if (strstart(uri, "exec:", &p)) {
        exec_start_outgoing_migration(s, p, &local_err);
    } else if (strstart(uri, "unix:", &p)) {
        unix_start_outgoing_migration(s, p, &local_err);
    } else if (strstart(uri, "fd:", &p)) {
        fd_start_outgoing_migration(s, p, &local_err);
    } else {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "uri",
                   "a valid migration protocol");
        migrate_set_state(&s->state, MIGRATION_STATUS_SETUP,
                          MIGRATION_STATUS_FAILED);
        block_cleanup_parameters(s);
        return;
    }

    if (local_err) {
        migrate_fd_error(s, local_err);
        error_propagate(errp, local_err);
        return;
    }
}

void qmp_migrate_cancel(Error **errp)
{
    migrate_fd_cancel(migrate_get_current());
}

void qmp_migrate_continue(MigrationStatus state, Error **errp)
{
    MigrationState *s = migrate_get_current();
    if (s->state != state) {
        error_setg(errp,  "Migration not in expected state: %s",
                   MigrationStatus_str(s->state));
        return;
    }
    qemu_sem_post(&s->pause_sem);
}

void qmp_migrate_set_cache_size(int64_t value, Error **errp)
{
    MigrateSetParameters p = {
        .has_xbzrle_cache_size = true,
        .xbzrle_cache_size = value,
    };

    qmp_migrate_set_parameters(&p, errp);
}

int64_t qmp_query_migrate_cache_size(Error **errp)
{
    return migrate_xbzrle_cache_size();
}

void qmp_migrate_set_speed(int64_t value, Error **errp)
{
    MigrateSetParameters p = {
        .has_max_bandwidth = true,
        .max_bandwidth = value,
    };

    qmp_migrate_set_parameters(&p, errp);
}

void qmp_migrate_set_downtime(double value, Error **errp)
{
    if (value < 0 || value > MAX_MIGRATE_DOWNTIME_SECONDS) {
        error_setg(errp, "Parameter 'downtime_limit' expects an integer in "
                         "the range of 0 to %d seconds",
                         MAX_MIGRATE_DOWNTIME_SECONDS);
        return;
    }

    value *= 1000; /* Convert to milliseconds */
    value = MAX(0, MIN(INT64_MAX, value));

    MigrateSetParameters p = {
        .has_downtime_limit = true,
        .downtime_limit = value,
    };

    qmp_migrate_set_parameters(&p, errp);
}

bool migrate_release_ram(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_RELEASE_RAM];
}

bool migrate_postcopy_ram(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_POSTCOPY_RAM];
}

bool migrate_postcopy(void)
{
    return migrate_postcopy_ram() || migrate_dirty_bitmaps();
}

bool migrate_auto_converge(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_AUTO_CONVERGE];
}

bool migrate_zero_blocks(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_ZERO_BLOCKS];
}

bool migrate_postcopy_blocktime(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_POSTCOPY_BLOCKTIME];
}

bool migrate_use_compression(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_COMPRESS];
}

int migrate_compress_level(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.compress_level;
}

int migrate_compress_threads(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.compress_threads;
}

int migrate_compress_wait_thread(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.compress_wait_thread;
}

int migrate_decompress_threads(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.decompress_threads;
}

bool migrate_dirty_bitmaps(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_DIRTY_BITMAPS];
}

bool migrate_ignore_shared(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_X_IGNORE_SHARED];
}

bool migrate_use_events(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_EVENTS];
}

bool migrate_use_multifd(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_MULTIFD];
}

bool migrate_pause_before_switchover(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[
        MIGRATION_CAPABILITY_PAUSE_BEFORE_SWITCHOVER];
}

int migrate_multifd_channels(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.multifd_channels;
}

int migrate_use_xbzrle(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_XBZRLE];
}

int64_t migrate_xbzrle_cache_size(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.xbzrle_cache_size;
}

static int64_t migrate_max_postcopy_bandwidth(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.max_postcopy_bandwidth;
}

bool migrate_use_block(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_BLOCK];
}

bool migrate_use_return_path(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_RETURN_PATH];
}

bool migrate_use_block_incremental(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.block_incremental;
}

/* migration thread support */
/*
 * Something bad happened to the RP stream, mark an error
 * The caller shall print or trace something to indicate why
 */
static void mark_source_rp_bad(MigrationState *s)
{
    s->rp_state.error = true;
}

static struct rp_cmd_args {
    ssize_t     len; /* -1 = variable */
    const char *name;
} rp_cmd_args[] = {
    [MIG_RP_MSG_INVALID]        = { .len = -1, .name = "INVALID" },
    [MIG_RP_MSG_SHUT]           = { .len =  4, .name = "SHUT" },
    [MIG_RP_MSG_PONG]           = { .len =  4, .name = "PONG" },
    [MIG_RP_MSG_REQ_PAGES]      = { .len = 12, .name = "REQ_PAGES" },
    [MIG_RP_MSG_REQ_PAGES_ID]   = { .len = -1, .name = "REQ_PAGES_ID" },
    [MIG_RP_MSG_RECV_BITMAP]    = { .len = -1, .name = "RECV_BITMAP" },
    [MIG_RP_MSG_RESUME_ACK]     = { .len =  4, .name = "RESUME_ACK" },
    [MIG_RP_MSG_MAX]            = { .len = -1, .name = "MAX" },
};

/*
 * Process a request for pages received on the return path,
 * We're allowed to send more than requested (e.g. to round to our page size)
 * and we don't need to send pages that have already been sent.
 */
static void migrate_handle_rp_req_pages(MigrationState *ms, const char* rbname,
                                       ram_addr_t start, size_t len)
{
    long our_host_ps = getpagesize();

    trace_migrate_handle_rp_req_pages(rbname, start, len);

    /*
     * Since we currently insist on matching page sizes, just sanity check
     * we're being asked for whole host pages.
     */
    if (start & (our_host_ps-1) ||
       (len & (our_host_ps-1))) {
        error_report("%s: Misaligned page request, start: " RAM_ADDR_FMT
                     " len: %zd", __func__, start, len);
        mark_source_rp_bad(ms);
        return;
    }

    if (ram_save_queue_pages(rbname, start, len)) {
        mark_source_rp_bad(ms);
    }
}

/* Return true to retry, false to quit */
static bool postcopy_pause_return_path_thread(MigrationState *s)
{
    trace_postcopy_pause_return_path();

    qemu_sem_wait(&s->postcopy_pause_rp_sem);

    trace_postcopy_pause_return_path_continued();

    return true;
}

static int migrate_handle_rp_recv_bitmap(MigrationState *s, char *block_name)
{
    RAMBlock *block = qemu_ram_block_by_name(block_name);

    if (!block) {
        error_report("%s: invalid block name '%s'", __func__, block_name);
        return -EINVAL;
    }

    /* Fetch the received bitmap and refresh the dirty bitmap */
    return ram_dirty_bitmap_reload(s, block);
}

static int migrate_handle_rp_resume_ack(MigrationState *s, uint32_t value)
{
    trace_source_return_path_thread_resume_ack(value);

    if (value != MIGRATION_RESUME_ACK_VALUE) {
        error_report("%s: illegal resume_ack value %"PRIu32,
                     __func__, value);
        return -1;
    }

    /* Now both sides are active. */
    migrate_set_state(&s->state, MIGRATION_STATUS_POSTCOPY_RECOVER,
                      MIGRATION_STATUS_POSTCOPY_ACTIVE);

    /* Notify send thread that time to continue send pages */
    qemu_sem_post(&s->rp_state.rp_sem);

    return 0;
}

/*
 * Handles messages sent on the return path towards the source VM
 *
 */
static void *source_return_path_thread(void *opaque)
{
    MigrationState *ms = opaque;
    QEMUFile *rp = ms->rp_state.from_dst_file;
    uint16_t header_len, header_type;
    uint8_t buf[512];
    uint32_t tmp32, sibling_error;
    ram_addr_t start = 0; /* =0 to silence warning */
    size_t  len = 0, expected_len;
    int res;

    trace_source_return_path_thread_entry();
    rcu_register_thread();

retry:
    while (!ms->rp_state.error && !qemu_file_get_error(rp) &&
           migration_is_setup_or_active(ms->state)) {
        trace_source_return_path_thread_loop_top();
        header_type = qemu_get_be16(rp);
        header_len = qemu_get_be16(rp);

        if (qemu_file_get_error(rp)) {
            mark_source_rp_bad(ms);
            goto out;
        }

        if (header_type >= MIG_RP_MSG_MAX ||
            header_type == MIG_RP_MSG_INVALID) {
            error_report("RP: Received invalid message 0x%04x length 0x%04x",
                    header_type, header_len);
            mark_source_rp_bad(ms);
            goto out;
        }

        if ((rp_cmd_args[header_type].len != -1 &&
            header_len != rp_cmd_args[header_type].len) ||
            header_len > sizeof(buf)) {
            error_report("RP: Received '%s' message (0x%04x) with"
                    "incorrect length %d expecting %zu",
                    rp_cmd_args[header_type].name, header_type, header_len,
                    (size_t)rp_cmd_args[header_type].len);
            mark_source_rp_bad(ms);
            goto out;
        }

        /* We know we've got a valid header by this point */
        res = qemu_get_buffer(rp, buf, header_len);
        if (res != header_len) {
            error_report("RP: Failed reading data for message 0x%04x"
                         " read %d expected %d",
                         header_type, res, header_len);
            mark_source_rp_bad(ms);
            goto out;
        }

        /* OK, we have the message and the data */
        switch (header_type) {
        case MIG_RP_MSG_SHUT:
            sibling_error = ldl_be_p(buf);
            trace_source_return_path_thread_shut(sibling_error);
            if (sibling_error) {
                error_report("RP: Sibling indicated error %d", sibling_error);
                mark_source_rp_bad(ms);
            }
            /*
             * We'll let the main thread deal with closing the RP
             * we could do a shutdown(2) on it, but we're the only user
             * anyway, so there's nothing gained.
             */
            goto out;

        case MIG_RP_MSG_PONG:
            tmp32 = ldl_be_p(buf);
            trace_source_return_path_thread_pong(tmp32);
            break;

        case MIG_RP_MSG_REQ_PAGES:
            start = ldq_be_p(buf);
            len = ldl_be_p(buf + 8);
            migrate_handle_rp_req_pages(ms, NULL, start, len);
            break;

        case MIG_RP_MSG_REQ_PAGES_ID:
            expected_len = 12 + 1; /* header + termination */

            if (header_len >= expected_len) {
                start = ldq_be_p(buf);
                len = ldl_be_p(buf + 8);
                /* Now we expect an idstr */
                tmp32 = buf[12]; /* Length of the following idstr */
                buf[13 + tmp32] = '\0';
                expected_len += tmp32;
            }
            if (header_len != expected_len) {
                error_report("RP: Req_Page_id with length %d expecting %zd",
                        header_len, expected_len);
                mark_source_rp_bad(ms);
                goto out;
            }
            migrate_handle_rp_req_pages(ms, (char *)&buf[13], start, len);
            break;

        case MIG_RP_MSG_RECV_BITMAP:
            if (header_len < 1) {
                error_report("%s: missing block name", __func__);
                mark_source_rp_bad(ms);
                goto out;
            }
            /* Format: len (1B) + idstr (<255B). This ends the idstr. */
            buf[buf[0] + 1] = '\0';
            if (migrate_handle_rp_recv_bitmap(ms, (char *)(buf + 1))) {
                mark_source_rp_bad(ms);
                goto out;
            }
            break;

        case MIG_RP_MSG_RESUME_ACK:
            tmp32 = ldl_be_p(buf);
            if (migrate_handle_rp_resume_ack(ms, tmp32)) {
                mark_source_rp_bad(ms);
                goto out;
            }
            break;

        default:
            break;
        }
    }

out:
    res = qemu_file_get_error(rp);
    if (res) {
        if (res == -EIO) {
            /*
             * Maybe there is something we can do: it looks like a
             * network down issue, and we pause for a recovery.
             */
            if (postcopy_pause_return_path_thread(ms)) {
                /* Reload rp, reset the rest */
                if (rp != ms->rp_state.from_dst_file) {
                    qemu_fclose(rp);
                    rp = ms->rp_state.from_dst_file;
                }
                ms->rp_state.error = false;
                goto retry;
            }
        }

        trace_source_return_path_thread_bad_end();
        mark_source_rp_bad(ms);
    }

    trace_source_return_path_thread_end();
    ms->rp_state.from_dst_file = NULL;
    qemu_fclose(rp);
    rcu_unregister_thread();
    return NULL;
}

static int open_return_path_on_source(MigrationState *ms,
                                      bool create_thread)
{

    ms->rp_state.from_dst_file = qemu_file_get_return_path(ms->to_dst_file);
    if (!ms->rp_state.from_dst_file) {
        return -1;
    }

    trace_open_return_path_on_source();

    if (!create_thread) {
        /* We're done */
        return 0;
    }

    qemu_thread_create(&ms->rp_state.rp_thread, "return path",
                       source_return_path_thread, ms, QEMU_THREAD_JOINABLE);

    trace_open_return_path_on_source_continue();

    return 0;
}

/* Returns 0 if the RP was ok, otherwise there was an error on the RP */
static int await_return_path_close_on_source(MigrationState *ms)
{
    /*
     * If this is a normal exit then the destination will send a SHUT and the
     * rp_thread will exit, however if there's an error we need to cause
     * it to exit.
     */
    if (qemu_file_get_error(ms->to_dst_file) && ms->rp_state.from_dst_file) {
        /*
         * shutdown(2), if we have it, will cause it to unblock if it's stuck
         * waiting for the destination.
         */
        qemu_file_shutdown(ms->rp_state.from_dst_file);
        mark_source_rp_bad(ms);
    }
    trace_await_return_path_close_on_source_joining();
    qemu_thread_join(&ms->rp_state.rp_thread);
    trace_await_return_path_close_on_source_close();
    return ms->rp_state.error;
}

/*
 * Switch from normal iteration to postcopy
 * Returns non-0 on error
 */
static int postcopy_start(MigrationState *ms)
{
    int ret;
    QIOChannelBuffer *bioc;
    QEMUFile *fb;
    int64_t time_at_stop = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    int64_t bandwidth = migrate_max_postcopy_bandwidth();
    bool restart_block = false;
    int cur_state = MIGRATION_STATUS_ACTIVE;
    if (!migrate_pause_before_switchover()) {
        migrate_set_state(&ms->state, MIGRATION_STATUS_ACTIVE,
                          MIGRATION_STATUS_POSTCOPY_ACTIVE);
    }

    trace_postcopy_start();
    qemu_mutex_lock_iothread();
    trace_postcopy_start_set_run();

    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER, NULL);
    global_state_store();
    ret = vm_stop_force_state(RUN_STATE_FINISH_MIGRATE);
    if (ret < 0) {
        goto fail;
    }

    ret = migration_maybe_pause(ms, &cur_state,
                                MIGRATION_STATUS_POSTCOPY_ACTIVE);
    if (ret < 0) {
        goto fail;
    }

    ret = bdrv_inactivate_all();
    if (ret < 0) {
        goto fail;
    }
    restart_block = true;

    /*
     * Cause any non-postcopiable, but iterative devices to
     * send out their final data.
     */
    qemu_savevm_state_complete_precopy(ms->to_dst_file, true, false);

    /*
     * in Finish migrate and with the io-lock held everything should
     * be quiet, but we've potentially still got dirty pages and we
     * need to tell the destination to throw any pages it's already received
     * that are dirty
     */
    if (migrate_postcopy_ram()) {
        if (ram_postcopy_send_discard_bitmap(ms)) {
            error_report("postcopy send discard bitmap failed");
            goto fail;
        }
    }

    /*
     * send rest of state - note things that are doing postcopy
     * will notice we're in POSTCOPY_ACTIVE and not actually
     * wrap their state up here
     */
    /* 0 max-postcopy-bandwidth means unlimited */
    if (!bandwidth) {
        qemu_file_set_rate_limit(ms->to_dst_file, INT64_MAX);
    } else {
        qemu_file_set_rate_limit(ms->to_dst_file, bandwidth / XFER_LIMIT_RATIO);
    }
    if (migrate_postcopy_ram()) {
        /* Ping just for debugging, helps line traces up */
        qemu_savevm_send_ping(ms->to_dst_file, 2);
    }

    /*
     * While loading the device state we may trigger page transfer
     * requests and the fd must be free to process those, and thus
     * the destination must read the whole device state off the fd before
     * it starts processing it.  Unfortunately the ad-hoc migration format
     * doesn't allow the destination to know the size to read without fully
     * parsing it through each devices load-state code (especially the open
     * coded devices that use get/put).
     * So we wrap the device state up in a package with a length at the start;
     * to do this we use a qemu_buf to hold the whole of the device state.
     */
    bioc = qio_channel_buffer_new(4096);
    qio_channel_set_name(QIO_CHANNEL(bioc), "migration-postcopy-buffer");
    fb = qemu_fopen_channel_output(QIO_CHANNEL(bioc));
    object_unref(OBJECT(bioc));

    /*
     * Make sure the receiver can get incoming pages before we send the rest
     * of the state
     */
    qemu_savevm_send_postcopy_listen(fb);

    qemu_savevm_state_complete_precopy(fb, false, false);
    if (migrate_postcopy_ram()) {
        qemu_savevm_send_ping(fb, 3);
    }

    qemu_savevm_send_postcopy_run(fb);

    /* <><> end of stuff going into the package */

    /* Last point of recovery; as soon as we send the package the destination
     * can open devices and potentially start running.
     * Lets just check again we've not got any errors.
     */
    ret = qemu_file_get_error(ms->to_dst_file);
    if (ret) {
        error_report("postcopy_start: Migration stream errored (pre package)");
        goto fail_closefb;
    }

    restart_block = false;

    /* Now send that blob */
    if (qemu_savevm_send_packaged(ms->to_dst_file, bioc->data, bioc->usage)) {
        goto fail_closefb;
    }
    qemu_fclose(fb);

    /* Send a notify to give a chance for anything that needs to happen
     * at the transition to postcopy and after the device state; in particular
     * spice needs to trigger a transition now
     */
    ms->postcopy_after_devices = true;
    notifier_list_notify(&migration_state_notifiers, ms);

    ms->downtime =  qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - time_at_stop;

    qemu_mutex_unlock_iothread();

    if (migrate_postcopy_ram()) {
        /*
         * Although this ping is just for debug, it could potentially be
         * used for getting a better measurement of downtime at the source.
         */
        qemu_savevm_send_ping(ms->to_dst_file, 4);
    }

    if (migrate_release_ram()) {
        ram_postcopy_migrated_memory_release(ms);
    }

    ret = qemu_file_get_error(ms->to_dst_file);
    if (ret) {
        error_report("postcopy_start: Migration stream errored");
        migrate_set_state(&ms->state, MIGRATION_STATUS_POSTCOPY_ACTIVE,
                              MIGRATION_STATUS_FAILED);
    }

    return ret;

fail_closefb:
    qemu_fclose(fb);
fail:
    migrate_set_state(&ms->state, MIGRATION_STATUS_POSTCOPY_ACTIVE,
                          MIGRATION_STATUS_FAILED);
    if (restart_block) {
        /* A failure happened early enough that we know the destination hasn't
         * accessed block devices, so we're safe to recover.
         */
        Error *local_err = NULL;

        bdrv_invalidate_cache_all(&local_err);
        if (local_err) {
            error_report_err(local_err);
        }
    }
    qemu_mutex_unlock_iothread();
    return -1;
}

/**
 * migration_maybe_pause: Pause if required to by
 * migrate_pause_before_switchover called with the iothread locked
 * Returns: 0 on success
 */
static int migration_maybe_pause(MigrationState *s,
                                 int *current_active_state,
                                 int new_state)
{
    if (!migrate_pause_before_switchover()) {
        return 0;
    }

    /* Since leaving this state is not atomic with posting the semaphore
     * it's possible that someone could have issued multiple migrate_continue
     * and the semaphore is incorrectly positive at this point;
     * the docs say it's undefined to reinit a semaphore that's already
     * init'd, so use timedwait to eat up any existing posts.
     */
    while (qemu_sem_timedwait(&s->pause_sem, 1) == 0) {
        /* This block intentionally left blank */
    }

    qemu_mutex_unlock_iothread();
    migrate_set_state(&s->state, *current_active_state,
                      MIGRATION_STATUS_PRE_SWITCHOVER);
    qemu_sem_wait(&s->pause_sem);
    migrate_set_state(&s->state, MIGRATION_STATUS_PRE_SWITCHOVER,
                      new_state);
    *current_active_state = new_state;
    qemu_mutex_lock_iothread();

    return s->state == new_state ? 0 : -EINVAL;
}

/**
 * migration_completion: Used by migration_thread when there's not much left.
 *   The caller 'breaks' the loop when this returns.
 *
 * @s: Current migration state
 */
static void migration_completion(MigrationState *s)
{
    int ret;
    int current_active_state = s->state;

    if (s->state == MIGRATION_STATUS_ACTIVE) {
        qemu_mutex_lock_iothread();
        s->downtime_start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER, NULL);
        s->vm_was_running = runstate_is_running();
        ret = global_state_store();

        if (!ret) {
            bool inactivate = !migrate_colo_enabled();
            ret = vm_stop_force_state(RUN_STATE_FINISH_MIGRATE);
            if (ret >= 0) {
                ret = migration_maybe_pause(s, &current_active_state,
                                            MIGRATION_STATUS_DEVICE);
            }
            if (ret >= 0) {
                qemu_file_set_rate_limit(s->to_dst_file, INT64_MAX);
                ret = qemu_savevm_state_complete_precopy(s->to_dst_file, false,
                                                         inactivate);
            }
            if (inactivate && ret >= 0) {
                s->block_inactive = true;
            }
        }
        qemu_mutex_unlock_iothread();

        if (ret < 0) {
            goto fail;
        }
    } else if (s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE) {
        trace_migration_completion_postcopy_end();

        qemu_savevm_state_complete_postcopy(s->to_dst_file);
        trace_migration_completion_postcopy_end_after_complete();
    }

    /*
     * If rp was opened we must clean up the thread before
     * cleaning everything else up (since if there are no failures
     * it will wait for the destination to send it's status in
     * a SHUT command).
     */
    if (s->rp_state.from_dst_file) {
        int rp_error;
        trace_migration_return_path_end_before();
        rp_error = await_return_path_close_on_source(s);
        trace_migration_return_path_end_after(rp_error);
        if (rp_error) {
            goto fail_invalidate;
        }
    }

    if (qemu_file_get_error(s->to_dst_file)) {
        trace_migration_completion_file_err();
        goto fail_invalidate;
    }

    if (!migrate_colo_enabled()) {
        migrate_set_state(&s->state, current_active_state,
                          MIGRATION_STATUS_COMPLETED);
    }

    return;

fail_invalidate:
    /* If not doing postcopy, vm_start() will be called: let's regain
     * control on images.
     */
    if (s->state == MIGRATION_STATUS_ACTIVE ||
        s->state == MIGRATION_STATUS_DEVICE) {
        Error *local_err = NULL;

        qemu_mutex_lock_iothread();
        bdrv_invalidate_cache_all(&local_err);
        if (local_err) {
            error_report_err(local_err);
        } else {
            s->block_inactive = false;
        }
        qemu_mutex_unlock_iothread();
    }

fail:
    migrate_set_state(&s->state, current_active_state,
                      MIGRATION_STATUS_FAILED);
}

bool migrate_colo_enabled(void)
{
    MigrationState *s = migrate_get_current();
    return s->enabled_capabilities[MIGRATION_CAPABILITY_X_COLO];
}

typedef enum MigThrError {
    /* No error detected */
    MIG_THR_ERR_NONE = 0,
    /* Detected error, but resumed successfully */
    MIG_THR_ERR_RECOVERED = 1,
    /* Detected fatal error, need to exit */
    MIG_THR_ERR_FATAL = 2,
} MigThrError;

static int postcopy_resume_handshake(MigrationState *s)
{
    qemu_savevm_send_postcopy_resume(s->to_dst_file);

    while (s->state == MIGRATION_STATUS_POSTCOPY_RECOVER) {
        qemu_sem_wait(&s->rp_state.rp_sem);
    }

    if (s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE) {
        return 0;
    }

    return -1;
}

/* Return zero if success, or <0 for error */
static int postcopy_do_resume(MigrationState *s)
{
    int ret;

    /*
     * Call all the resume_prepare() hooks, so that modules can be
     * ready for the migration resume.
     */
    ret = qemu_savevm_state_resume_prepare(s);
    if (ret) {
        error_report("%s: resume_prepare() failure detected: %d",
                     __func__, ret);
        return ret;
    }

    /*
     * Last handshake with destination on the resume (destination will
     * switch to postcopy-active afterwards)
     */
    ret = postcopy_resume_handshake(s);
    if (ret) {
        error_report("%s: handshake failed: %d", __func__, ret);
        return ret;
    }

    return 0;
}

/*
 * We don't return until we are in a safe state to continue current
 * postcopy migration.  Returns MIG_THR_ERR_RECOVERED if recovered, or
 * MIG_THR_ERR_FATAL if unrecovery failure happened.
 */
static MigThrError postcopy_pause(MigrationState *s)
{
    assert(s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE);

    while (true) {
        QEMUFile *file;

        migrate_set_state(&s->state, s->state,
                          MIGRATION_STATUS_POSTCOPY_PAUSED);

        /* Current channel is possibly broken. Release it. */
        assert(s->to_dst_file);
        qemu_mutex_lock(&s->qemu_file_lock);
        file = s->to_dst_file;
        s->to_dst_file = NULL;
        qemu_mutex_unlock(&s->qemu_file_lock);

        qemu_file_shutdown(file);
        qemu_fclose(file);

        error_report("Detected IO failure for postcopy. "
                     "Migration paused.");

        /*
         * We wait until things fixed up. Then someone will setup the
         * status back for us.
         */
        while (s->state == MIGRATION_STATUS_POSTCOPY_PAUSED) {
            qemu_sem_wait(&s->postcopy_pause_sem);
        }

        if (s->state == MIGRATION_STATUS_POSTCOPY_RECOVER) {
            /* Woken up by a recover procedure. Give it a shot */

            /*
             * Firstly, let's wake up the return path now, with a new
             * return path channel.
             */
            qemu_sem_post(&s->postcopy_pause_rp_sem);

            /* Do the resume logic */
            if (postcopy_do_resume(s) == 0) {
                /* Let's continue! */
                trace_postcopy_pause_continued();
                return MIG_THR_ERR_RECOVERED;
            } else {
                /*
                 * Something wrong happened during the recovery, let's
                 * pause again. Pause is always better than throwing
                 * data away.
                 */
                continue;
            }
        } else {
            /* This is not right... Time to quit. */
            return MIG_THR_ERR_FATAL;
        }
    }
}

static MigThrError migration_detect_error(MigrationState *s)
{
    int ret;
    int state = s->state;

    if (state == MIGRATION_STATUS_CANCELLING ||
        state == MIGRATION_STATUS_CANCELLED) {
        /* End the migration, but don't set the state to failed */
        return MIG_THR_ERR_FATAL;
    }

    /* Try to detect any file errors */
    ret = qemu_file_get_error(s->to_dst_file);

    if (!ret) {
        /* Everything is fine */
        return MIG_THR_ERR_NONE;
    }

    if (state == MIGRATION_STATUS_POSTCOPY_ACTIVE && ret == -EIO) {
        /*
         * For postcopy, we allow the network to be down for a
         * while. After that, it can be continued by a
         * recovery phase.
         */
        return postcopy_pause(s);
    } else {
        /*
         * For precopy (or postcopy with error outside IO), we fail
         * with no time.
         */
        migrate_set_state(&s->state, state, MIGRATION_STATUS_FAILED);
        trace_migration_thread_file_err();

        /* Time to stop the migration, now. */
        return MIG_THR_ERR_FATAL;
    }
}

/* How many bytes have we transferred since the beggining of the migration */
static uint64_t migration_total_bytes(MigrationState *s)
{
    return qemu_ftell(s->to_dst_file) + ram_counters.multifd_bytes;
}

static void migration_calculate_complete(MigrationState *s)
{
    uint64_t bytes = migration_total_bytes(s);
    int64_t end_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    int64_t transfer_time;

    s->total_time = end_time - s->start_time;
    if (!s->downtime) {
        /*
         * It's still not set, so we are precopy migration.  For
         * postcopy, downtime is calculated during postcopy_start().
         */
        s->downtime = end_time - s->downtime_start;
    }

    transfer_time = s->total_time - s->setup_time;
    if (transfer_time) {
        s->mbps = ((double) bytes * 8.0) / transfer_time / 1000;
    }
}

static void migration_update_counters(MigrationState *s,
                                      int64_t current_time)
{
    uint64_t transferred, transferred_pages, time_spent;
    uint64_t current_bytes; /* bytes transferred since the beginning */
    double bandwidth;

    if (current_time < s->iteration_start_time + BUFFER_DELAY) {
        return;
    }

    current_bytes = migration_total_bytes(s);
    transferred = current_bytes - s->iteration_initial_bytes;
    time_spent = current_time - s->iteration_start_time;
    bandwidth = (double)transferred / time_spent;
    s->threshold_size = bandwidth * s->parameters.downtime_limit;

    s->mbps = (((double) transferred * 8.0) /
               ((double) time_spent / 1000.0)) / 1000.0 / 1000.0;

    transferred_pages = ram_get_total_transferred_pages() -
                            s->iteration_initial_pages;
    s->pages_per_second = (double) transferred_pages /
                             (((double) time_spent / 1000.0));

    /*
     * if we haven't sent anything, we don't want to
     * recalculate. 10000 is a small enough number for our purposes
     */
    if (ram_counters.dirty_pages_rate && transferred > 10000) {
        s->expected_downtime = ram_counters.remaining / bandwidth;
    }

    qemu_file_reset_rate_limit(s->to_dst_file);

    s->iteration_start_time = current_time;
    s->iteration_initial_bytes = current_bytes;
    s->iteration_initial_pages = ram_get_total_transferred_pages();

    trace_migrate_transferred(transferred, time_spent,
                              bandwidth, s->threshold_size);
}

/* Migration thread iteration status */
typedef enum {
    MIG_ITERATE_RESUME,         /* Resume current iteration */
    MIG_ITERATE_SKIP,           /* Skip current iteration */
    MIG_ITERATE_BREAK,          /* Break the loop */
} MigIterateState;

/*
 * Return true if continue to the next iteration directly, false
 * otherwise.
 */
static MigIterateState migration_iteration_run(MigrationState *s)
{
    uint64_t pending_size, pend_pre, pend_compat, pend_post;
    bool in_postcopy = s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE;

    qemu_savevm_state_pending(s->to_dst_file, s->threshold_size, &pend_pre,
                              &pend_compat, &pend_post);
    pending_size = pend_pre + pend_compat + pend_post;

    trace_migrate_pending(pending_size, s->threshold_size,
                          pend_pre, pend_compat, pend_post);

    if (pending_size && pending_size >= s->threshold_size) {
        /* Still a significant amount to transfer */
        if (migrate_postcopy() && !in_postcopy &&
            pend_pre <= s->threshold_size &&
            atomic_read(&s->start_postcopy)) {
            if (postcopy_start(s)) {
                error_report("%s: postcopy failed to start", __func__);
            }
            return MIG_ITERATE_SKIP;
        }
        /* Just another iteration step */
        qemu_savevm_state_iterate(s->to_dst_file,
            s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE);
    } else {
        trace_migration_thread_low_pending(pending_size);
        migration_completion(s);
        return MIG_ITERATE_BREAK;
    }

    return MIG_ITERATE_RESUME;
}

static void migration_iteration_finish(MigrationState *s)
{
    /* If we enabled cpu throttling for auto-converge, turn it off. */
    cpu_throttle_stop();

    qemu_mutex_lock_iothread();
    switch (s->state) {
    case MIGRATION_STATUS_COMPLETED:
        migration_calculate_complete(s);
        runstate_set(RUN_STATE_POSTMIGRATE);
        break;

    case MIGRATION_STATUS_ACTIVE:
        /*
         * We should really assert here, but since it's during
         * migration, let's try to reduce the usage of assertions.
         */
        if (!migrate_colo_enabled()) {
            error_report("%s: critical error: calling COLO code without "
                         "COLO enabled", __func__);
        }
        migrate_start_colo_process(s);
        /*
         * Fixme: we will run VM in COLO no matter its old running state.
         * After exited COLO, we will keep running.
         */
        s->vm_was_running = true;
        /* Fallthrough */
    case MIGRATION_STATUS_FAILED:
    case MIGRATION_STATUS_CANCELLED:
    case MIGRATION_STATUS_CANCELLING:
        if (s->vm_was_running) {
            vm_start();
        } else {
            if (runstate_check(RUN_STATE_FINISH_MIGRATE)) {
                runstate_set(RUN_STATE_POSTMIGRATE);
            }
        }
        break;

    default:
        /* Should not reach here, but if so, forgive the VM. */
        error_report("%s: Unknown ending state %d", __func__, s->state);
        break;
    }
    qemu_bh_schedule(s->cleanup_bh);
    qemu_mutex_unlock_iothread();
}

void migration_make_urgent_request(void)
{
    qemu_sem_post(&migrate_get_current()->rate_limit_sem);
}

void migration_consume_urgent_request(void)
{
    qemu_sem_wait(&migrate_get_current()->rate_limit_sem);
}

/*
 * Master migration thread on the source VM.
 * It drives the migration and pumps the data down the outgoing channel.
 */
static void *migration_thread(void *opaque)
{
    MigrationState *s = opaque;
    int64_t setup_start = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    MigThrError thr_error;
    bool urgent = false;

    rcu_register_thread();

    object_ref(OBJECT(s));
    s->iteration_start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    qemu_savevm_state_header(s->to_dst_file);

    /*
     * If we opened the return path, we need to make sure dst has it
     * opened as well.
     */
    if (s->rp_state.from_dst_file) {
        /* Now tell the dest that it should open its end so it can reply */
        qemu_savevm_send_open_return_path(s->to_dst_file);

        /* And do a ping that will make stuff easier to debug */
        qemu_savevm_send_ping(s->to_dst_file, 1);
    }

    if (migrate_postcopy()) {
        /*
         * Tell the destination that we *might* want to do postcopy later;
         * if the other end can't do postcopy it should fail now, nice and
         * early.
         */
        qemu_savevm_send_postcopy_advise(s->to_dst_file);
    }

    if (migrate_colo_enabled()) {
        /* Notify migration destination that we enable COLO */
        qemu_savevm_send_colo_enable(s->to_dst_file);
    }

    qemu_savevm_state_setup(s->to_dst_file);

    s->setup_time = qemu_clock_get_ms(QEMU_CLOCK_HOST) - setup_start;
    migrate_set_state(&s->state, MIGRATION_STATUS_SETUP,
                      MIGRATION_STATUS_ACTIVE);

    trace_migration_thread_setup_complete();

    while (s->state == MIGRATION_STATUS_ACTIVE ||
           s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE) {
        int64_t current_time;

        if (urgent || !qemu_file_rate_limit(s->to_dst_file)) {
            MigIterateState iter_state = migration_iteration_run(s);
            if (iter_state == MIG_ITERATE_SKIP) {
                continue;
            } else if (iter_state == MIG_ITERATE_BREAK) {
                break;
            }
        }

        /*
         * Try to detect any kind of failures, and see whether we
         * should stop the migration now.
         */
        thr_error = migration_detect_error(s);
        if (thr_error == MIG_THR_ERR_FATAL) {
            /* Stop migration */
            break;
        } else if (thr_error == MIG_THR_ERR_RECOVERED) {
            /*
             * Just recovered from a e.g. network failure, reset all
             * the local variables. This is important to avoid
             * breaking transferred_bytes and bandwidth calculation
             */
            s->iteration_start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
            s->iteration_initial_bytes = 0;
        }

        current_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

        migration_update_counters(s, current_time);

        urgent = false;
        if (qemu_file_rate_limit(s->to_dst_file)) {
            /* Wait for a delay to do rate limiting OR
             * something urgent to post the semaphore.
             */
            int ms = s->iteration_start_time + BUFFER_DELAY - current_time;
            trace_migration_thread_ratelimit_pre(ms);
            if (qemu_sem_timedwait(&s->rate_limit_sem, ms) == 0) {
                /* We were worken by one or more urgent things but
                 * the timedwait will have consumed one of them.
                 * The service routine for the urgent wake will dec
                 * the semaphore itself for each item it consumes,
                 * so add this one we just eat back.
                 */
                qemu_sem_post(&s->rate_limit_sem);
                urgent = true;
            }
            trace_migration_thread_ratelimit_post(urgent);
        }
    }

    trace_migration_thread_after_loop();
    migration_iteration_finish(s);
    object_unref(OBJECT(s));
    rcu_unregister_thread();
    return NULL;
}

void migrate_fd_connect(MigrationState *s, Error *error_in)
{
    int64_t rate_limit;
    bool resume = s->state == MIGRATION_STATUS_POSTCOPY_PAUSED;

    s->expected_downtime = s->parameters.downtime_limit;
    s->cleanup_bh = qemu_bh_new(migrate_fd_cleanup, s);
    if (error_in) {
        migrate_fd_error(s, error_in);
        migrate_fd_cleanup(s);
        return;
    }

    if (resume) {
        /* This is a resumed migration */
        rate_limit = INT64_MAX;
    } else {
        /* This is a fresh new migration */
        rate_limit = s->parameters.max_bandwidth / XFER_LIMIT_RATIO;

        /* Notify before starting migration thread */
        notifier_list_notify(&migration_state_notifiers, s);
    }

    qemu_file_set_rate_limit(s->to_dst_file, rate_limit);
    qemu_file_set_blocking(s->to_dst_file, true);

    /*
     * Open the return path. For postcopy, it is used exclusively. For
     * precopy, only if user specified "return-path" capability would
     * QEMU uses the return path.
     */
    if (migrate_postcopy_ram() || migrate_use_return_path()) {
        if (open_return_path_on_source(s, !resume)) {
            error_report("Unable to open return-path for postcopy");
            migrate_set_state(&s->state, s->state, MIGRATION_STATUS_FAILED);
            migrate_fd_cleanup(s);
            return;
        }
    }

    if (resume) {
        /* Wakeup the main migration thread to do the recovery */
        migrate_set_state(&s->state, MIGRATION_STATUS_POSTCOPY_PAUSED,
                          MIGRATION_STATUS_POSTCOPY_RECOVER);
        qemu_sem_post(&s->postcopy_pause_sem);
        return;
    }

    if (multifd_save_setup() != 0) {
        migrate_set_state(&s->state, MIGRATION_STATUS_SETUP,
                          MIGRATION_STATUS_FAILED);
        migrate_fd_cleanup(s);
        return;
    }
    qemu_thread_create(&s->thread, "live_migration", migration_thread, s,
                       QEMU_THREAD_JOINABLE);
    s->migration_thread_running = true;
}

void migration_global_dump(Monitor *mon)
{
    MigrationState *ms = migrate_get_current();

    monitor_printf(mon, "globals:\n");
    monitor_printf(mon, "store-global-state: %s\n",
                   ms->store_global_state ? "on" : "off");
    monitor_printf(mon, "only-migratable: %s\n",
                   only_migratable ? "on" : "off");
    monitor_printf(mon, "send-configuration: %s\n",
                   ms->send_configuration ? "on" : "off");
    monitor_printf(mon, "send-section-footer: %s\n",
                   ms->send_section_footer ? "on" : "off");
    monitor_printf(mon, "decompress-error-check: %s\n",
                   ms->decompress_error_check ? "on" : "off");
}

#define DEFINE_PROP_MIG_CAP(name, x)             \
    DEFINE_PROP_BOOL(name, MigrationState, enabled_capabilities[x], false)

static Property migration_properties[] = {
    DEFINE_PROP_BOOL("store-global-state", MigrationState,
                     store_global_state, true),
    DEFINE_PROP_BOOL("send-configuration", MigrationState,
                     send_configuration, true),
    DEFINE_PROP_BOOL("send-section-footer", MigrationState,
                     send_section_footer, true),
    DEFINE_PROP_BOOL("decompress-error-check", MigrationState,
                      decompress_error_check, true),

    /* Migration parameters */
    DEFINE_PROP_UINT8("x-compress-level", MigrationState,
                      parameters.compress_level,
                      DEFAULT_MIGRATE_COMPRESS_LEVEL),
    DEFINE_PROP_UINT8("x-compress-threads", MigrationState,
                      parameters.compress_threads,
                      DEFAULT_MIGRATE_COMPRESS_THREAD_COUNT),
    DEFINE_PROP_BOOL("x-compress-wait-thread", MigrationState,
                      parameters.compress_wait_thread, true),
    DEFINE_PROP_UINT8("x-decompress-threads", MigrationState,
                      parameters.decompress_threads,
                      DEFAULT_MIGRATE_DECOMPRESS_THREAD_COUNT),
    DEFINE_PROP_UINT8("x-cpu-throttle-initial", MigrationState,
                      parameters.cpu_throttle_initial,
                      DEFAULT_MIGRATE_CPU_THROTTLE_INITIAL),
    DEFINE_PROP_UINT8("x-cpu-throttle-increment", MigrationState,
                      parameters.cpu_throttle_increment,
                      DEFAULT_MIGRATE_CPU_THROTTLE_INCREMENT),
    DEFINE_PROP_SIZE("x-max-bandwidth", MigrationState,
                      parameters.max_bandwidth, MAX_THROTTLE),
    DEFINE_PROP_UINT64("x-downtime-limit", MigrationState,
                      parameters.downtime_limit,
                      DEFAULT_MIGRATE_SET_DOWNTIME),
    DEFINE_PROP_UINT32("x-checkpoint-delay", MigrationState,
                      parameters.x_checkpoint_delay,
                      DEFAULT_MIGRATE_X_CHECKPOINT_DELAY),
    DEFINE_PROP_UINT8("multifd-channels", MigrationState,
                      parameters.multifd_channels,
                      DEFAULT_MIGRATE_MULTIFD_CHANNELS),
    DEFINE_PROP_SIZE("xbzrle-cache-size", MigrationState,
                      parameters.xbzrle_cache_size,
                      DEFAULT_MIGRATE_XBZRLE_CACHE_SIZE),
    DEFINE_PROP_SIZE("max-postcopy-bandwidth", MigrationState,
                      parameters.max_postcopy_bandwidth,
                      DEFAULT_MIGRATE_MAX_POSTCOPY_BANDWIDTH),
    DEFINE_PROP_UINT8("max-cpu-throttle", MigrationState,
                      parameters.max_cpu_throttle,
                      DEFAULT_MIGRATE_MAX_CPU_THROTTLE),
    DEFINE_PROP_SIZE("announce-initial", MigrationState,
                      parameters.announce_initial,
                      DEFAULT_MIGRATE_ANNOUNCE_INITIAL),
    DEFINE_PROP_SIZE("announce-max", MigrationState,
                      parameters.announce_max,
                      DEFAULT_MIGRATE_ANNOUNCE_MAX),
    DEFINE_PROP_SIZE("announce-rounds", MigrationState,
                      parameters.announce_rounds,
                      DEFAULT_MIGRATE_ANNOUNCE_ROUNDS),
    DEFINE_PROP_SIZE("announce-step", MigrationState,
                      parameters.announce_step,
                      DEFAULT_MIGRATE_ANNOUNCE_STEP),

    /* Migration capabilities */
    DEFINE_PROP_MIG_CAP("x-xbzrle", MIGRATION_CAPABILITY_XBZRLE),
    DEFINE_PROP_MIG_CAP("x-rdma-pin-all", MIGRATION_CAPABILITY_RDMA_PIN_ALL),
    DEFINE_PROP_MIG_CAP("x-auto-converge", MIGRATION_CAPABILITY_AUTO_CONVERGE),
    DEFINE_PROP_MIG_CAP("x-zero-blocks", MIGRATION_CAPABILITY_ZERO_BLOCKS),
    DEFINE_PROP_MIG_CAP("x-compress", MIGRATION_CAPABILITY_COMPRESS),
    DEFINE_PROP_MIG_CAP("x-events", MIGRATION_CAPABILITY_EVENTS),
    DEFINE_PROP_MIG_CAP("x-postcopy-ram", MIGRATION_CAPABILITY_POSTCOPY_RAM),
    DEFINE_PROP_MIG_CAP("x-colo", MIGRATION_CAPABILITY_X_COLO),
    DEFINE_PROP_MIG_CAP("x-release-ram", MIGRATION_CAPABILITY_RELEASE_RAM),
    DEFINE_PROP_MIG_CAP("x-block", MIGRATION_CAPABILITY_BLOCK),
    DEFINE_PROP_MIG_CAP("x-return-path", MIGRATION_CAPABILITY_RETURN_PATH),
    DEFINE_PROP_MIG_CAP("x-multifd", MIGRATION_CAPABILITY_MULTIFD),

    DEFINE_PROP_END_OF_LIST(),
};

static void migration_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->user_creatable = false;
    dc->props = migration_properties;
}

static void migration_instance_finalize(Object *obj)
{
    MigrationState *ms = MIGRATION_OBJ(obj);
    MigrationParameters *params = &ms->parameters;

    qemu_mutex_destroy(&ms->error_mutex);
    qemu_mutex_destroy(&ms->qemu_file_lock);
    g_free(params->tls_hostname);
    g_free(params->tls_creds);
    qemu_sem_destroy(&ms->rate_limit_sem);
    qemu_sem_destroy(&ms->pause_sem);
    qemu_sem_destroy(&ms->postcopy_pause_sem);
    qemu_sem_destroy(&ms->postcopy_pause_rp_sem);
    qemu_sem_destroy(&ms->rp_state.rp_sem);
    error_free(ms->error);
}

static void migration_instance_init(Object *obj)
{
    MigrationState *ms = MIGRATION_OBJ(obj);
    MigrationParameters *params = &ms->parameters;

    ms->state = MIGRATION_STATUS_NONE;
    ms->mbps = -1;
    ms->pages_per_second = -1;
    qemu_sem_init(&ms->pause_sem, 0);
    qemu_mutex_init(&ms->error_mutex);

    params->tls_hostname = g_strdup("");
    params->tls_creds = g_strdup("");

    /* Set has_* up only for parameter checks */
    params->has_compress_level = true;
    params->has_compress_threads = true;
    params->has_decompress_threads = true;
    params->has_cpu_throttle_initial = true;
    params->has_cpu_throttle_increment = true;
    params->has_max_bandwidth = true;
    params->has_downtime_limit = true;
    params->has_x_checkpoint_delay = true;
    params->has_block_incremental = true;
    params->has_multifd_channels = true;
    params->has_xbzrle_cache_size = true;
    params->has_max_postcopy_bandwidth = true;
    params->has_max_cpu_throttle = true;
    params->has_announce_initial = true;
    params->has_announce_max = true;
    params->has_announce_rounds = true;
    params->has_announce_step = true;

    qemu_sem_init(&ms->postcopy_pause_sem, 0);
    qemu_sem_init(&ms->postcopy_pause_rp_sem, 0);
    qemu_sem_init(&ms->rp_state.rp_sem, 0);
    qemu_sem_init(&ms->rate_limit_sem, 0);
    qemu_mutex_init(&ms->qemu_file_lock);
}

/*
 * Return true if check pass, false otherwise. Error will be put
 * inside errp if provided.
 */
static bool migration_object_check(MigrationState *ms, Error **errp)
{
    MigrationCapabilityStatusList *head = NULL;
    /* Assuming all off */
    bool cap_list[MIGRATION_CAPABILITY__MAX] = { 0 }, ret;
    int i;

    if (!migrate_params_check(&ms->parameters, errp)) {
        return false;
    }

    for (i = 0; i < MIGRATION_CAPABILITY__MAX; i++) {
        if (ms->enabled_capabilities[i]) {
            head = migrate_cap_add(head, i, true);
        }
    }

    ret = migrate_caps_check(cap_list, head, errp);

    /* It works with head == NULL */
    qapi_free_MigrationCapabilityStatusList(head);

    return ret;
}

static const TypeInfo migration_type = {
    .name = TYPE_MIGRATION,
    /*
     * NOTE: TYPE_MIGRATION is not really a device, as the object is
     * not created using qdev_create(), it is not attached to the qdev
     * device tree, and it is never realized.
     *
     * TODO: Make this TYPE_OBJECT once QOM provides something like
     * TYPE_DEVICE's "-global" properties.
     */
    .parent = TYPE_DEVICE,
    .class_init = migration_class_init,
    .class_size = sizeof(MigrationClass),
    .instance_size = sizeof(MigrationState),
    .instance_init = migration_instance_init,
    .instance_finalize = migration_instance_finalize,
};

static void register_migration_types(void)
{
    type_register_static(&migration_type);
}

type_init(register_migration_types);
