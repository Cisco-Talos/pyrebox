/*
 * libslirp - a general purpose TCP-IP emulator
 * Copyright (C) 2016 Renzo Davoli VirtualSquare
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <include/libslirp.h>
#include <slirp.h>
#undef slirp_send

#define MAXMTU 4096
#define APPSIDE 0
#define DAEMONSIDE 1
static int slirpdaemonfd[2];
static pthread_t slirpdaemon_tid;

struct slirp_init_data {
	uint32_t flags;
	struct in_addr vhost;
	int prefix;
	struct in6_addr vhost6;
	int prefix6;
	char *vhostname;
	char *tftp_path;
	char *bootfile;
	struct in_addr vdhcp_start;
	struct in_addr vnameserver;
	struct in6_addr vnameserver6;
	char **vdnssearch;
};

struct slirp_conn;
struct slirp {
	struct slirp_init_data *init_data;
	int channel[2];
	struct slirp_conn *slirp_conn;
};

struct slirp_conn {
	Slirp *slirp;
	int outfd;
};

#define SLIRP_ADD_FWD 0x11
#define SLIRP_DEL_FWD 0x12
#define SLIRP_ADD_UNIXFWD 0x21
#define SLIRP_DEL_UNIXFWD 0x22
#define SLIRP_ADD_EXEC 0x31

struct slirp_request {
	int tag;
	int pipefd[2];
	int intarg;
	const void *ptrarg;
	struct in_addr host_addr;
	int host_port;
	struct in_addr guest_addr;
	int guest_port;
};

SLIRP *slirp_open(uint32_t flags) {
	SLIRP *rval = malloc(sizeof(struct slirp));
	if (rval == NULL)
		goto rval_err;
	rval->init_data = calloc(1,sizeof(struct slirp_init_data));
	if (rval->init_data == NULL)
		goto init_data_err;
	if (socketpair(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0, rval->channel) < 0)
		goto socketpair_err;
	/* default values */
	if ((flags & (SLIRP_IPV4 | SLIRP_IPV6)) == 0)
		flags |= SLIRP_IPV4;
	rval->init_data->flags = flags;
	inet_pton(AF_INET,"10.0.2.2", &(rval->init_data->vhost));
	rval->init_data->prefix = 24;
	inet_pton(AF_INET,"10.0.2.3", &(rval->init_data->vnameserver));
	inet_pton(AF_INET,"10.0.2.15", &(rval->init_data->vdhcp_start));
	inet_pton(AF_INET6,"fe80::2", &(rval->init_data->vhost6));
	inet_pton(AF_INET6,"fe80::3", &(rval->init_data->vnameserver6));
	rval->init_data->prefix6 = 64;
	return rval;

socketpair_err:
	free(rval->init_data);
init_data_err:
	free(rval);
rval_err:
	return NULL;
}

static char **dup_array(char **v) {
	size_t size,i;
	char **rval;
	for (size=0; v[size] != 0; size++);
	rval = malloc((size + 1) * sizeof(char *));
	if (rval) {
		for (i=0; i < size; i++)
			rval[i] = strdup(v[i]);
		rval[i] = NULL;
	}
	return rval;
}

static void free_array(char **v) {
	char **scan;
	for (scan = v; *scan != NULL; scan++)
		free(*scan);
	free(v);
}

static void free_init_data(SLIRP *slirp) {
	struct slirp_init_data *data = slirp->init_data;
	if (data) {
		if (data->vhostname) free(data->vhostname);
		if (data->tftp_path) free(data->tftp_path);
		if (data->bootfile) free(data->bootfile);
		if (data->vdnssearch) free_array(data->vdnssearch);
		free(data);
	}
}

int slirp_set_addr(SLIRP *slirp, struct in_addr vhost, int prefix) {
	if (slirp->init_data) {
		slirp->init_data->vhost = vhost;
		slirp->init_data->prefix = prefix;
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_set_addr6(SLIRP *slirp, struct in6_addr vhost6, int prefix) {
	if (slirp->init_data) {
		slirp->init_data->vhost6 = vhost6;
		slirp->init_data->prefix6 = prefix;
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_set_hostname(SLIRP *slirp, const char *vhostname) {
	if (slirp->init_data && slirp->init_data->vhostname == NULL) {
		slirp->init_data->vhostname = strdup(vhostname);
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_set_tftppath(SLIRP *slirp, const char *tftp_path) {
	if (slirp->init_data && slirp->init_data->tftp_path == NULL) {
		slirp->init_data->tftp_path = strdup(tftp_path);
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_set_bootfile(SLIRP *slirp, const char *bootfile) {
	if (slirp->init_data && slirp->init_data->bootfile == NULL) {
		slirp->init_data->bootfile = strdup(bootfile);
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_set_dhcp(SLIRP *slirp, struct in_addr vdhcp_start) {
	if (slirp->init_data) {
		slirp->init_data->vdhcp_start = vdhcp_start;
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_set_dnsaddr(SLIRP *slirp, struct in_addr vnameserver) {
	if (slirp->init_data) {
		slirp->init_data->vnameserver = vnameserver;
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_set_dnsaddr6(SLIRP *slirp, struct in6_addr vnameserver6) {
	if (slirp->init_data) {
		slirp->init_data->vnameserver6 = vnameserver6;
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_set_vdnssearch(SLIRP *slirp, char **vdnssearch) {
	if (slirp->init_data && slirp->init_data->vdnssearch == NULL) {
		slirp->init_data->vdnssearch = dup_array(vdnssearch);
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

int slirp_start(SLIRP *slirp) {
	if (slirp->init_data) {
		struct slirp_conn *slirp_conn=NULL;
		struct iovec iovout[]={{&slirp_conn,sizeof(slirp_conn)},{&slirp,sizeof(slirp)}};
		if (writev(slirpdaemonfd[APPSIDE], iovout, 2) < 0) {
			return -1;
		}
		if (read(slirp->channel[APPSIDE], &slirp_conn, sizeof(slirp_conn)) < sizeof(slirp_conn)) {
			return -1;
		}
		if (slirp_conn != NULL) {
			slirp->slirp_conn = slirp_conn;
			free_init_data(slirp);
		}
		return 0;
	} else {
		errno = EISCONN;
		return -1;
	}
}

ssize_t slirp_send(SLIRP *slirp, const void *buf, size_t count) {
	struct slirp_conn *slirp_conn = slirp->slirp_conn;
	if (slirp_conn && count > sizeof(void *)) {
		struct iovec iovout[]={{&slirp_conn,sizeof(slirp_conn)},{(char *)buf,count}};
		ssize_t rval = writev(slirpdaemonfd[APPSIDE], iovout, 2);
		return rval - sizeof(slirp_conn);
	} else {
		errno = EINVAL;
		return -1;
	}
}

ssize_t slirp_recv(SLIRP *slirp, void *buf, size_t count) {
	struct slirp_conn *slirp_conn = slirp->slirp_conn;
	if (slirp_conn) {
		return read(slirp->channel[APPSIDE], buf, count);
	} else {
		errno = EINVAL;
		return -1;
	}
}

int slirp_fd(SLIRP *slirp) {
	struct slirp_conn *slirp_conn = slirp->slirp_conn;
	if (slirp_conn) {
		return slirp->channel[APPSIDE];
	} else {
		errno = EINVAL;
		return -1;
	}
}

int slirp_close(SLIRP *slirp) {
	struct slirp_conn *slirp_conn = slirp->slirp_conn;
	if (slirp_conn) {
		struct iovec iovout[]={{&slirp_conn,sizeof(slirp_conn)}};
		ssize_t rval = writev(slirpdaemonfd[APPSIDE], iovout, 1);
		if (rval >= 0) {
			close(slirp->channel[APPSIDE]);
			close(slirp->channel[DAEMONSIDE]);
			free(slirp);
		}
		return rval;
	} else {
		free_init_data(slirp);
		return 0;
	}
}

static int slirp_send_req(struct slirp_conn *slirp_conn, struct slirp_request *preq) {
	struct iovec iovout[]={{&slirp_conn,sizeof(slirp_conn)},{&preq,sizeof(preq)}};
	int rval;
	pipe(preq->pipefd);
	writev(slirpdaemonfd[APPSIDE], iovout, 2);
	read(preq->pipefd[APPSIDE],&rval,sizeof(rval));
	close(preq->pipefd[0]);
	close(preq->pipefd[1]);
	return rval;
}

int slirp_add_fwd(SLIRP *slirp, int is_udp,
		struct in_addr host_addr, int host_port,
		struct in_addr guest_addr, int guest_port) {
	struct slirp_request req = {
		.tag = SLIRP_ADD_FWD,
		.intarg = is_udp,
		.host_addr = host_addr,
		.host_port = host_port,
		.guest_addr = guest_addr,
		.guest_port = guest_port };
	return slirp_send_req(slirp->slirp_conn, &req);
}

int slirp_remove_fwd(SLIRP *slirp, int is_udp,
		struct in_addr host_addr, int host_port) {
	struct slirp_request req = {
		.tag = SLIRP_DEL_FWD,
		.intarg = is_udp,
		.host_addr = host_addr,
		.host_port = host_port};
	 return slirp_send_req(slirp->slirp_conn, &req);
}

int slirp_add_unixfwd(SLIRP *slirp,
		struct in_addr guest_addr, int guest_port, char *path) {
	struct slirp_request req = {
		.tag = SLIRP_ADD_UNIXFWD,
		.guest_addr = guest_addr,
		.guest_port = guest_port,
		.ptrarg = path };
	return slirp_send_req(slirp->slirp_conn, &req);
}

int slirp_remove_unixfwd(SLIRP *slirp,
		struct in_addr guest_addr, int guest_port) {
	struct slirp_request req = {
		.tag = SLIRP_DEL_UNIXFWD,
		.guest_addr = guest_addr,
		.guest_port = guest_port};
	return slirp_send_req(slirp->slirp_conn, &req);
}

int slirp_add_cmdexec(SLIRP *slirp, int do_pty, const void *args,
		struct in_addr guest_addr, int guest_port) {
	struct slirp_request req = {
		.tag = SLIRP_ADD_EXEC,
		.intarg = do_pty,
		.ptrarg = args,
		.guest_addr = guest_addr,
		.guest_port = guest_port };
  return slirp_send_req(slirp->slirp_conn, &req);
}

/* DAEMON SIDE */

static void netmask6 (struct in6_addr *prefixaddr, struct in6_addr *host, int prefix6){
	int i;
	*prefixaddr = *host;
	for (i=0; i<16; i++, prefix6 -= 8) {
		if (prefix6 < 0)
			prefixaddr->s6_addr[i] = 0;
		else if (prefix6 < 8) {
			int mask = ~((1 << (prefix6 - 8)) - 1);
			prefixaddr->s6_addr[i] &= mask;
		}
	}
}

static void slirp_conn_open(void **arg) {
	struct slirp *slirp = *arg;
	if (slirp && slirp->init_data) {
		struct slirp_conn *slirp_conn = calloc(1, sizeof(*slirp_conn));
		struct slirp_init_data *data = slirp->init_data;
		struct in_addr vnetwork, vnetmask;
		struct in6_addr vprefix_addr6;

		vnetmask.s_addr = htonl(~((1<< (32 - data->prefix)) - 1));
		vnetwork.s_addr = data->vhost.s_addr & vnetmask.s_addr;
		netmask6 (&vprefix_addr6, &data->vhost6, data->prefix6);

		slirp_conn->slirp = slirp_init((data->flags & SLIRP_RESTRICTED) != 0,
				(data->flags & SLIRP_IPV4) != 0,
				vnetwork,
				vnetmask,
				data->vhost,
				(data->flags & SLIRP_IPV6) != 0,
				vprefix_addr6,
				data->prefix6,
				data->vhost6,
				data->vhostname,
				data->tftp_path,
				data->bootfile,
				data->vdhcp_start,
				data->vnameserver,
				data->vnameserver6,
				(const char **) data->vdnssearch,
				slirp_conn);
		slirp_conn->outfd = slirp->channel[DAEMONSIDE];
		write(slirp_conn->outfd, &slirp_conn, sizeof(slirp_conn));
	}
}

void slirp_conn_close(struct slirp_conn *slirp_conn) {
	slirp_clean_hostunixfwd(slirp_conn->slirp);
	slirp_cleanup(slirp_conn->slirp);
	free(slirp_conn);
}

void slirp_do_req(struct slirp_conn *slirp_conn, void **arg) {
	  struct slirp_request *preq = *arg;
		int rval = -1;

		switch (preq->tag) {
			case SLIRP_ADD_FWD:
				rval = slirp_add_hostfwd(slirp_conn->slirp, preq->intarg,
						preq->host_addr, preq->host_port,
						preq->guest_addr, preq->guest_port);
				break;
			case SLIRP_DEL_FWD:
				rval = slirp_remove_hostfwd(slirp_conn->slirp, preq->intarg,
						preq->host_addr, preq->host_port);
				break;
			case SLIRP_ADD_UNIXFWD:
				rval = slirp_add_hostunixfwd(slirp_conn->slirp,
						preq->guest_addr, preq->guest_port, preq->ptrarg);
				break;
			case SLIRP_DEL_UNIXFWD:
				rval = slirp_remove_hostunixfwd(slirp_conn->slirp,
						preq->guest_addr, preq->guest_port);
				break;
			case SLIRP_ADD_EXEC:
				rval = slirp_add_exec(slirp_conn->slirp, preq->intarg,
						preq->ptrarg,
						&preq->guest_addr, preq->guest_port);
				break;
		}

		write(preq->pipefd[DAEMONSIDE],&rval,sizeof(rval));
}

void slirp_output(void *opaque, const uint8_t *pkt, int pkt_len) {
	struct slirp_conn *slirp_conn = (struct slirp_conn *) opaque;
	write(slirp_conn->outfd, pkt, pkt_len);
}

static void *slirpdaemon_thread (void *arg) {
	static GArray mainloopfds;
	struct pollfd in = {slirpdaemonfd[DAEMONSIDE], POLLIN | POLLHUP, 0};
	g_array_append_val(&mainloopfds, in);
	while(1) {
		int pollout;
		uint32_t timeout = -1;
		mainloopfds.len = 1;
		slirp_pollfds_fill(&mainloopfds, &timeout);
		update_ra_timeout(&timeout);
#if 0
		int i;
		printf("poll %d %d", mainloopfds.len,timeout);
		for (i=0; i<mainloopfds.len; i++) {
			printf("[%d, %x]", mainloopfds.pfd[i].fd,mainloopfds.pfd[i].events);
			if (mainloopfds.pfd[i].fd > 1024)
				usleep(100000);
		}
		printf("\n");
#endif
		pollout = poll(mainloopfds.pfd, mainloopfds.len, timeout);
		if (mainloopfds.pfd[0].revents) {
			struct slirp_conn *slirp_conn;
			uint8_t buf[MAXMTU];
			struct iovec iovin[]={{&slirp_conn,sizeof(slirp_conn)},{buf,MAXMTU}};
			size_t len = readv(slirpdaemonfd[DAEMONSIDE], iovin, 2);
			if (len == 0)
				break;
			if (slirp_conn == NULL) {
				/* NEW CONN */
				slirp_conn_open((void **) buf);
			} else if (len <= sizeof(slirp_conn) + sizeof(struct slirp_request *)) {
				if (len == sizeof(slirp_conn))
					slirp_conn_close(slirp_conn);
				else
					slirp_do_req(slirp_conn, (void **) buf);
			} else {
				/* incoming msg */
				slirp_input(slirp_conn->slirp, buf, len - sizeof(slirp_conn));
			}
			pollout--;
		}
		slirp_pollfds_poll(&mainloopfds, (pollout <= 0));
		check_ra_timeout();
	}
	return 0;
}

__attribute__((constructor)) static void init() {
	//fprintf(stderr, "INIT!\n");
	socketpair(AF_LOCAL, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, slirpdaemonfd);
	pthread_create(&slirpdaemon_tid, NULL, slirpdaemon_thread, NULL);
}

__attribute__((destructor)) static void fini() {
	//fprintf(stderr, "FINI!\n");
	close(slirpdaemonfd[APPSIDE]);
	pthread_join(slirpdaemon_tid, NULL);
	close(slirpdaemonfd[DAEMONSIDE]);
}

