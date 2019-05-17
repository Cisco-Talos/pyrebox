/*
 * unixfwd - add port forwarding to a unixsocket (e.g. for X-window)
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

#include <slirp.h>

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

struct tcp2unix {
	void *slirp;
	struct in_addr addr;
	int port; // net endian!
	char *path;
	struct tcp2unix *next;
};

static struct tcp2unix *t2u_head;

int slirp_add_hostunixfwd(void *vslirp, struct in_addr host_addr,
		int host_port, const void *arg) {
	const char *path = arg;
	Slirp *slirp = vslirp;
	int port = htons(host_port);
	struct tcp2unix **scan, *this;
	if (host_addr.s_addr == 0)
		host_addr = slirp->vhost_addr;
	for (scan = &t2u_head; *scan != NULL; scan = &((*scan)->next)) {
		this = *scan;
		if (this->slirp == slirp && this->addr.s_addr == host_addr.s_addr && this->port == port) {
			free(this->path);
			this->path = strdup(path);
			return 0;
		}
	}
	this = malloc(sizeof(struct tcp2unix));
	if (this) {
		this->slirp = slirp;
		this->addr = host_addr;
		this->port = port;
		this->path = strdup(path);
		this->next = NULL;
		*scan = this;
		return 0;
	} else
		return -1;
}

int slirp_remove_hostunixfwd(void *slirp, struct in_addr host_addr,
		int host_port) {
	int port = htons(host_port);
	struct tcp2unix **scan, *this;
	for (scan = &t2u_head; *scan != NULL; scan = &((*scan)->next)) {
		this = *scan;
		if (this->slirp == slirp && this->addr.s_addr == host_addr.s_addr && this->port == port) {
			free(this->path);
			*scan = this->next;
			free(this);
			return 0;
		}
	}
	return -1;
}

void slirp_clean_hostunixfwd(void *slirp) {
	struct tcp2unix **scan, *this;
	for (scan = &t2u_head; *scan != NULL; scan = &((*scan)->next)) {
		this = *scan;
		if (this->slirp == slirp) {
			free(this->path);
			*scan = this->next;
			free(this);
		}
	}
}

int unixtcp_fconnect(struct socket *so, unsigned short af) {
	Slirp *slirp = so->slirp;
	int ret = -1;
	struct tcp2unix **scan, *this;
	if (af == AF_INET) {
		for (scan = &t2u_head; *scan != NULL; scan = &((*scan)->next)) {
			this = *scan;
			if (this->slirp == slirp && this->addr.s_addr == so->so_faddr.s_addr && this->port == so->so_fport)
				break;
		}
		this = *scan;
		if (this != NULL) {
			ret = so->s = qemu_socket(PF_UNIX, SOCK_STREAM, 0);
			if (ret >= 0) {
				struct sockaddr_un addr;
				qemu_set_nonblock(ret);
				addr.sun_family = AF_UNIX;
				strncpy(addr.sun_path,this->path,UNIX_PATH_MAX);
				ret = connect(so->s, (struct sockaddr *)&addr, sizeof (addr));
				soisfconnecting(so);
			}
		}
	}
	return ret;
}
