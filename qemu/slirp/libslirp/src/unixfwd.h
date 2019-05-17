#ifndef UNIXFWD_H
#define UNIXFWD_H

struct socket;

int slirp_add_hostunixfwd(void *slirp, struct in_addr host_addr,
		                      int host_port, const void *path);

int slirp_remove_hostunixfwd(void *slirp, struct in_addr host_addr,
		                      int host_port);

void slirp_clean_hostunixfwd(void *slirp);

int unixtcp_fconnect(struct socket *so, unsigned short af);

#endif
