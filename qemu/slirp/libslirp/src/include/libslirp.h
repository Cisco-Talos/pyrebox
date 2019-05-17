#ifndef LIBSLIRP__H
#define LIBSLIRP__H

#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct slirp;
typedef struct slirp SLIRP;

#define SLIRP_IPV4       0x01
#define SLIRP_IPV6       0x02
#define SLIRP_RESTRICTED 0x10

SLIRP *slirp_open(uint32_t flags);

int slirp_set_addr(SLIRP *slirp, struct in_addr vhost, int prefix);

int slirp_set_addr6(SLIRP *slirp, struct in6_addr vhost6, int prefix);

int slirp_set_hostname(SLIRP *slirp, const char *vhostname);

int slirp_set_tftppath(SLIRP *slirp, const char *tftp_path);

int slirp_set_bootfile(SLIRP *slirp, const char *bootfile);

int slirp_set_dhcp(SLIRP *slirp, struct in_addr vdhcp_start);

int slirp_set_dnsaddr(SLIRP *slirp, struct in_addr vnameserver);

int slirp_set_dnsaddr6(SLIRP *slirp, struct in6_addr vnameserver6);

int slirp_set_vdnssearch(SLIRP *slirp, char **vdnssearch);

int slirp_start(SLIRP *slirp);

ssize_t slirp_send(SLIRP *slirp, const void *buf, size_t count);

ssize_t slirp_recv(SLIRP *slirp, void *buf, size_t count);

int slirp_fd(SLIRP *slirp);

int slirp_close(SLIRP *slirp);

int slirp_add_fwd(SLIRP *slirp, int is_udp,
		struct in_addr host_addr, int host_port,
		struct in_addr guest_addr, int guest_port);
int slirp_remove_fwd(SLIRP *slirp, int is_udp,
		struct in_addr host_addr, int host_port);

int slirp_add_unixfwd(SLIRP *slirp, 
		struct in_addr guest_addr, int guest_port, char *path);
int slirp_remove_unixfwd(SLIRP *slirp, 
		struct in_addr guest_addr, int guest_port);

int slirp_add_cmdexec(SLIRP *slirp, int do_pty, const void *args,
		struct in_addr guest_addr, int guest_port);
#endif
