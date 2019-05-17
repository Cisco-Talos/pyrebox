SUBDIRS = include
lib_LTLIBRARIES = libslirp.la 

AM_CFLAGS = -Wall -O2 -I. -I../include

libslirp_la_SOURCES = arp_table.c bootp.c cksum.c dhcpv6.c dnssearch.c ip6_input.c ip6_output.c \
											ip_icmp.c ip_input.c ip_output.c mbuf.c misc.c ndp_table.c sbuf.c socket.c tcp_input.c \
											tcp_output.c tcp_subr.c tcp_timer.c tftp.c udp.c udp6.c if.c ip6_icmp.c \
											slirp.c qemu2libslirp.c unixfwd.c libslirp.c
libslirp_la_LIBADD = -lpthread
libslirp_la_LDFLAGS = -version-number 0:2:0
