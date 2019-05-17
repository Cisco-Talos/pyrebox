#ifndef QEMU2SLIRPLIB_H
#define QEMU2SLIRPLIB_H

#define slirp_send _slirp_send

#define QEMU_PACKED __attribute__((packed))
typedef int bool;
#define true 1
#define false 0
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>

#include <unixfwd.h>

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *) 0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
		    const typeof(((type *) 0)->member) *__mptr = (ptr);     \
		    (type *) ((char *) __mptr - offsetof(type, member));})
#endif
#define             g_assert_not_reached()
#define             g_warning(...)
#define             g_malloc(X) malloc(X)
#define             g_malloc0(X) calloc(1,(X))
#define             g_new(X,N) calloc((N),sizeof(X))
#define             g_free(X) free(X)
#define             g_strdup(X) ((X) ? strdup(X) : strdup(""))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif
#define qemu_socket socket
#define qemu_recv recv
#define qemu_setsockopt setsockopt
#define closesocket close
#define ioctlsocket ioctl
#define qemu_notify_event()

static inline void pstrcpy(char *buf, int buf_size, const char *str) {
	strncpy(buf, str, buf_size);
	buf[buf_size-1] = 0;
}

static inline int socket_set_fast_reuse(int fd)
{
	int val = 1, ret;

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			(const char *)&val, sizeof(val));

	assert(ret == 0);

	return ret;
}

static inline int socket_set_nodelay(int fd)
{
	int v = 1;
	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(v));
}


#define ETH_ALEN 6
#define ETH_HLEN 14

typedef enum {
	QEMU_CLOCK_REALTIME = 0,
	QEMU_CLOCK_VIRTUAL = 1,
	QEMU_CLOCK_HOST = 2,
	QEMU_CLOCK_VIRTUAL_RT = 3,
	QEMU_CLOCK_MAX
} QEMUClockType;

#include <time.h>
static inline int64_t qemu_clock_get_ns(QEMUClockType type) {
	struct timespec ts;
	clock_gettime(type, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

#define SCALE_MS 1000000
static inline int64_t qemu_clock_get_ms(QEMUClockType type)
{
	    return qemu_clock_get_ns(type) / SCALE_MS;
}


#define qemu_log_mask(...) 

#define ETH_P_IP  0x0800    /* Internet Protocol packet */
#define ETH_P_ARP 0x0806    /* Address Resolution packet  */
#define ETH_P_IPV6 (0x86dd)

typedef struct {
	int maxlen;
	int len;
	struct pollfd *pfd;
} GArray;
typedef struct pollfd  GPollFD;

#define g_array_index(gar, X, index) ((gar)->pfd[(index)])
static inline void g_array_append_val(GArray *p, struct pollfd elem) {
	if (p->len >= p->maxlen) {
		struct pollfd *newpfd;
		if ((newpfd = realloc(p->pfd, (p->maxlen + 16) * sizeof(struct pollfd))) != NULL) {
			p->pfd = newpfd;
			p->maxlen += 16;
		}
	}
	if (p->len < p->maxlen) {
		elem.revents = 0;
		p->pfd[p->len] = elem;
		p->len ++;
	}
}

#define G_IO_IN POLLIN
#define G_IO_OUT POLLOUT
#define G_IO_PRI POLLPRI
#define G_IO_HUP POLLHUP
#define G_IO_ERR POLLERR

#define error_report(format, ...) ({ \
		fprintf (stderr, format, ## __VA_ARGS__); \
		fprintf (stderr, "\n"); \
		})

#define monitor_printf(mon, format, ...) ({ \
		fprintf (stderr, format, ## __VA_ARGS__); \
		fprintf (stderr, "\n"); \
		})

static inline void qemu_set_nonblock(int fd)
{
	int f;
	f = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

struct QEMUTimer;
typedef struct QEMUTimer QEMUTimer;

QEMUTimer *timer_new_ms(int timetag, void (*handler)(void *opaque), void *opaque);
void timer_free(QEMUTimer *t);
void timer_mod(QEMUTimer *t, uint64_t deadline);
void timer_del(QEMUTimer *t);
void update_ra_timeout(uint32_t *timeout);
void check_ra_timeout(void);

typedef void GRand;

static inline uint32_t g_rand_int_range (GRand *rand_, uint32_t begin, uint32_t end) {
	return (random() % (end - begin)) + begin;
}

static inline GRand *g_rand_new (void) {
	srandom(time(NULL));
	return NULL;
}

static inline void g_rand_free (GRand *rand_) {
}

#define register_savevm(...)
#define unregister_savevm(...)
#define qemu_chr_fe_write(...)
#define qemu_add_child_watch(...)

typedef void QEMUFile;

#define qemu_put_byte(...) ((void) 0)
#define qemu_put_sbyte(...) ((void) 0)
#define qemu_put_be16(...) ((void) 0)
#define qemu_put_sbe16(...) ((void) 0)
#define qemu_put_be32(...) ((void) 0)
#define qemu_put_sbe32(...) ((void) 0)
#define qemu_put_buffer(...) ((void) 0)
#define qemu_get_byte(...) 0
#define qemu_get_sbyte(...) 0
#define qemu_get_be16(...) 0
#define qemu_get_sbe16(...) 0
#define qemu_get_be32(...) 0
#define qemu_get_sbe32(...) 0
#define qemu_get_buffer(...) ((void) 0)

#endif
