/*
 * timerfd - us a file descriptor as a timer
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>

static inline int64_t clock_get_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

static void *timer_thread (void *arg) {
	int fd = (uintptr_t) arg;
	struct pollfd fds={fd, POLLIN | POLLHUP, 0};
	int64_t next_timeout=-1;
	int timeout = -1; 
	int64_t now;
	char msg = 0;
	while(1) {
		int n = poll(&fds, 1, timeout);
		now = clock_get_ms();
		if (fds.revents) {
			if (read(fd, &timeout, sizeof(int)) == 0 || timeout == INT_MIN)
				break;
			next_timeout = (timeout == -1) ? -1LL : now + timeout;
		}
		if (next_timeout == -1)
			timeout = -1;
		else {
			timeout = (next_timeout == -1) ? -1 : (int) (next_timeout - now);
			if (timeout < 0) {
				write(fd, &msg, 1);
				timeout = -1;
			}
		}
	}
	close(fd);
	pthread_exit(NULL);
}

int timerfd_init(void) {
	int fd[2];
	pthread_t timer_t;
	socketpair(PF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0, fd);
	pthread_create(&timer_t, NULL, timer_thread, (void *)(uintptr_t)fd[1]);
	return fd[0];
}

void timerfd_close(int fd) {
	int terminate = INT_MIN;
	write(fd,&terminate,sizeof(int));
	close(fd);
}

void timerfd_set(int fd, int timeout_ms) {
	if (timeout_ms < 0)
		timeout_ms = -1;
	write(fd,&timeout_ms,sizeof(int));
}

void timerfd_reset(int fd) {
	char buf[8];
	read(fd,buf,8);
}

/*
	 int main() {
	 int tfd = timerfd_init();
	 struct pollfd fds[2]={{STDIN_FILENO, POLLIN, 0},{tfd, POLLIN, 0}};
	 while (1) {
	 poll(fds, 2, -1);
	 if (fds[0].revents) {
	 char buf[128];
	 int timeout;
	 if (read(STDIN_FILENO,buf,128) <= 0)
	 break;
	 timeout = atoi(buf);
//scanf("%d", &timeout);
printf("timeout set %d\n",timeout);
timerfd_set(tfd, timeout);
}
if (fds[1].revents) {
timerfd_reset(tfd);
printf("timer expired\n");
}
}
timerfd_close(tfd);
}
 */
