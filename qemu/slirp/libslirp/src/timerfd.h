#ifndef TIMERFD_H
#define TIMERFD_H

int timerfd_init(void);

void timerfd_close(int fd); 

void timerfd_set(int fd, int timeout_ms); 

void timerfd_reset(int fd);

#endif
