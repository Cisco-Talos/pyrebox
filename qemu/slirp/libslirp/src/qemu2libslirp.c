/*
 * qemu2libslirp - implement the timer for router advertisement
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
#include <stdint.h>
#include <slirp.h>


struct QEMUTimer{
	struct QEMUTimer *next;
	uint64_t deadline;
	void (*handler)(void *opaque);
	void *opaque;
};

static QEMUTimer *head;

QEMUTimer *timer_new_ms(int timetag, void (*handler)(void *opaque), void *opaque) {
	QEMUTimer *qt = malloc(sizeof(*qt));
	if (qt) {
		qt->next = head;
		qt->deadline = -1;
		qt->handler = handler;
		qt->opaque = opaque;
		head=qt;
	}
	return qt;
}

void timer_free(QEMUTimer *qt) {
	QEMUTimer **scan;
	for (scan =  &head;
			*scan != NULL && *scan != qt;
			scan = &((*scan) ->next)) 
		;
	if (*scan) {
		*scan = qt->next;
	  free(qt);
	}
}

void timer_mod(QEMUTimer *qt, uint64_t deadline) {
	qt->deadline = deadline;
}

void timer_del(QEMUTimer *qt) {
	qt->deadline = -1;
}

void update_ra_timeout(uint32_t *timeout) {
	QEMUTimer *qt;
	int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
	for (qt = head; qt != NULL; qt =  qt->next) {
		if (qt->deadline != -1) {
			int64_t diff = qt->deadline - now; 
			if (diff < 0) diff = 0;
			if (diff < *timeout) *timeout = diff;
		}
	}
}

void check_ra_timeout(void) {
	QEMUTimer *qt;
	int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
	for (qt = head; qt != NULL; qt =  qt->next) {
		if (qt->deadline != -1) {
			int64_t diff = qt->deadline - now;
			if (diff <= 0) {
				qt->deadline = -1;
				qt->handler(qt->opaque);
			}
		}
	}
}
