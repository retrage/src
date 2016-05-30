/*-
 * Copyright (C) 2001 Jason Evans <jasone@freebsd.org>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * $FreeBSD: head/sys/sys/sema.h 139825 2005-01-07 02:29:27Z imp $
 */

#ifndef	_HV_SEMA_H_
#define	_HV_SEMA_H_

#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>

struct hv_sema {
	kmutex_t	sema_mtx;	/* General protection lock. */
	kcondvar_t	sema_cv;	/* Waiters. */
	int		sema_waiters;	/* Number of waiters. */
	int		sema_value;	/* Semaphore value. */
};

void	hv_sema_init(struct hv_sema *sema, int value, const char *description);
void	hv_sema_destroy(struct hv_sema *sema);
void	hv_sema_post(struct hv_sema *sema);
void	hv_sema_wait(struct hv_sema *sema);
int	hv_sema_timedwait(struct hv_sema *sema, int timo);
int	hv_sema_trywait(struct hv_sema *sema);
int	hv_sema_value(struct hv_sema *sema);

#endif	/* _HV_SEMA_H_ */
