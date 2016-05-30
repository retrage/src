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
 */

/*
 * Counting semaphores.
 *
 * Priority propagation will not generally raise the priority of semaphore
 * "owners" (a misnomer in the context of semaphores), so should not be relied
 * upon in combination with semaphores.
 */

#include <sys/cdefs.h>

/*
__FBSDID("$FreeBSD: head/sys/kern/kern_sema.c 139804 2005-01-06 23:35:40Z imp $");
*/

#include <sys/param.h>
#include <sys/systm.h>
/*
#include <sys/ktr.h>
*/
#include <sys/condvar.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <dev/acpi/vmbus/hyperv/vmbus/hv_sema.h>

void
hv_sema_init(struct hv_sema *sema, int value, const char *description)
{

	KASSERT(value >= 0);

	bzero(sema, sizeof(sema));
	mutex_init(&sema->sema_mtx, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&sema->sema_cv, description);
	sema->sema_value = value;
}

void
hv_sema_destroy(struct hv_sema *sema)
{
	KASSERT(sema->sema_waiters == 0);

	mutex_destroy(&sema->sema_mtx);
	cv_destroy(&sema->sema_cv);
}

void
hv_sema_post(struct hv_sema *sema)
{

	mutex_enter(&sema->sema_mtx);
	sema->sema_value++;
	if (sema->sema_waiters && sema->sema_value > 0)
		cv_signal(&sema->sema_cv);

	mutex_exit(&sema->sema_mtx);
}

void
hv_sema_wait(struct hv_sema *sema)
{

	mutex_enter(&sema->sema_mtx);
	while (sema->sema_value == 0) {
		sema->sema_waiters++;
		cv_wait(&sema->sema_cv, &sema->sema_mtx);
		sema->sema_waiters--;
	}
	sema->sema_value--;

	mutex_exit(&sema->sema_mtx);
}

int
hv_sema_timedwait(struct hv_sema *sema, int timo)
{
	int error;

	mutex_enter(&sema->sema_mtx);

	/*
	 * A spurious wakeup will cause the timeout interval to start over.
	 * This isn't a big deal as long as spurious wakeups don't occur
	 * continuously, since the timeout period is merely a lower bound on how
	 * long to wait.
	 */
	for (error = 0; sema->sema_value == 0 && error == 0;) {
		sema->sema_waiters++;
		error = cv_timedwait(&sema->sema_cv, &sema->sema_mtx, timo);
		sema->sema_waiters--;
	}
	if (sema->sema_value > 0) {
		/* Success. */
		sema->sema_value--;
		error = 0;
	}

	mutex_exit(&sema->sema_mtx);
	return (error);
}

int
hv_sema_trywait(struct hv_sema *sema)
{
	int ret;

	mutex_enter(&sema->sema_mtx);

	if (sema->sema_value > 0) {
		/* Success. */
		sema->sema_value--;
		ret = 1;
	} else {
		ret = 0;
	}

	mutex_exit(&sema->sema_mtx);
	return (ret);
}

int
hv_sema_value(struct hv_sema *sema)
{
	int ret;

	mutex_enter(&sema->sema_mtx);
	ret = sema->sema_value;
	mutex_exit(&sema->sema_mtx);
	return (ret);
}
