/*-
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/atomic.h>
#include <sys/workqueue.h>
#include <sys/bitops.h>
#include <sys/reboot.h>
/*
#include <machine/bus.h>
#include <machine/atomic.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
*/

#include <dev/acpi/vmbus/hyperv/vmbus/hv_sema.h>

#include <dev/acpi/vmbus/hyperv/vmbus/hv_vmbus_priv.h>
#include <dev/acpi/vmbus/hyperv/vmbus/vmbus_var.h>

/*
 * Globals
 */
hv_vmbus_connection hv_vmbus_g_connection =
	{ .connect_state = HV_DISCONNECTED,
	  .next_gpadl_handle = 0xE1E10, };

uint32_t hv_vmbus_protocal_version = HV_VMBUS_VERSION_WS2008;

static uint32_t
hv_vmbus_get_next_version(uint32_t current_ver)
{
	switch (current_ver) {
	case (HV_VMBUS_VERSION_WIN7):
		return(HV_VMBUS_VERSION_WS2008);

	case (HV_VMBUS_VERSION_WIN8):
		return(HV_VMBUS_VERSION_WIN7);

	case (HV_VMBUS_VERSION_WIN8_1):
		return(HV_VMBUS_VERSION_WIN8);

	case (HV_VMBUS_VERSION_WS2008):
	default:
		return(HV_VMBUS_VERSION_INVALID);
	}
}

/**
 * Negotiate the highest supported hypervisor version.
 */
static int
hv_vmbus_negotiate_version(hv_vmbus_channel_msg_info *msg_info,
	uint32_t hv_version)
{
	int					ret = 0;
	hv_vmbus_channel_initiate_contact	*msg;

	hv_sema_init(&msg_info->wait_sema, 0, "Msg Info Sema");
	msg = (hv_vmbus_channel_initiate_contact*) msg_info->msg;

	msg->header.message_type = HV_CHANNEL_MESSAGE_INITIATED_CONTACT;
	msg->vmbus_version_requested = hv_version;

	msg->interrupt_page = hv_get_phys_addr(
		hv_vmbus_g_connection.interrupt_page);

	msg->monitor_page_1 = hv_get_phys_addr(
		hv_vmbus_g_connection.monitor_page_1);

	msg->monitor_page_2 = hv_get_phys_addr(
		hv_vmbus_g_connection.monitor_page_2);

	/**
	 * Add to list before we send the request since we may receive the
	 * response before returning from this routine
	 */
	mutex_enter(&hv_vmbus_g_connection.channel_msg_lock);

	TAILQ_INSERT_TAIL(
		&hv_vmbus_g_connection.channel_msg_anchor,
		msg_info,
		msg_list_entry);

	mutex_exit(&hv_vmbus_g_connection.channel_msg_lock);

	ret = hv_vmbus_post_message(
		msg,
		sizeof(hv_vmbus_channel_initiate_contact));

	if (ret != 0) {
		mutex_enter(&hv_vmbus_g_connection.channel_msg_lock);
		TAILQ_REMOVE(
			&hv_vmbus_g_connection.channel_msg_anchor,
			msg_info,
			msg_list_entry);
		mutex_exit(&hv_vmbus_g_connection.channel_msg_lock);
		printf("hv_vmbus_negotiate_version ret\n");
		return (ret);
	}

	/**
	 * Wait for the connection response
	 */
	ret = hv_sema_timedwait(&msg_info->wait_sema, 5 * hz); /* KYS 5 seconds */
	printf("sema_timedwait in negotiate done: ret=%d\n", ret);

	mutex_enter(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_REMOVE(
		&hv_vmbus_g_connection.channel_msg_anchor,
		msg_info,
		msg_list_entry);
	mutex_exit(&hv_vmbus_g_connection.channel_msg_lock);

	/**
	 * Check if successful
	 */
	if (msg_info->response.version_response.version_supported) {
		hv_vmbus_g_connection.connect_state = HV_CONNECTED;
	} else {
		ret = ECONNREFUSED;
	}

	printf("hv_vmbus_negotiate_version done\n");

	return (ret);
}

/**
 * Send a connect request on the partition service connection
 */
int
hv_vmbus_connect(void)
{
	int					ret = 0;
	uint32_t				hv_version;
	hv_vmbus_channel_msg_info*		msg_info = NULL;

	/**
	 * Make sure we are not connecting or connected
	 */
	if (hv_vmbus_g_connection.connect_state != HV_DISCONNECTED) {
		return (-1);
	}

	/**
	 * Initialize the vmbus connection
	 */
	hv_vmbus_g_connection.connect_state = HV_CONNECTING;

	TAILQ_INIT(&hv_vmbus_g_connection.channel_msg_anchor);
	mutex_init(&hv_vmbus_g_connection.channel_msg_lock, MUTEX_DEFAULT, IPL_NONE);

	TAILQ_INIT(&hv_vmbus_g_connection.channel_anchor);
	mutex_init(&hv_vmbus_g_connection.channel_lock, MUTEX_DEFAULT, IPL_NONE);

	/**
	 * Setup the vmbus event connection for channel interrupt abstraction
	 * stuff
	 */
	hv_vmbus_g_connection.interrupt_page = kmem_intr_zalloc(PAGE_SIZE, KM_SLEEP);

	hv_vmbus_g_connection.recv_interrupt_page =
		hv_vmbus_g_connection.interrupt_page;

	hv_vmbus_g_connection.send_interrupt_page =
		((uint8_t *) hv_vmbus_g_connection.interrupt_page +
		    (PAGE_SIZE >> 1));

	/**
	 * Set up the monitor notification facility. The 1st page for
	 * parent->child and the 2nd page for child->parent
	 */
	hv_vmbus_g_connection.monitor_page_1 = kmem_zalloc(PAGE_SIZE, KM_SLEEP);
	hv_vmbus_g_connection.monitor_page_2 = kmem_zalloc(PAGE_SIZE, KM_SLEEP);

	msg_info = (hv_vmbus_channel_msg_info*)
		kmem_zalloc(sizeof(hv_vmbus_channel_msg_info) +
			sizeof(hv_vmbus_channel_initiate_contact), KM_SLEEP);

	hv_vmbus_g_connection.channels = kmem_zalloc(sizeof(hv_vmbus_channel*) *
		HV_CHANNEL_MAX_COUNT, KM_SLEEP);

	/*
	 * Find the highest vmbus version number we can support.
	 */
	hv_version = HV_VMBUS_VERSION_CURRENT;

	do {
		ret = hv_vmbus_negotiate_version(msg_info, hv_version);
		if (ret == EWOULDBLOCK) {
			/*
			 * We timed out.
			 */
			goto cleanup;
		}

		if (hv_vmbus_g_connection.connect_state == HV_CONNECTED)
			break;

		hv_version = hv_vmbus_get_next_version(hv_version);
	} while (hv_version != HV_VMBUS_VERSION_INVALID);

	hv_vmbus_protocal_version = hv_version;
	if (bootverbose)
		printf("VMBUS: Protocol Version: %d.%d\n",
		    hv_version >> 16, hv_version & 0xFFFF);

	hv_sema_destroy(&msg_info->wait_sema);
	kmem_free(msg_info, sizeof(hv_vmbus_channel_msg_info) +
			sizeof(hv_vmbus_channel_initiate_contact));

	printf("hv_vmbus_connect done\n");

	return (0);

	/*
	 * Cleanup after failure!
	 */
	cleanup:

	hv_vmbus_g_connection.connect_state = HV_DISCONNECTED;

	mutex_destroy(&hv_vmbus_g_connection.channel_lock);
	mutex_destroy(&hv_vmbus_g_connection.channel_msg_lock);

	if (hv_vmbus_g_connection.interrupt_page != NULL) {
		kmem_intr_free(hv_vmbus_g_connection.interrupt_page, PAGE_SIZE);
		hv_vmbus_g_connection.interrupt_page = NULL;
	}

	kmem_free(hv_vmbus_g_connection.monitor_page_1, PAGE_SIZE);
	kmem_free(hv_vmbus_g_connection.monitor_page_2, PAGE_SIZE);

	if (msg_info) {
		hv_sema_destroy(&msg_info->wait_sema);
		kmem_free(msg_info, sizeof(hv_vmbus_channel_msg_info) +
				sizeof(hv_vmbus_channel_initiate_contact));
	}

	kmem_free(hv_vmbus_g_connection.channels,
			sizeof(hv_vmbus_channel*) * HV_CHANNEL_MAX_COUNT);
	return (ret);
}

/**
 * Send a disconnect request on the partition service connection
 */
int
hv_vmbus_disconnect(void)
{
	int			 ret = 0;
	hv_vmbus_channel_unload  msg;

	msg.message_type = HV_CHANNEL_MESSAGE_UNLOAD;

	ret = hv_vmbus_post_message(&msg, sizeof(hv_vmbus_channel_unload));

	free(hv_vmbus_g_connection.interrupt_page, M_DEVBUF);

	mutex_destroy(&hv_vmbus_g_connection.channel_msg_lock);

	free(hv_vmbus_g_connection.channels, M_DEVBUF);
	hv_vmbus_g_connection.connect_state = HV_DISCONNECTED;

	return (ret);
}

static __inline void
vmbus_event_flags_proc(unsigned long *event_flags, int flag_cnt)
{
	int f;

	for (f = 0; f < flag_cnt; ++f) {
		uint32_t rel_id_base;
		unsigned long flags;
		int bit;

		if (event_flags[f] == 0)
			continue;

		flags = atomic_swap_ulong(&event_flags[f], 0);
		rel_id_base = f << HV_CHANNEL_ULONG_SHIFT;

		while ((bit = ffs64(flags)) != 0) {
			struct hv_vmbus_channel *channel;
			uint32_t rel_id;

			--bit;	/* NOTE: ffsl is 1-based */
			flags &= ~(1UL << bit);

			rel_id = rel_id_base + bit;
			channel = hv_vmbus_g_connection.channels[rel_id];

			/* if channel is closed or closing */
			if (channel == NULL || channel->rxq == NULL)
				continue;

			if (channel->batched_reading)
				hv_ring_buffer_read_begin(&channel->inbound);
			workqueue_enqueue(channel->rxq, channel->channel_task, NULL);
		}
	}
}

void
vmbus_event_proc(struct vmbus_softc *sc, int cpu)
{
	hv_vmbus_synic_event_flags *event;

	/*
	 * On Host with Win8 or above, the event page can be checked directly
	 * to get the id of the channel that has the pending interrupt.
	 */
	event = VMBUS_PCPU_GET(sc, event_flag, cpu) + HV_VMBUS_MESSAGE_SINT;
	vmbus_event_flags_proc(event->flagsul,
	    VMBUS_PCPU_GET(sc, event_flag_cnt, cpu));
}

void
vmbus_event_proc_compat(struct vmbus_softc *sc __unused, int cpu)
{
	hv_vmbus_synic_event_flags *event;

	event = VMBUS_PCPU_GET(sc, event_flag, cpu) + HV_VMBUS_MESSAGE_SINT;
	if (atomic_testandclear_int(&event->flags32[0], 0)) {
		vmbus_event_flags_proc(
		    hv_vmbus_g_connection.recv_interrupt_page,
		    HV_MAX_NUM_CHANNELS_SUPPORTED >> HV_CHANNEL_ULONG_SHIFT);
	}
}

/**
 * Send a msg on the vmbus's message connection
 */
int hv_vmbus_post_message(void *buffer, size_t bufferLen)
{
	hv_vmbus_connection_id connId;
	int time = 1;
	int retries;
	int ret;

	printf("Enter hv_vmbus_post_message\n");

	connId.as_uint32_t = 0;
	connId.u.id = HV_VMBUS_MESSAGE_CONNECTION_ID;

	/*
	 * We retry to cope with transient failures caused by host side's
	 * insufficient resources. 20 times should suffice in practice.
	 */
	for (retries = 0; retries < 20; retries++) {
		ret = hv_vmbus_post_msg_via_msg_ipc(connId, 1, buffer,
						    bufferLen);
		if (ret == HV_STATUS_SUCCESS) {
			printf("hv_vmbus_post_message returned\n");
			return (0);
		}

		kpause("pstmsg", false, mstohz(time), NULL);
		if (time < 1000 * 2)
			time *= 2;
	}

	KASSERT(ret == HV_STATUS_SUCCESS);

	printf("hv_vmbus_post_message done\n");

	return (EAGAIN);
}

/**
 * Send an event notification to the parent
 */
int
hv_vmbus_set_event(hv_vmbus_channel *channel)
{
	int ret = 0;
	uint32_t child_rel_id = channel->offer_msg.child_rel_id;

	/* Each uint32_t represents 32 channels */

	synch_set_bit(child_rel_id & 31,
		(((uint32_t *)hv_vmbus_g_connection.send_interrupt_page
			+ (child_rel_id >> 5))));
	ret = hv_vmbus_signal_event(channel->signal_event_param);

	return (ret);
}

void
vmbus_on_channel_open(const struct hv_vmbus_channel *chan)
{
	volatile int *flag_cnt_ptr;
	int flag_cnt;

	flag_cnt = (chan->offer_msg.child_rel_id / HV_CHANNEL_ULONG_LEN) + 1;
	flag_cnt_ptr = VMBUS_PCPU_PTR(vmbus_get_softc(), event_flag_cnt,
	    chan->target_cpu);

	for (;;) {
		int old_flag_cnt;

		old_flag_cnt = *flag_cnt_ptr;
		if (old_flag_cnt >= flag_cnt)
			break;
		if (atomic_cmpset_int(flag_cnt_ptr, old_flag_cnt, flag_cnt)) {
			if (bootverbose) {
				printf("VMBUS: channel%u update "
				    "cpu%d flag_cnt to %d\n",
				    chan->offer_msg.child_rel_id,
				    chan->target_cpu, flag_cnt);
			}
			break;
		}
	}
}
