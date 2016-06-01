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

/**
 * Implements low-level interactions with Hypver-V/Azure
 */
#include <sys/cdefs.h>
/*
__FBSDID("$FreeBSD: head/sys/dev/hyperv/vmbus/hv_hv.c 300834 2016-05-27 07:29:31Z sephe $");
*/

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/reboot.h>
/*
#include <sys/pcpu.h>
*/
#include <sys/timetc.h>
/*
#include <machine/bus.h>
#include <machine/md_var.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
*/
#include <sys/bus.h>

#include <dev/acpi/vmbus/hyperv/include/hyperv_busdma.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hv_vmbus_priv.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hyperv_reg.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hyperv_var.h>
#include <dev/acpi/vmbus/hyperv/vmbus/vmbus_var.h>

#define HV_NANOSECONDS_PER_SEC		1000000000L

#define HYPERV_NETBSD_BUILD		0ULL
#define HYPERV_NETBSD_VERSION		((uint64_t)__NetBSD_Version__)
#define HYPERV_NETBSD_OSID		0ULL

#define MSR_HV_GUESTID_BUILD_NETBSD	\
	(HYPERV_NETBSD_BUILD & MSR_HV_GUESTID_BUILD_MASK)
#define MSR_HV_GUESTID_VERSION_NETBSD	\
	((HYPERV_NETBSD_VERSION << MSR_HV_GUESTID_VERSION_SHIFT) & \
	 MSR_HV_GUESTID_VERSION_MASK)
#define MSR_HV_GUESTID_OSID_NETBSD	\
	((HYPERV_NETBSD_OSID << MSR_HV_GUESTID_OSID_SHIFT) & \
	 MSR_HV_GUESTID_OSID_MASK)

#define MSR_HV_GUESTID_NETBSD		\
	(MSR_HV_GUESTID_BUILD_NETBSD |	\
	 MSR_HV_GUESTID_VERSION_NETBSD | \
	 MSR_HV_GUESTID_OSID_NETBSD |	\
	 MSR_HV_GUESTID_OSTYPE_NETBSD)

struct hypercall_ctx {
	void			*hc_addr;
	struct hyperv_dma	hc_dma;
};

static u_int	hyperv_get_timecount(struct timecounter *tc);

u_int		hyperv_features;
u_int		hyperv_recommends;

static u_int	hyperv_pm_features;
static u_int	hyperv_features3;

static struct timecounter	hyperv_timecounter = {
	.tc_get_timecount	= hyperv_get_timecount,
	.tc_poll_pps		= NULL,
	.tc_counter_mask	= 0xffffffff,
	.tc_frequency		= HV_NANOSECONDS_PER_SEC/100,
	.tc_name		= "Hyper-V",
	.tc_quality		= 2000,
	.tc_priv		= NULL,
	.tc_next		= NULL
};

static struct hypercall_ctx	hypercall_context;

int vm_guest;

static u_int
hyperv_get_timecount(struct timecounter *tc __unused)
{
	return rdmsr(MSR_HV_TIME_REF_COUNT);
}

/**
 * @brief Invoke the specified hypercall
 */
static uint64_t
hv_vmbus_do_hypercall(uint64_t control, void* input, void* output)
{
#ifdef __x86_64__
	uint64_t hv_status = 0;
	uint64_t input_address = (input) ? hv_get_phys_addr(input) : 0;
	uint64_t output_address = (output) ? hv_get_phys_addr(output) : 0;
	volatile void *hypercall_page = hypercall_context.hc_addr;

	__asm__ __volatile__ ("mov %0, %%r8" : : "r" (output_address): "r8");
	__asm__ __volatile__ ("call *%3" : "=a"(hv_status):
				"c" (control), "d" (input_address),
				"m" (hypercall_page));
	return (hv_status);
#else
	uint32_t control_high = control >> 32;
	uint32_t control_low = control & 0xFFFFFFFF;
	uint32_t hv_status_high = 1;
	uint32_t hv_status_low = 1;
	uint64_t input_address = (input) ? hv_get_phys_addr(input) : 0;
	uint32_t input_address_high = input_address >> 32;
	uint32_t input_address_low = input_address & 0xFFFFFFFF;
	uint64_t output_address = (output) ? hv_get_phys_addr(output) : 0;
	uint32_t output_address_high = output_address >> 32;
	uint32_t output_address_low = output_address & 0xFFFFFFFF;
	volatile void *hypercall_page = hypercall_context.hc_addr;

	__asm__ __volatile__ ("call *%8" : "=d"(hv_status_high),
				"=a"(hv_status_low) : "d" (control_high),
				"a" (control_low), "b" (input_address_high),
				"c" (input_address_low),
				"D"(output_address_high),
				"S"(output_address_low), "m" (hypercall_page));
	return (hv_status_low | ((uint64_t)hv_status_high << 32));
#endif /* __x86_64__ */
}

/**
 * @brief Post a message using the hypervisor message IPC.
 * (This involves a hypercall.)
 */
hv_vmbus_status
hv_vmbus_post_msg_via_msg_ipc(
	hv_vmbus_connection_id	connection_id,
	hv_vmbus_msg_type	message_type,
	void*			payload,
	size_t			payload_size)
{
	struct alignedinput {
	    uint64_t alignment8;
	    hv_vmbus_input_post_message msg;
	};

	hv_vmbus_input_post_message*	aligned_msg;
	hv_vmbus_status 		status;
	size_t				addr;

	if (payload_size > HV_MESSAGE_PAYLOAD_BYTE_COUNT)
	    return (EMSGSIZE);

	addr = (size_t) malloc(sizeof(struct alignedinput), M_DEVBUF,
			    M_ZERO | M_NOWAIT);
	KASSERT(addr != 0);
	if (addr == 0)
	    return (ENOMEM);

	aligned_msg = (hv_vmbus_input_post_message*)
	    (HV_ALIGN_UP(addr, HV_HYPERCALL_PARAM_ALIGN));

	aligned_msg->connection_id = connection_id;
	aligned_msg->message_type = message_type;
	aligned_msg->payload_size = payload_size;
	memcpy((void*) aligned_msg->payload, payload, payload_size);

	status = hv_vmbus_do_hypercall(
		    HV_CALL_POST_MESSAGE, aligned_msg, 0) & 0xFFFF;

	free((void *) addr, M_DEVBUF);
	return (status);
}

/**
 * @brief Signal an event on the specified connection using the hypervisor
 * event IPC. (This involves a hypercall.)
 */
hv_vmbus_status
hv_vmbus_signal_event(void *con_id)
{
	hv_vmbus_status status;

	status = hv_vmbus_do_hypercall(
		    HV_CALL_SIGNAL_EVENT,
		    con_id,
		    0) & 0xFFFF;

	return (status);
}


static bool
hyperv_identify(void)
{
	u_int regs[4];
	unsigned int maxleaf;

	if (vm_guest != VM_GUEST_HV)
		return (false);

	x86_cpuid(CPUID_LEAF_HV_MAXLEAF, regs);
	maxleaf = regs[0];
	if (maxleaf < CPUID_LEAF_HV_LIMITS)
		return (false);

	x86_cpuid(CPUID_LEAF_HV_INTERFACE, regs);
	if (regs[0] != CPUID_HV_IFACE_HYPERV)
		return (false);

	x86_cpuid(CPUID_LEAF_HV_FEATURES, regs);
	if ((regs[0] & CPUID_HV_MSR_HYPERCALL) == 0) {
		/*
		 * Hyper-V w/o Hypercall is impossible; someone
		 * is faking Hyper-V.
		 */
		return (false);
	}
	hyperv_features = regs[0];
	hyperv_pm_features = regs[2];
	hyperv_features3 = regs[3];

	x86_cpuid(CPUID_LEAF_HV_IDENTITY, regs);
	printf("Hyper-V Version: %d.%d.%d [SP%d]\n",
	    regs[1] >> 16, regs[1] & 0xffff, regs[0], regs[2]);

	/* TODO: Missing %b, print features */
	printf("  Features=0x%x\n", hyperv_features);
	printf("  PM Features=0x%x [C%u]\n",
	    (hyperv_pm_features & ~CPUPM_HV_CSTATE_MASK),
	    CPUPM_HV_CSTATE(hyperv_pm_features));
	printf("  Features3=0x%x\n", hyperv_features3);

	x86_cpuid(CPUID_LEAF_HV_RECOMMENDS, regs);
	hyperv_recommends = regs[0];
	if (bootverbose)
		printf("  Recommends: %08x %08x\n", regs[0], regs[1]);

	x86_cpuid(CPUID_LEAF_HV_LIMITS, regs);
	if (bootverbose) {
		printf("  Limits: Vcpu:%d Lcpu:%d Int:%d\n",
		    regs[0], regs[1], regs[2]);
	}

	if (maxleaf >= CPUID_LEAF_HV_HWFEATURES) {
		x86_cpuid(CPUID_LEAF_HV_HWFEATURES, regs);
		if (bootverbose) {
			printf("  HW Features: %08x, AMD: %08x\n",
			    regs[0], regs[3]);
		}
	}

	return (true);
}

void
hyperv_init(void)
{
	if (!hyperv_identify()) {
		/* Not Hyper-V; reset guest id to the generic one. */
		if (vm_guest == VM_GUEST_HV)
			vm_guest = VM_GUEST_VM;
		return;
	}

	/* Set guest id */
	wrmsr(MSR_HV_GUEST_OS_ID, MSR_HV_GUESTID_NETBSD);

	if (hyperv_features & CPUID_HV_MSR_TIME_REFCNT) {
		/* Register Hyper-V timecounter */
		tc_init(&hyperv_timecounter);
	}
}
/*
SYSINIT(hyperv_initialize, SI_SUB_HYPERVISOR, SI_ORDER_FIRST, hyperv_init,
    NULL);
*/

static void
hypercall_memfree(void)
{
	hyperv_dmamem_free(&hypercall_context.hc_dma,
	    hypercall_context.hc_addr);
	hypercall_context.hc_addr = NULL;
}

void
hypercall_create(void)
{
	uint64_t hc, hc_orig;

	if (vm_guest != VM_GUEST_HV)
		return;

	hypercall_context.hc_addr = hyperv_dmamem_alloc(NULL, PAGE_SIZE, 0,
	    PAGE_SIZE, &hypercall_context.hc_dma, BUS_DMA_WAITOK);
	if (hypercall_context.hc_addr == NULL) {
		printf("hyperv: Hypercall page allocation failed\n");
		/* Can't perform any Hyper-V specific actions */
		vm_guest = VM_GUEST_VM;
		return;
	}

	/* Get the 'reserved' bits, which requires preservation. */
	hc_orig = rdmsr(MSR_HV_HYPERCALL);

	/*
	 * Setup the Hypercall page.
	 *
	 * NOTE: 'reserved' bits MUST be preserved.
	 */
	hc = ((hypercall_context.hc_dma.hv_paddr >> PAGE_SHIFT) <<
	    MSR_HV_HYPERCALL_PGSHIFT) |
	    (hc_orig & MSR_HV_HYPERCALL_RSVD_MASK) |
	    MSR_HV_HYPERCALL_ENABLE;
	wrmsr(MSR_HV_HYPERCALL, hc);

	/*
	 * Confirm that Hypercall page did get setup.
	 */
	hc = rdmsr(MSR_HV_HYPERCALL);
	if ((hc & MSR_HV_HYPERCALL_ENABLE) == 0) {
		printf("hyperv: Hypercall setup failed\n");
		hypercall_memfree();
		/* Can't perform any Hyper-V specific actions */
		vm_guest = VM_GUEST_VM;
		return;
	}
	if (bootverbose)
		printf("hyperv: Hypercall created\n");
}
/*
SYSINIT(hypercall_ctor, SI_SUB_DRIVERS, SI_ORDER_FIRST, hypercall_create, NULL);
*/

void
hypercall_destroy(void)
{
	uint64_t hc;

	if (hypercall_context.hc_addr == NULL)
		return;

	/* Disable Hypercall */
	hc = rdmsr(MSR_HV_HYPERCALL);
	wrmsr(MSR_HV_HYPERCALL, (hc & MSR_HV_HYPERCALL_RSVD_MASK));
	hypercall_memfree();

	if (bootverbose)
		printf("hyperv: Hypercall destroyed\n");
}
/*
SYSUNINIT(hypercall_dtor, SI_SUB_DRIVERS, SI_ORDER_FIRST, hypercall_destroy,
    NULL);
*/
