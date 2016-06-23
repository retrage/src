
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/types.h>
#include <sys/condvar.h>
#include <sys/cpu.h>
#include <sys/reboot.h>
#include <sys/lock.h>
#include <sys/workqueue.h>
#include <sys/mutex.h>

#include <dev/acpi/acpivar.h>

#include <machine/i82489var.h>

#include <machine/cpufunc.h>

#include <dev/acpi/vmbus/hyperv/include/hyperv_busdma.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hv_sema.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hv_vmbus_priv.h>

#include <dev/acpi/vmbus/hyperv/vmbus/hyperv_reg.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hyperv_var.h>
#include <dev/acpi/vmbus/hyperv/vmbus/vmbus_var.h>

#define _COMPONENT	ACPI_BUS_COMPONENT
ACPI_MODULE_NAME	("vmbus")

/*
void hv_vector_handler(struct intrframe *);
*/
void hv_vector_handler(void);

static int  vmbus_match(device_t, cfdata_t, void *);
static void vmbus_attach(device_t, device_t, void *);
static int  vmbus_detach(device_t, int);

kmutex_t		vmbus_chwait_lock;

struct workqueue	*hv_workqueue;

struct vmbus_softc	*vmbus_sc;

static const char *vmbus_ids[] = {
	"VMBUS",
	NULL
};

extern void hv_vmbus_callback(void);

CFATTACH_DECL3_NEW(vmbus, sizeof(struct vmbus_softc),
	vmbus_match, vmbus_attach, vmbus_detach, NULL, NULL, NULL, 0);

/**
 * @brief Interrupt filter routine for VMBUS.
 *
 * The purpose of this routine is to determine the type of VMBUS protocol
 * message to process - an event or a channel message.
 */
static inline int
hv_vmbus_isr(struct vmbus_softc *sc, struct intrframe *frame, int cpu)
{
	hv_vmbus_message *msg, *msg_base;

	/*
	 * The Windows team has advised that we check for events
	 * before checking for messages. This is the way they do it
	 * in Windows when running as a guest in Hyper-V
	 */
	sc->vmbus_event_proc(sc, cpu);

	/* Check if there are actual msgs to be process */
	msg_base = VMBUS_PCPU_GET(sc, message, cpu);
	msg = msg_base + HV_VMBUS_TIMER_SINT;

	/* we call eventtimer process the message */
	if (msg->header.message_type == HV_MESSAGE_TIMER_EXPIRED) {
		msg->header.message_type = HV_MESSAGE_TYPE_NONE;

		/* call intrrupt handler of event timer */
		/*
		hv_et_intr(frame);
		*/

		/*
		 * Make sure the write to message_type (ie set to
		 * HV_MESSAGE_TYPE_NONE) happens before we read the
		 * message_pending and EOMing. Otherwise, the EOMing will
		 * not deliver any more messages
		 * since there is no empty slot
		 *
		 * NOTE:
		 * mb() is used here, since atomic_thread_fence_seq_cst()
		 * will become compiler fence on UP kernel.
		 */
		x86_mfence();

		if (msg->header.message_flags.u.message_pending) {
			/*
			 * This will cause message queue rescan to possibly
			 * deliver another msg from the hypervisor
			 */
			wrmsr(MSR_HV_EOM, 0);
		}
	}

	msg = msg_base + HV_VMBUS_MESSAGE_SINT;
	if (msg->header.message_type != HV_MESSAGE_TYPE_NONE) {
		CPU_INFO_ITERATOR cii;
		struct cpu_info *ci;

		for (CPU_INFO_FOREACH(cii, ci)) {
			if (cpu_index(ci) == cpu) {
				workqueue_enqueue(VMBUS_PCPU_GET(sc, message_tq, cpu),
					VMBUS_PCPU_GET(sc, message_task, cpu), ci);
			}
		}
	}

	return 0;
}

void
hv_vector_handler(void)
{
	struct vmbus_softc *sc = vmbus_get_softc();
	int cpu = cpu_index(curcpu());

	printf("Enter hv_vector_handler\n");

	/*
	 * Disable preemption.
	 */
	kpreempt_disable();

	/*
	 * Do a little interrupt counting.
	 */
	(VMBUS_PCPU_GET(sc, intr_cnt, cpu).ev_count)++;

	/*
	hv_vmbus_isr(sc, regs, cpu);
	*/
	hv_vmbus_isr(sc, NULL, cpu);

	/*
	 * Enable preemption.
	 */
	kpreempt_enable();

	printf("hv_vector_handler done\n");
}

static void
vmbus_synic_setup(void *xsc)
{
	struct vmbus_softc *sc = xsc;
	int cpu = cpu_index(curcpu());
	uint64_t val, orig;
	uint32_t sint;

	if (hyperv_features & CPUID_HV_MSR_VP_INDEX) {
		/*
		 * Save virtual processor id.
		 */
		VMBUS_PCPU_GET(sc, vcpuid, cpu) = rdmsr(MSR_HV_VP_INDEX);
	} else {
		/*
		 * XXX
		 * Virtual processoor id is only used by a pretty broken
		 * channel selection code from storvsc.  It's nothing
		 * critical even if CPUID_HV_MSR_VP_INDEX is not set; keep
		 * moving on.
		 */
		VMBUS_PCPU_GET(sc, vcpuid, cpu) = cpu;
	}

	/*
	 * Setup the SynIC message.
	 */
	orig = rdmsr(MSR_HV_SIMP);
	val = MSR_HV_SIMP_ENABLE | (orig & MSR_HV_SIMP_RSVD_MASK) |
	    ((VMBUS_PCPU_GET(sc, message_dma.hv_paddr, cpu) >> PAGE_SHIFT) <<
	     MSR_HV_SIMP_PGSHIFT);
	wrmsr(MSR_HV_SIMP, val);

	/*
	 * Setup the SynIC event flags.
	 */
	orig = rdmsr(MSR_HV_SIEFP);
	val = MSR_HV_SIEFP_ENABLE | (orig & MSR_HV_SIEFP_RSVD_MASK) |
	    ((VMBUS_PCPU_GET(sc, event_flag_dma.hv_paddr, cpu) >> PAGE_SHIFT) <<
	     MSR_HV_SIEFP_PGSHIFT);
	wrmsr(MSR_HV_SIEFP, val);

	/*
	 * Configure and unmask SINT for message and event flags.
	 */
	sint = MSR_HV_SINT0 + HV_VMBUS_MESSAGE_SINT;
	orig = rdmsr(sint);
	val = sc->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
	    (orig & MSR_HV_SINT_RSVD_MASK);
	wrmsr(sint, val);

	/*
	 * Configure and unmask SINT for timer.
	 */
	sint = MSR_HV_SINT0 + HV_VMBUS_TIMER_SINT;
	orig = rdmsr(sint);
	val = sc->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
	    (orig & MSR_HV_SINT_RSVD_MASK);
	wrmsr(sint, val);

	/*
	 * All done; enable SynIC.
	 */
	orig = rdmsr(MSR_HV_SCONTROL);
	val = MSR_HV_SCTRL_ENABLE | (orig & MSR_HV_SCTRL_RSVD_MASK);
	wrmsr(MSR_HV_SCONTROL, val);
}

static void
vmbus_synic_teardown(void *arg)
{
	uint64_t orig;
	uint32_t sint;

	/*
	 * Disable SynIC.
	 */
	orig = rdmsr(MSR_HV_SCONTROL);
	wrmsr(MSR_HV_SCONTROL, (orig & MSR_HV_SCTRL_RSVD_MASK));

	/*
	 * Mask message and event flags SINT.
	 */
	sint = MSR_HV_SINT0 + HV_VMBUS_MESSAGE_SINT;
	orig = rdmsr(sint);
	wrmsr(sint, orig | MSR_HV_SINT_MASKED);

	/*
	 * Mask timer SINT.
	 */
	sint = MSR_HV_SINT0 + HV_VMBUS_TIMER_SINT;
	orig = rdmsr(sint);
	wrmsr(sint, orig | MSR_HV_SINT_MASKED);

	/*
	 * Teardown SynIC message.
	 */
	orig = rdmsr(MSR_HV_SIMP);
	wrmsr(MSR_HV_SIMP, (orig & MSR_HV_SIMP_RSVD_MASK));

	/*
	 * Teardown SynIC event flags.
	 */
	orig = rdmsr(MSR_HV_SIEFP);
	wrmsr(MSR_HV_SIEFP, (orig & MSR_HV_SIEFP_RSVD_MASK));
}

static int
vmbus_dma_alloc(struct vmbus_softc *sc)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;

	for (CPU_INFO_FOREACH(cii, ci)) {
		void *ptr;

		/*
		 * Per-cpu messages and event flags.
		 */
		ptr = (void *)uvm_km_alloc(kernel_map, PAGE_SIZE, 0,
		    UVM_KMF_ZERO | UVM_KMF_WIRED);
		if (ptr == NULL)
			return ENOMEM;
		VMBUS_PCPU_GET(sc, message, cpu_index(ci)) = ptr;

		ptr = (void *)uvm_km_alloc(kernel_map, PAGE_SIZE, 0,
		    UVM_KMF_ZERO | UVM_KMF_WIRED);
		if (ptr == NULL)
			return ENOMEM;
		VMBUS_PCPU_GET(sc, event_flag, cpu_index(ci)) = ptr;
	}

	return 0;
}

static void
vmbus_dma_free(struct vmbus_softc *sc)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;

	for (CPU_INFO_FOREACH(cii, ci)) {
		if (VMBUS_PCPU_GET(sc, message, cpu_index(ci)) != NULL) {
			uvm_km_free(kernel_map,
			    (vaddr_t)VMBUS_PCPU_PTR(sc, message, cpu_index(ci)),
			    PAGE_SIZE, UVM_KMF_ZERO | UVM_KMF_WIRED);
			VMBUS_PCPU_GET(sc, message, cpu_index(ci)) = NULL;
		}
		if (VMBUS_PCPU_GET(sc, event_flag, cpu_index(ci)) != NULL) {
			uvm_km_free(kernel_map,
			    (vaddr_t)VMBUS_PCPU_PTR(sc, event_flag, cpu_index(ci)),
			    PAGE_SIZE, UVM_KMF_ZERO | UVM_KMF_WIRED);
			VMBUS_PCPU_GET(sc, event_flag, cpu_index(ci)) = NULL;
		}
	}
}

static int
vmbus_intr_setup(struct vmbus_softc *sc)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	struct workqueue *event_tq;
	struct workqueue *message_tq;

	/*
	 * On FreeBSD, the driver has taskqueues for earch cpu.
	 * On this driver, it has one workqueue with WQ_PERCPU.
	 * Each sc->*_tq of CPU pointer is same.
	 */

	/*
	 * Setup workqueue to handle events.  Task will be per-
	 * channel.
	 */
	workqueue_create(&event_tq, "hyperv event",
		NULL, NULL, PRI_NONE, IPL_HIGH, WQ_PERCPU | WQ_MPSAFE);

	/*
	 * Setup workqueue to handle messages.
	 */
	workqueue_create(&message_tq, "hyperv message",
		NULL, NULL, PRI_NONE, IPL_HIGH, WQ_PERCPU | WQ_MPSAFE);

	for (CPU_INFO_FOREACH(cii, ci)) {
		char buf[MAXCOMLEN + 1];
		u_int cpu_idx = cpu_index(ci);

		/* Allocate an interrupt counter for Hyper-V interrupt */
		snprintf(buf, sizeof(buf), "cpu%d:hyperv", cpu_idx);
		evcnt_attach_dynamic(VMBUS_PCPU_PTR(sc, intr_cnt, cpu_idx),
		    EVCNT_TYPE_INTR, NULL, "hyperv", buf);

		VMBUS_PCPU_GET(sc, event_tq, cpu_idx) = event_tq;
		VMBUS_PCPU_GET(sc, message_tq, cpu_idx) = message_tq;
	}

	/*
	TASK_INIT(VMBUS_PCPU_PTR(sc, message_task, cpu), 0,
	    vmbus_msg_task, sc);
	*/

	/*
	 * All Hyper-V ISR required resources are setup, now let's find a
	 * free IDT vector for Hyper-V ISR and set it up.
	 */
	/*
	sc->vmbus_idtvec = idt_vec_alloc(0x00, 0xff);
	if (sc->vmbus_idtvec < 0) {
		device_printf(sc->vmbus_dev, "cannot find free IDT vector\n");
		return ENXIO;
	}
	idt_vec_set(sc->vmbus_idtvec, hv_vmbus_callback);
	*/

	sc->vmbus_idtvec = LAPIC_HV_VECTOR;
	if(bootverbose) {
		device_printf(sc->vmbus_dev, "vmbus IDT vector %d\n",
		    sc->vmbus_idtvec);
	}
	return 0;
}

static void
vmbus_intr_teardown(struct vmbus_softc *sc)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;

	if (sc->vmbus_idtvec >= 0) {
		idt_vec_free(sc->vmbus_idtvec);
		sc->vmbus_idtvec = -1;
	}

	/* Destroy workqueue */
	workqueue_destroy(VMBUS_PCPU_GET(sc, event_tq, 0));

	/*
	taskqueue_drain(VMBUS_PCPU_GET(sc, message_tq, cpu),
	    VMBUS_PCPU_PTR(sc, message_task, cpu));
	*/
	workqueue_destroy(VMBUS_PCPU_GET(sc, message_tq, 0));

	for (CPU_INFO_FOREACH(cii, ci)) {
		u_int cpu_idx = cpu_index(ci);

		if (VMBUS_PCPU_GET(sc, event_tq, cpu_idx) != NULL) {
			VMBUS_PCPU_GET(sc, event_tq, cpu_idx) = NULL;
		}
		if (VMBUS_PCPU_GET(sc, message_tq, cpu_idx) != NULL) {
			VMBUS_PCPU_GET(sc, message_tq, cpu_idx) = NULL;
		}
	}
}

/*
static int
vmbus_child_pnpinfo_str(device_t dev, device_t child, char *buf, size_t buflen)
{
	char guidbuf[40];
	struct hv_device *dev_ctx = device_get_ivars(child);

	if (dev_ctx == NULL)
		return (0);

	strlcat(buf, "classid=", buflen);
	snprintf_hv_guid(guidbuf, sizeof(guidbuf), &dev_ctx->class_id);
	strlcat(buf, guidbuf, buflen);

	strlcat(buf, " deviceid=", buflen);
	snprintf_hv_guid(guidbuf, sizeof(guidbuf), &dev_ctx->device_id);
	strlcat(buf, guidbuf, buflen);

	return (0);
}
*/

struct hv_device *
hv_vmbus_child_device_create(hv_guid type, hv_guid instance,
    hv_vmbus_channel *channel)
{
	hv_device *child_dev;

	/*
	 * Allocate the new child device
	 */
	child_dev = malloc(sizeof(hv_device), M_DEVBUF, M_WAITOK | M_ZERO);

	child_dev->channel = channel;
	memcpy(&child_dev->class_id, &type, sizeof(hv_guid));
	memcpy(&child_dev->device_id, &instance, sizeof(hv_guid));

	return (child_dev);
}

int
snprintf_hv_guid(char *buf, size_t sz, const hv_guid *guid)
{
	int cnt;
	const unsigned char *d = guid->data;

	cnt = snprintf(buf, sz,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d[3], d[2], d[1], d[0], d[5], d[4], d[7], d[6],
		d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
	return (cnt);
}

int
hv_vmbus_child_device_register(struct hv_device *child_dev)
{
	/*
	device_t child;
	*/

	if (bootverbose) {
		char name[40];
		snprintf_hv_guid(name, sizeof(name), &child_dev->class_id);
		printf("VMBUS: Class ID: %s\n", name);
	}

	/*
	child = device_add_child(vmbus_get_device(), NULL, -1);
	child_dev->device = child;
	device_set_ivars(child, child_dev);

	return (0);
	*/
	return (0);
}

int
hv_vmbus_child_device_unregister(struct hv_device *child_dev)
{
	int ret = 0;
	/*
	 * XXXKYS: Ensure that this is the opposite of
	 * device_add_child()
	 */
/*
	mtx_lock(&Giant);
	ret = device_delete_child(vmbus_get_device(), child_dev->device);
	mtx_unlock(&Giant);
*/
	return(ret);
}

static int
vmbus_match(device_t parent, cfdata_t match, void *aux)
{
	struct acpi_attach_args *aa = aux;

	if (aa->aa_node->ad_type != ACPI_TYPE_DEVICE)
		return 0;

	if (acpi_match_hid(aa->aa_node->ad_devinfo, vmbus_ids))
		return 1;

	return 0;
}

/**
 * @brief Main vmbus driver initialization routine.
 *
 * Here, we
 * - initialize the vmbus driver context
 * - setup various driver entry points
 * - invoke the vmbus hv main init routine
 * - get the irq resource
 * - invoke the vmbus to add the vmbus root device
 * - setup the vmbus root device
 * - retrieve the channel offers
 */
static int
vmbus_bus_init(void)
{
	struct vmbus_softc *sc = vmbus_get_softc();
	ipi_msg_t ipimsg = { .func = (ipi_func_t)vmbus_synic_setup, .arg = sc };
	int ret;

	if (sc->vmbus_flags & VMBUS_FLAG_ATTACHED)
		return (0);
	sc->vmbus_flags |= VMBUS_FLAG_ATTACHED;

	/*
	 * Allocate DMA stuffs.
	 */
	ret = vmbus_dma_alloc(sc);
	if (ret != 0)
		goto cleanup;

	/*
	 * Setup interrupt.
	 */
	ret = vmbus_intr_setup(sc);
	if (ret != 0)
		goto cleanup;

	/*
	 * Setup SynIC.
	 */
	kpreempt_disable();
	ipi_broadcast(&ipimsg);
	ipi_wait(&ipimsg);
	kpreempt_enable();

	sc->vmbus_flags |= VMBUS_FLAG_SYNIC;

	/*
	 * Connect to VMBus in the root partition
	 */
	ret = hv_vmbus_connect();
	printf("hv_vmbus_connect done\n");

	if (ret != 0)
		goto cleanup;

	if (hv_vmbus_protocal_version == HV_VMBUS_VERSION_WS2008 ||
	    hv_vmbus_protocal_version == HV_VMBUS_VERSION_WIN7)
		sc->vmbus_event_proc = vmbus_event_proc_compat;
	else
		sc->vmbus_event_proc = vmbus_event_proc;

	hv_vmbus_request_channel_offers();

	vmbus_scan();
	/*
	bus_generic_attach(sc->vmbus_dev);
	device_printf(sc->vmbus_dev, "device scan, probe and attach done\n");
	*/

	return (ret);

cleanup:
	vmbus_intr_teardown(sc);
	vmbus_dma_free(sc);

	return (ret);
}
static void
vmbus_event_proc_dummy(struct vmbus_softc *sc __unused, int cpu __unused)
{
}

static void
vmbus_attach(device_t parent, device_t self, void *aux)
{
	/*
	 * FreeBSD's implementation uses SYSINIT,
	 * but NetBSD does not have it.
	 * */
	vm_guest = VM_GUEST_HV;
	mutex_init(&vmbus_chwait_lock, MUTEX_DEFAULT, IPL_NONE);
	workqueue_create(&hv_workqueue, "hyperv workqueue", NULL, NULL, PRI_NONE,
		IPL_HIGH, WQ_PERCPU | WQ_MPSAFE);

	hyperv_init();

	hypercall_create();

	vmbus_sc = device_private(self);
	vmbus_sc->vmbus_dev = self;
	vmbus_sc->vmbus_idtvec = -1;

	/*
	 * Event processing logic will be configured:
	 * - After the vmbus protocol version negotiation.
	 * - Before we request channel offers.
	 */
	vmbus_sc->vmbus_event_proc = vmbus_event_proc_dummy;

	vmbus_bus_init();

	/* bus_generic_probe */
}

static int
vmbus_detach(device_t self, int flags)
{
	struct vmbus_softc *sc = device_private(self);
	ipi_msg_t ipimsg = { .func = (ipi_func_t)vmbus_synic_teardown };

	hv_vmbus_release_unattached_channels();

	hv_vmbus_disconnect();

	if (sc->vmbus_flags & VMBUS_FLAG_SYNIC) {
		sc->vmbus_flags &= ~VMBUS_FLAG_SYNIC;

		kpreempt_disable();
		ipi_broadcast(&ipimsg);
		ipi_wait(&ipimsg);
		kpreempt_enable();
	}

	vmbus_intr_teardown(sc);
	vmbus_dma_free(sc);

	mutex_destroy(&vmbus_chwait_lock);
	workqueue_destroy(hv_workqueue);

	return (0);
}
