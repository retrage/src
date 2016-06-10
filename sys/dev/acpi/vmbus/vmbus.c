
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/types.h>
#include <sys/condvar.h>
#include <sys/cpu.h>
#include <sys/reboot.h>
#include <sys/lock.h>

#include <dev/acpi/acpivar.h>

#include <machine/cpufunc.h>

#include <dev/acpi/vmbus/hyperv/include/hyperv_busdma.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hv_sema.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hv_vmbus_priv.h>

#include <dev/acpi/vmbus/hyperv/vmbus/hyperv_reg.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hyperv_var.h>
#include <dev/acpi/vmbus/hyperv/vmbus/vmbus_var.h>

#define _COMPONENT	ACPI_BUS_COMPONENT
ACPI_MODULE_NAME	("vmbus")

void hv_vector_handler(struct intrframe *);

static int  vmbus_match(device_t, cfdata_t, void *);
static void vmbus_attach(device_t, device_t, void *);

struct vmbus_softc	*vmbus_sc;

static const char *vmbus_ids[] = {
	"VMBUS",
	NULL
};

extern void hv_vmbus_callback(void);

CFATTACH_DECL_NEW(vmbus, sizeof(struct vmbus_softc),
	vmbus_match, vmbus_attach, NULL, NULL);

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
	/*
	sc->vmbus_event_proc(sc, cpu);
	*/

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
		/*
		taskqueue_enqueue(VMBUS_PCPU_GET(sc, message_tq, cpu),
		    VMBUS_PCPU_PTR(sc, message_task, cpu));
		*/
	}

	return 0;
}

void
hv_vector_handler(struct intrframe *regs)
{
	struct vmbus_softc *sc = vmbus_get_softc();
	int cpu = cpu_index(curcpu());

	/*
	 * Disable preemption.
	 */
	kpreempt_disable();

	/*
	 * Do a little interrupt counting.
	 */
	(VMBUS_PCPU_GET(sc, intr_cnt, cpu).ev_count)++;

	hv_vmbus_isr(sc, regs, cpu);

	/*
	 * Enable preemption.
	 */
	kpreempt_enable();
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

	for (CPU_INFO_FOREACH(cii, ci)) {
		char buf[MAXCOMLEN + 1];
		/*
		cpuset_t cpu_mask;
		*/

		/* Allocate an interrupt counter for Hyper-V interrupt */
		snprintf(buf, sizeof(buf), "cpu%d:hyperv", cpu_index(ci));
		evcnt_attach_dynamic(VMBUS_PCPU_PTR(sc, intr_cnt, cpu_index(ci)),
		    EVCNT_TYPE_INTR, NULL, "hyperv", buf);

		/*
		 * Setup workqueue to handle events.  Task will be per-
		 * channel.
		 */
		/*
		VMBUS_PCPU_GET(sc, event_tq, cpu) = taskqueue_create_fast(
		    "hyperv event", M_WAITOK, taskqueue_thread_enqueue,
		    VMBUS_PCPU_PTR(sc, event_tq, cpu));
		CPU_SETOF(cpu, &cpu_mask);
		taskqueue_start_threads_cpuset(
		    VMBUS_PCPU_PTR(sc, event_tq, cpu), 1, PI_NET, &cpu_mask,
		    "hvevent%d", cpu);
		*/

		/*
		 * Setup tasks and taskqueues to handle messages.
		 */
		/*
		VMBUS_PCPU_GET(sc, message_tq, cpu) = taskqueue_create_fast(
		    "hyperv msg", M_WAITOK, taskqueue_thread_enqueue,
		    VMBUS_PCPU_PTR(sc, message_tq, cpu));
		CPU_SETOF(cpu, &cpu_mask);
		taskqueue_start_threads_cpuset(
		    VMBUS_PCPU_PTR(sc, message_tq, cpu), 1, PI_NET, &cpu_mask,
		    "hvmsg%d", cpu);
		TASK_INIT(VMBUS_PCPU_PTR(sc, message_task, cpu), 0,
		    vmbus_msg_task, sc);
		*/
	}

	/*
	 * All Hyper-V ISR required resources are setup, now let's find a
	 * free IDT vector for Hyper-V ISR and set it up.
	 */
	sc->vmbus_idtvec = idt_vec_alloc(0x00, 0xff);
	if (sc->vmbus_idtvec < 0) {
		device_printf(sc->vmbus_dev, "cannot find free IDT vector\n");
		return ENXIO;
	}
	idt_vec_set(sc->vmbus_idtvec, hv_vmbus_callback);

	if(bootverbose) {
		device_printf(sc->vmbus_dev, "vmbus IDT vector %d\n",
		    sc->vmbus_idtvec);
	}
	return 0;
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
	ipi_msg_t ipimsg = { .func = (ipi_func_t)vmbus_synic_setup, .arg = sc };
	struct vmbus_softc *sc = vmbus_get_softc();
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

	if (ret != 0)
		goto cleanup;

	if (hv_vmbus_protocal_version == HV_VMBUS_VERSION_WS2008 ||
	    hv_vmbus_protocal_version == HV_VMBUS_VERSION_WIN7)
		sc->vmbus_event_proc = vmbus_event_proc_compat;
	else
		sc->vmbus_event_proc = vmbus_event_proc;

	/*
	hv_vmbus_request_channel_offers();

	vmbus_scan();
	*/
	/*
	bus_generic_attach(sc->vmbus_dev);
	device_printf(sc->vmbus_dev, "device scan, probe and attach done\n");
	*/

	return (ret);

cleanup:
	/*
	vmbus_intr_teardown(sc);
	*/
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
	/* FreeBSD's implementation uses SYSINIT to init hyperv and  */

	vm_guest = VM_GUEST_HV;

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
