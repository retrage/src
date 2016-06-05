
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/types.h>
#include <sys/condvar.h>

#include <dev/acpi/acpivar.h>

#include <dev/acpi/vmbus/hyperv/include/hyperv_busdma.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hv_sema.h>
#include <dev/acpi/vmbus/hyperv/vmbus/hv_vmbus_priv.h>

#include <dev/acpi/vmbus/hyperv/vmbus/vmbus_var.h>

#define _COMPONENT	ACPI_BUS_COMPONENT
ACPI_MODULE_NAME	("vmbus")

static int  vmbus_match(device_t, cfdata_t, void *);
static void vmbus_attach(device_t, device_t, void *);

struct vmbus_softc	*vmbus_sc;

static const char *vmbus_ids[] = {
	"VMBUS",
	NULL
};

CFATTACH_DECL_NEW(vmbus, sizeof(struct vmbus_softc),
	vmbus_match, vmbus_attach, NULL, NULL);

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

static void
vmbus_attach(device_t parent, device_t self, void *aux)
{
}

