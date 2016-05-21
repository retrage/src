
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/types.h>

#include <dev/acpi/acpivar.h>

#define _COMPONENT	ACPI_BUS_COMPONENT
ACPI_MODULE_NAME	("vmbus")

static int  vmbus_match(device_t, cfdata_t, void *);
static void vmbus_attach(device_t, device_t, void *);

struct vmbus_softc {
	device_t	sc_dev;
};

CFATTACH_DECL_NEW(vmbus, sizeof(struct vmbus_softc),
	vmbus_match, vmbus_attach, NULL, NULL);

static int
vmbus_match(device_t parent, cfdata_t match, void *aux)
{
	struct acpi_attach_args *aaa = aux;
	struct acpi_devnode *node = aaa->aa_node;

	if (strcmp(node->ad_name, "VMB8") != 0)
		return 0;

	return 1;
}

static void
vmbus_attach(device_t parent, device_t self, void *aux)
{
}

