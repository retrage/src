.include "../Makefile.inc"

.PATH:	${S}/dev/acpi/vmbus

KMOD=	vmbus
IOCONF=	vmbus.ioconf
SRCS=	pv/hyperv.c

WARNS=	4

.include <bsd.kmodule.mk>
