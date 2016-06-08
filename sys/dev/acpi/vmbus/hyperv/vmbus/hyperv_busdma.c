/*-
 * Copyright (c) 2016 Microsoft Corp.
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

#include <sys/cdefs.h>
/*
__FBSDID("$FreeBSD: head/sys/dev/hyperv/vmbus/hyperv_busdma.c 300568 2016-05-24 05:26:52Z sephe $");
*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kmem.h>

#include <dev/acpi/vmbus/hyperv/include/hyperv_busdma.h>

/*
 * missing BUS_DMA_ZERO
 */
#define HYPERV_DMA_MASK	(BUS_DMA_WAITOK | BUS_DMA_NOWAIT)

void *
hyperv_dmamem_alloc(bus_dma_tag_t parent_dtag, bus_size_t alignment,
    bus_addr_t boundary, bus_size_t size, struct hyperv_dma *dma, int flags)
{
	void *ret;
	int rsegs;
	int error;

	dma->hv_segs = kmem_alloc(1 * sizeof(*dma->hv_segs), KM_SLEEP);
	if (dma->hv_segs == NULL) {
	    return NULL;
	}

	ret = NULL;
	rsegs = 0;

	printf("hyperv_dmamem_alloc: size=%lx align=%lx bound=%lx\n", size, alignment, boundary);

	error = bus_dmamem_alloc(dma->hv_dtag, /* tag */
	    size,			/* size */
	    alignment,			/* alignment */
	    boundary,			/* boundary */
	    dma->hv_segs,		/* segs */
	    1,				/* nsegs */
	    &rsegs,			/* rsegs */
	    BUS_DMA_WAITOK);		/* flags */
	if (error)
		return NULL;

	error = bus_dmamem_map(dma->hv_dtag, /* tag */
	    dma->hv_segs,		/* segs */
	    1,				/* nsegs */
	    size,			/* size */
	    ret,			/* kvap */
	    (flags & (HYPERV_DMA_MASK | BUS_DMA_COHERENT)));
	if (error) {
		bus_dmamap_destroy(dma->hv_dtag, dma->hv_dmap);
		return NULL;
	}

	error = bus_dmamap_create(dma->hv_dtag, /* tag */
	    size,			/* size */
	    1,				/* nsegments */
	    size,			/* maxsegsize */
	    boundary,			/* boundary */
	    (flags & HYPERV_DMA_MASK),	/* flags */
	    &dma->hv_dmap);
	if (error) {
		bus_dmamem_free(dma->hv_dtag, dma->hv_segs, rsegs);
		bus_dmamap_destroy(dma->hv_dtag, dma->hv_dmap);
		return NULL;
	}

	error = bus_dmamap_load(dma->hv_dtag, /* tag */
	    dma->hv_dmap,	/* dmam */
	    ret,		/* buf */
	    size,		/* buflen */
	    NULL,		/* p */
	    BUS_DMA_NOWAIT);
	if (error) {
		bus_dmamem_unmap(dma->hv_dtag, ret, size);
		bus_dmamem_free(dma->hv_dtag, dma->hv_segs, rsegs);
		bus_dmamap_destroy(dma->hv_dtag, dma->hv_dmap);
		return NULL;
	}
	/* XXX missing BUS_DMA_ZERO */
	memset(ret, 0, size);
	bus_dmamap_sync(dma->hv_dtag, dma->hv_dmap, 0, size, BUS_DMASYNC_PREWRITE);

	/* hyperv_dma_map_paddr */
	dma->hv_paddr = dma->hv_dmap->dm_segs[0].ds_addr;

	return ret;
}

void
hyperv_dmamem_free(struct hyperv_dma *dma, void *ptr)
{
	bus_dmamap_unload(dma->hv_dtag, dma->hv_dmap);
	bus_dmamem_free(dma->hv_dtag, ptr, 1);
	bus_dmamap_destroy(dma->hv_dtag, dma->hv_dmap);
}
