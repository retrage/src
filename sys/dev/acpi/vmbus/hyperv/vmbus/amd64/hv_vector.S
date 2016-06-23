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
 *
 * $FreeBSD: head/sys/dev/hyperv/vmbus/amd64/hv_vector.S 298022 2016-04-15 02:20:18Z sephe $
 */

#include <machine/asm.h>

#define ALIGN_TEXT .align 16,0x90

#include <machine/frameasm.h>
#include <machine/segments.h>
#include <machine/trap.h>
#include <machine/specialreg.h>

#include "assym.h"

/*
 * This is the Hyper-V vmbus channel direct callback interrupt.
 * Only used when it is running on Hyper-V.
 */

	.text
NENTRY(hv_vmbus_callback)
	movq	(%rsp),%rcx
	movq	8(%rsp),%r11
	addq	$16,%rsp
	pushq	$0  # Dummy error code
	pushq	$T_ASTFLT
	INTRENTRY
	# sti??
	movq	%rsp, %rdi
	subq	$8, %rdi; /* don't forget if_ppl */
	call	hv_vector_handler
	testb	$SEL_RPL,TF_CS(%rsp)
	jnz	doreti_checkast
1:
	INTRFASTEXIT
END(hv_vmbus_callback)
