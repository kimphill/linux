/*
 * arm_spe_insn_decoder.c: Intel Processor Trace support
 * Copyright (c) 2013-2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <byteswap.h>

#include "event.h"

#include "insn.h"

#if 0
#include "inat.c"
#include "insn.c"
#endif

#include "arm-spe-insn-decoder.h"

/* Based on branch_type() from perf_event_intel_lbr.c */
static void arm_spe_insn_decoder(struct insn *insn,
				  struct arm_spe_insn *arm_spe_insn)
{
	enum arm_spe_insn_op op = ARM_SPE_OP_OTHER;
	enum arm_spe_insn_branch branch = ARM_SPE_BR_NO_BRANCH;
	int ext;

	if (insn_is_avx(insn)) {
		arm_spe_insn->op = ARM_SPE_OP_OTHER;
		arm_spe_insn->branch = ARM_SPE_BR_NO_BRANCH;
		arm_spe_insn->length = insn->length;
		return;
	}

	switch (insn->opcode.bytes[0]) {
	case 0xf:
		switch (insn->opcode.bytes[1]) {
		case 0x05: /* syscall */
		case 0x34: /* sysenter */
			op = ARM_SPE_OP_SYSCALL;
			branch = ARM_SPE_BR_INDIRECT;
			break;
		case 0x07: /* sysret */
		case 0x35: /* sysexit */
			op = ARM_SPE_OP_SYSRET;
			branch = ARM_SPE_BR_INDIRECT;
			break;
		case 0x80 ... 0x8f: /* jcc */
			op = ARM_SPE_OP_JCC;
			branch = ARM_SPE_BR_CONDITIONAL;
			break;
		default:
			break;
		}
		break;
	case 0x70 ... 0x7f: /* jcc */
		op = ARM_SPE_OP_JCC;
		branch = ARM_SPE_BR_CONDITIONAL;
		break;
	case 0xc2: /* near ret */
	case 0xc3: /* near ret */
	case 0xca: /* far ret */
	case 0xcb: /* far ret */
		op = ARM_SPE_OP_RET;
		branch = ARM_SPE_BR_INDIRECT;
		break;
	case 0xcf: /* iret */
		op = ARM_SPE_OP_IRET;
		branch = ARM_SPE_BR_INDIRECT;
		break;
	case 0xcc ... 0xce: /* int */
		op = ARM_SPE_OP_INT;
		branch = ARM_SPE_BR_INDIRECT;
		break;
	case 0xe8: /* call near rel */
		op = ARM_SPE_OP_CALL;
		branch = ARM_SPE_BR_UNCONDITIONAL;
		break;
	case 0x9a: /* call far absolute */
		op = ARM_SPE_OP_CALL;
		branch = ARM_SPE_BR_INDIRECT;
		break;
	case 0xe0 ... 0xe2: /* loop */
		op = ARM_SPE_OP_LOOP;
		branch = ARM_SPE_BR_CONDITIONAL;
		break;
	case 0xe3: /* jcc */
		op = ARM_SPE_OP_JCC;
		branch = ARM_SPE_BR_CONDITIONAL;
		break;
	case 0xe9: /* jmp */
	case 0xeb: /* jmp */
		op = ARM_SPE_OP_JMP;
		branch = ARM_SPE_BR_UNCONDITIONAL;
		break;
	case 0xea: /* far jmp */
		op = ARM_SPE_OP_JMP;
		branch = ARM_SPE_BR_INDIRECT;
		break;
	case 0xff: /* call near absolute, call far absolute ind */
		ext = (insn->modrm.bytes[0] >> 3) & 0x7;
		switch (ext) {
		case 2: /* near ind call */
		case 3: /* far ind call */
			op = ARM_SPE_OP_CALL;
			branch = ARM_SPE_BR_INDIRECT;
			break;
		case 4:
		case 5:
			op = ARM_SPE_OP_JMP;
			branch = ARM_SPE_BR_INDIRECT;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	arm_spe_insn->op = op;
	arm_spe_insn->branch = branch;
	arm_spe_insn->length = insn->length;

	if (branch == ARM_SPE_BR_CONDITIONAL ||
	    branch == ARM_SPE_BR_UNCONDITIONAL) {
#if __BYTE_ORDER == __BIG_ENDIAN
		switch (insn->immediate.nbytes) {
		case 1:
			arm_spe_insn->rel = insn->immediate.value;
			break;
		case 2:
			arm_spe_insn->rel =
					bswap_16((short)insn->immediate.value);
			break;
		case 4:
			arm_spe_insn->rel = bswap_32(insn->immediate.value);
			break;
		default:
			arm_spe_insn->rel = 0;
			break;
		}
#else
		arm_spe_insn->rel = insn->immediate.value;
#endif
	}
}

int arm_spe_get_insn(const unsigned char *buf, size_t len, int x86_64,
		      struct arm_spe_insn *arm_spe_insn)
{
	struct insn insn;

	insn_init(&insn, buf, len, x86_64);
	insn_get_length(&insn);
	if (!insn_complete(&insn) || insn.length > len)
		return -1;
	arm_spe_insn_decoder(&insn, arm_spe_insn);
	if (insn.length < ARM_SPE_INSN_DBG_BUF_SZ)
		memcpy(arm_spe_insn->buf, buf, insn.length);
	else
		memcpy(arm_spe_insn->buf, buf, ARM_SPE_INSN_DBG_BUF_SZ);
	return 0;
}

const char *arm_branch_name[] = {
	[ARM_SPE_OP_OTHER]	= "Other",
	[ARM_SPE_OP_CALL]	= "Call",
	[ARM_SPE_OP_RET]	= "Ret",
	[ARM_SPE_OP_JCC]	= "Jcc",
	[ARM_SPE_OP_JMP]	= "Jmp",
	[ARM_SPE_OP_LOOP]	= "Loop",
	[ARM_SPE_OP_IRET]	= "IRet",
	[ARM_SPE_OP_INT]	= "Int",
	[ARM_SPE_OP_SYSCALL]	= "Syscall",
	[ARM_SPE_OP_SYSRET]	= "Sysret",
};

const char *arm_spe_insn_name(enum arm_spe_insn_op op)
{
	return arm_branch_name[op];
}

int arm_spe_insn_desc(const struct arm_spe_insn *arm_spe_insn, char *buf,
		       size_t buf_len)
{
	switch (arm_spe_insn->branch) {
	case ARM_SPE_BR_CONDITIONAL:
	case ARM_SPE_BR_UNCONDITIONAL:
		return snprintf(buf, buf_len, "%s %s%d",
				arm_spe_insn_name(arm_spe_insn->op),
				arm_spe_insn->rel > 0 ? "+" : "",
				arm_spe_insn->rel);
	case ARM_SPE_BR_NO_BRANCH:
	case ARM_SPE_BR_INDIRECT:
		return snprintf(buf, buf_len, "%s",
				arm_spe_insn_name(arm_spe_insn->op));
	default:
		break;
	}
	return 0;
}

size_t arm_spe_insn_max_size(void)
{
	return MAX_INSN_SIZE;
}

int arm_spe_insn_type(enum arm_spe_insn_op op)
{
	switch (op) {
	case ARM_SPE_OP_OTHER:
		return 0;
	case ARM_SPE_OP_CALL:
		return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_CALL;
	case ARM_SPE_OP_RET:
		return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_RETURN;
	case ARM_SPE_OP_JCC:
		return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_CONDITIONAL;
	case ARM_SPE_OP_JMP:
		return PERF_IP_FLAG_BRANCH;
	case ARM_SPE_OP_LOOP:
		return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_CONDITIONAL;
	case ARM_SPE_OP_IRET:
		return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_RETURN |
		       PERF_IP_FLAG_INTERRUPT;
	case ARM_SPE_OP_INT:
		return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_CALL |
		       PERF_IP_FLAG_INTERRUPT;
	case ARM_SPE_OP_SYSCALL:
		return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_CALL |
		       PERF_IP_FLAG_SYSCALLRET;
	case ARM_SPE_OP_SYSRET:
		return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_RETURN |
		       PERF_IP_FLAG_SYSCALLRET;
	default:
		return 0;
	}
}
