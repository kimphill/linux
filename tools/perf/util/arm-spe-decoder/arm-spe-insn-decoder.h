/*
 * arm_spe_insn_decoder.h: Intel Processor Trace support
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

#ifndef INCLUDE__ARM_SPE_INSN_DECODER_H__
#define INCLUDE__ARM_SPE_INSN_DECODER_H__

#include <stddef.h>
#include <stdint.h>

#define ARM_SPE_INSN_DESC_MAX		32
#define ARM_SPE_INSN_DBG_BUF_SZ	16

enum arm_spe_insn_op {
	ARM_SPE_OP_OTHER,
	ARM_SPE_OP_CALL,
	ARM_SPE_OP_RET,
	ARM_SPE_OP_JCC,
	ARM_SPE_OP_JMP,
	ARM_SPE_OP_LOOP,
	ARM_SPE_OP_IRET,
	ARM_SPE_OP_INT,
	ARM_SPE_OP_SYSCALL,
	ARM_SPE_OP_SYSRET,
};

enum arm_spe_insn_branch {
	ARM_SPE_BR_NO_BRANCH,
	ARM_SPE_BR_INDIRECT,
	ARM_SPE_BR_CONDITIONAL,
	ARM_SPE_BR_UNCONDITIONAL,
};

struct arm_spe_insn {
	enum arm_spe_insn_op		op;
	enum arm_spe_insn_branch	branch;
	int				length;
	int32_t				rel;
	unsigned char			buf[ARM_SPE_INSN_DBG_BUF_SZ];
};

int arm_spe_get_insn(const unsigned char *buf, size_t len, int x86_64,
		      struct arm_spe_insn *arm_spe_insn);

const char *arm_spe_insn_name(enum arm_spe_insn_op op);

int arm_spe_insn_desc(const struct arm_spe_insn *arm_spe_insn, char *buf,
		       size_t buf_len);

size_t arm_spe_insn_max_size(void);

int arm_spe_insn_type(enum arm_spe_insn_op op);

#endif
