/*
 * ARM Statistical Profiling Extensions (SPE) support
 * Copyright (c) 2017, ARM Ltd.
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

#ifndef INCLUDE__ARM_SPE_DECODER_H__
#define INCLUDE__ARM_SPE_DECODER_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "arm-spe-insn-decoder.h"

#define ARM_SPE_IN_TX		(1 << 0)
#define ARM_SPE_ABORT_TX	(1 << 1)
#define ARM_SPE_ASYNC		(1 << 2)

enum arm_spe_sample_type {
	ARM_SPE_BRANCH		= 1 << 0,
	ARM_SPE_INSTRUCTION	= 1 << 1,
	ARM_SPE_TRANSACTION	= 1 << 2,
};

enum arm_spe_period_type {
	ARM_SPE_PERIOD_NONE,
	ARM_SPE_PERIOD_INSTRUCTIONS,
	ARM_SPE_PERIOD_TICKS,
	ARM_SPE_PERIOD_MTC,
};

enum {
	ARM_SPE_ERR_NOMEM = 1,
	ARM_SPE_ERR_INTERN,
	ARM_SPE_ERR_BADPKT,
	ARM_SPE_ERR_NODATA,
	ARM_SPE_ERR_NOINSN,
	ARM_SPE_ERR_MISMAT,
	ARM_SPE_ERR_OVR,
	ARM_SPE_ERR_LOST,
	ARM_SPE_ERR_UNK,
	ARM_SPE_ERR_NELOOP,
	ARM_SPE_ERR_MAX,
};

struct arm_spe_state {
	enum arm_spe_sample_type type;
	int err;
	uint64_t from_ip;
	uint64_t to_ip;
	uint64_t cr3;
	uint64_t tot_insn_cnt;
	uint64_t timestamp;
	uint64_t est_timestamp;
	uint64_t trace_nr;
	uint32_t flags;
	enum arm_spe_insn_op insn_op;
};

struct arm_spe_insn;

struct arm_spe_buffer {
	const unsigned char *buf;
	size_t len;
	bool consecutive;
	uint64_t ref_timestamp;
	uint64_t trace_nr;
};

struct arm_spe_params {
	int (*get_trace)(struct arm_spe_buffer *buffer, void *data);
	int (*walk_insn)(struct arm_spe_insn *arm_spe_insn,
			 uint64_t *insn_cnt_ptr, uint64_t *ip, uint64_t to_ip,
			 uint64_t max_insn_cnt, void *data);
	void *data;
	bool return_compression;
	uint64_t period;
	enum arm_spe_period_type period_type;
	unsigned max_non_turbo_ratio;
	unsigned int mtc_period;
	uint32_t tsc_ctc_ratio_n;
	uint32_t tsc_ctc_ratio_d;
};

struct arm_spe_decoder;

struct arm_spe_decoder *arm_spe_decoder_new(struct arm_spe_params *params);
void arm_spe_decoder_free(struct arm_spe_decoder *decoder);

const struct arm_spe_state *arm_spe_decode(struct arm_spe_decoder *decoder);

unsigned char *arm_spe_find_overlap(unsigned char *buf_a, size_t len_a,
				     unsigned char *buf_b, size_t len_b,
				     bool have_tsc);

int arm_spe__strerror(int code, char *buf, size_t buflen);

#endif
