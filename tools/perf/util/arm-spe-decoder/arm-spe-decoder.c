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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

#include "../cache.h"
#include "../util.h"

#include "arm-spe-insn-decoder.h"
#include "arm-spe-pkt-decoder.h"
#include "arm-spe-decoder.h"
#include "arm-spe-log.h"

#define ARM_SPE_BLK_SIZE 1024

#define ARM_SPE_RETURN 1

/* Maximum number of loops with no packets consumed i.e. stuck in a loop */
#define ARM_SPE_MAX_LOOPS 10000
 
struct arm_spe_blk {
	struct arm_spe_blk *prev;
	uint64_t ip[ARM_SPE_BLK_SIZE];
};

struct arm_spe_stack {
	struct arm_spe_blk *blk;
	struct arm_spe_blk *spare;
	int pos;
};

enum arm_spe_pkt_state {
	ARM_SPE_STATE_ERROR = -1,
	ARM_SPE_STATE_RECORD_INCOMPLETE,
	ARM_SPE_STATE_RECORD_COMPLETE,
};

struct arm_spe_decoder {
	int (*get_trace)(struct arm_spe_buffer *buffer, void *data);
	int (*walk_insn)(struct arm_spe_insn *arm_spe_insn,
			 uint64_t *insn_cnt_ptr, uint64_t *ip, uint64_t to_ip,
			 uint64_t max_insn_cnt, void *data);
	void *data;
	struct arm_spe_state state;
	const unsigned char *buf;
	size_t len;
	uint64_t ip;
	uint64_t tgt_ip;
	uint64_t timestamp;
	uint64_t latency;

	/* intel remains below */
	uint64_t pos;
	uint64_t last_ip;
	uint64_t ret_addr;
	uint64_t cycle_cnt;
	struct arm_spe_stack stack;
	enum arm_spe_pkt_state pkt_state;
	struct arm_spe_pkt packet;
	int pkt_step;
	int pkt_len;
	int last_packet_type;
	unsigned int cbr;
	int exec_mode;
	uint64_t period;
	enum arm_spe_period_type period_type;
	uint64_t tot_insn_cnt;
	uint64_t period_insn_cnt;
	uint64_t period_mask;
	uint64_t period_ticks;
	uint64_t last_masked_timestamp;
	bool set_fup_tx_flags;
	unsigned int fup_tx_flags;
	unsigned int tx_flags;
	uint64_t timestamp_insn_cnt;
	uint64_t stuck_ip;
	int no_progress;
	int stuck_ip_prd;
	int stuck_ip_cnt;
	const unsigned char *next_buf;
	size_t next_len;
	unsigned char temp_buf[ARM_SPE_PKT_MAX_SZ];
};

static uint64_t arm_spe_lower_power_of_2(uint64_t x)
{
	int i;

	for (i = 0; x != 1; i++)
		x >>= 1;

	return x << i;
}

static void arm_spe_setup_period(struct arm_spe_decoder *decoder)
{
	decoder->period_type = ARM_SPE_PERIOD_NONE;
	if (decoder->period_type == ARM_SPE_PERIOD_TICKS) {
		uint64_t period;

		period = arm_spe_lower_power_of_2(decoder->period);
		decoder->period_mask  = ~(period - 1);
		decoder->period_ticks = period;
	}
}

struct arm_spe_decoder *arm_spe_decoder_new(struct arm_spe_params *params)
{
	struct arm_spe_decoder *decoder;

	if (!params->get_trace || !params->walk_insn)
		return NULL;

	decoder = zalloc(sizeof(struct arm_spe_decoder));
	if (!decoder)
		return NULL;

	decoder->get_trace          = params->get_trace;
	decoder->walk_insn          = params->walk_insn;
	decoder->data               = params->data;

	decoder->period             = params->period;
	decoder->period_type        = params->period_type;

	arm_spe_setup_period(decoder);

	return decoder;
}

static void arm_spe_pop_blk(struct arm_spe_stack *stack /*rmme: */ __maybe_unused)
{
	return;
}

static void arm_spe_clear_stack(struct arm_spe_stack *stack)
{
	while (stack->blk)
		arm_spe_pop_blk(stack);
	stack->pos = 0;
}

static void arm_spe_free_stack(struct arm_spe_stack *stack)
{
	arm_spe_clear_stack(stack);
	zfree(&stack->blk);
	zfree(&stack->spare);
}

void arm_spe_decoder_free(struct arm_spe_decoder *decoder)
{
	arm_spe_free_stack(&decoder->stack);
	free(decoder);
}

static int arm_spe_ext_err(int code)
{
	switch (code) {
	case -ENOMEM:
		return ARM_SPE_ERR_NOMEM;
	case -ENOSYS:
		return ARM_SPE_ERR_INTERN;
	case -EBADMSG:
		return ARM_SPE_ERR_BADPKT;
	case -ENODATA:
		return ARM_SPE_ERR_NODATA;
	case -EILSEQ:
		return ARM_SPE_ERR_NOINSN;
	case -ENOENT:
		return ARM_SPE_ERR_MISMAT;
	case -EOVERFLOW:
		return ARM_SPE_ERR_OVR;
	case -ENOSPC:
		return ARM_SPE_ERR_LOST;
	case -ELOOP:
		return ARM_SPE_ERR_NELOOP;
	default:
		return ARM_SPE_ERR_UNK;
	}
}

static const char *arm_spe_err_msgs[] = {
	[ARM_SPE_ERR_NOMEM]  = "Memory allocation failed",
	[ARM_SPE_ERR_INTERN] = "Internal error",
	[ARM_SPE_ERR_BADPKT] = "Bad packet",
	[ARM_SPE_ERR_NODATA] = "No more data",
	[ARM_SPE_ERR_NOINSN] = "Failed to get instruction",
	[ARM_SPE_ERR_MISMAT] = "Trace doesn't match instruction",
	[ARM_SPE_ERR_OVR]    = "Overflow packet",
	[ARM_SPE_ERR_LOST]   = "Lost trace data",
	[ARM_SPE_ERR_UNK]    = "Unknown error!",
	[ARM_SPE_ERR_NELOOP] = "Never-ending loop",
};

int arm_spe__strerror(int code, char *buf, size_t buflen)
{
	if (code < 1 || code >= ARM_SPE_ERR_MAX)
		code = ARM_SPE_ERR_UNK;
	strlcpy(buf, arm_spe_err_msgs[code], buflen);
	return 0;
}

static void arm_spe_decoder_log_packet(struct arm_spe_decoder *decoder)
{
	arm_spe_log_packet(&decoder->packet, decoder->pkt_len, decoder->pos,
			    decoder->buf);
}

static int arm_spe_bug(struct arm_spe_decoder *decoder)
{
	arm_spe_log("ERROR: Internal error\n");
	decoder->pkt_state = ARM_SPE_STATE_RECORD_INCOMPLETE;
	return -ENOSYS;
}

static inline void arm_spe_clear_tx_flags(struct arm_spe_decoder *decoder)
{
	decoder->tx_flags = 0;
}

static inline void arm_spe_update_in_tx(struct arm_spe_decoder *decoder)
{
	decoder->tx_flags = decoder->packet.payload & ARM_SPE_IN_TX;
}

static int arm_spe_bad_packet(struct arm_spe_decoder *decoder)
{
	arm_spe_clear_tx_flags(decoder);
	decoder->pkt_len = 1;
	decoder->pkt_step = 1;
	arm_spe_decoder_log_packet(decoder);
	if (decoder->pkt_state != ARM_SPE_STATE_RECORD_INCOMPLETE) {
		arm_spe_log("ERROR: Bad packet\n");
		decoder->pkt_state = ARM_SPE_STATE_ERROR;
	}
	return -EBADMSG;
}

static int arm_spe_get_data(struct arm_spe_decoder *decoder)
{
	struct arm_spe_buffer buffer = { .buf = 0, };
	int ret;

	decoder->pkt_step = 0;

	arm_spe_log("Getting more data\n");
	ret = decoder->get_trace(&buffer, decoder->data);
	if (ret)
		return ret;

	decoder->buf = buffer.buf;
	decoder->len = buffer.len;
	if (!decoder->len) {
		arm_spe_log("No more data\n");
		return -ENODATA;
	}

	if (!buffer.consecutive) {
		decoder->ip = 0;
		decoder->pkt_state = ARM_SPE_STATE_RECORD_INCOMPLETE;
		decoder->timestamp = 0;
		decoder->state.trace_nr = buffer.trace_nr;
		return -ENOLINK;
	}

	return 0;
}

static int arm_spe_get_next_data(struct arm_spe_decoder *decoder)
{
	if (!decoder->next_buf)
		return arm_spe_get_data(decoder);

	decoder->buf = decoder->next_buf;
	decoder->len = decoder->next_len;
	decoder->next_buf = 0;
	decoder->next_len = 0;
	return 0;
}

static int arm_spe_get_split_packet(struct arm_spe_decoder *decoder)
{
	unsigned char *buf = decoder->temp_buf;
	size_t old_len, len, n;
	int ret;

	old_len = decoder->len;
	len = decoder->len;
	memcpy(buf, decoder->buf, len);

	ret = arm_spe_get_data(decoder);
	if (ret) {
		decoder->pos += old_len;
		return ret < 0 ? ret : -EINVAL;
	}

	n = ARM_SPE_PKT_MAX_SZ - len;
	if (n > decoder->len)
		n = decoder->len;
	memcpy(buf + len, decoder->buf, n);
	len += n;

	ret = arm_spe_get_packet(buf, len, &decoder->packet);
	if (ret < (int)old_len) {
		decoder->next_buf = decoder->buf;
		decoder->next_len = decoder->len;
		decoder->buf = buf;
		decoder->len = old_len;
		return arm_spe_bad_packet(decoder);
	}

	decoder->next_buf = decoder->buf + (ret - old_len);
	decoder->next_len = decoder->len - (ret - old_len);

	decoder->buf = buf;
	decoder->len = ret;

	return ret;
}

struct arm_spe_pkt_info {
	struct arm_spe_decoder	  *decoder;
	struct arm_spe_pkt       packet;
	uint64_t                  pos;
	int                       pkt_len;
	int                       last_packet_type;
	void                      *data;
};

typedef int (*arm_spe_pkt_cb_t)(struct arm_spe_pkt_info *pkt_info);

struct arm_spe_calc_cyc_to_tsc_info {
	uint64_t        cycle_cnt;
	unsigned int    cbr;
	uint32_t        last_mtc;
	uint64_t        timestamp;
};

static int arm_spe_get_next_packet(struct arm_spe_decoder *decoder)
{
	int ret;

	decoder->last_packet_type = decoder->packet.type;

	do {
		decoder->pos += decoder->pkt_step;
		decoder->buf += decoder->pkt_step;
		decoder->len -= decoder->pkt_step;

		if (!decoder->len) {
			ret = arm_spe_get_next_data(decoder);
			if (ret)
				return ret;
		}

		ret = arm_spe_get_packet(decoder->buf, decoder->len,
					  &decoder->packet);
		if (ret == ARM_SPE_NEED_MORE_BYTES &&
		    decoder->len < ARM_SPE_PKT_MAX_SZ && !decoder->next_buf) {
			ret = arm_spe_get_split_packet(decoder);
			if (ret < 0)
				return ret;
		}
		if (ret <= 0)
			return arm_spe_bad_packet(decoder);

		decoder->pkt_len = ret;
		decoder->pkt_step = ret;
		arm_spe_decoder_log_packet(decoder);
	} while (decoder->packet.type == ARM_SPE_PAD);

	return 0;
}

static int arm_spe_walk_to_ip(struct arm_spe_decoder *decoder)
{
	int err;
	u64 address;

	while (1) {
		err = arm_spe_get_next_packet(decoder);
		if (err)
			return err;

		switch (decoder->packet.type) {
		case ARM_SPE_INSN_TYPE:
			decoder->state.type = ARM_SPE_INSTRUCTION;
			switch (decoder->packet.index) {
			case 0:	/* INSN_OTHER sub-type */
				break;
			case 1:	/* ARM_SPE_INSN_TYPE load/store sub-type */
				/* if (decoder->packet.payload & 0x1)
					decoder->state.type = ARM_SPE_STORE;
				else
					decoder->state.type = ARM_SPE_LOAD; */
				break;
			case 2:	/*BRANCH sub-type */
				break;
			default: /* undefined */
				break;
			}
			break;
		case ARM_SPE_BAD:
			break;
		case ARM_SPE_PAD:
			break;
		case ARM_SPE_TIMESTAMP:
			decoder->timestamp = decoder->packet.payload;
		case ARM_SPE_END:
			decoder->pkt_state = ARM_SPE_STATE_RECORD_COMPLETE;
			return 0;
		case ARM_SPE_ADDRESS:
			address = decoder->packet.payload & ~(0xffULL << 56);
			switch (decoder->packet.index) {
			case 0: decoder->ip = address;
				/* last entry in a packet with timestamps on;
				 * otherwise check for END */
				return 0;
			case 1: decoder->tgt_ip = address;
				break;
			case 2:	/* VA */
				break;
			case 3:	/* PA */
				break;
			default:
				break;
			}
			break;
		case ARM_SPE_COUNTER:
			switch (decoder->packet.index) {
			case 0: /* TOT */ decoder->latency++; break;
			case 1: /* ISSUE */ decoder->latency++; break;
			case 2: /* XLAT */ decoder->latency++; break;
			default: break;
			}
			break;
		case ARM_SPE_CONTEXT:
			break;
		case ARM_SPE_EVENTS:
			break;
		case ARM_SPE_DATA_SOURCE:
			break;
		default:
			break;
		}
	}
}

const struct arm_spe_state *arm_spe_decode(struct arm_spe_decoder *decoder)
{
	int err = 0;

	decoder->last_ip = 0;
	decoder->ip = 0;
	decoder->tgt_ip = 0;
	decoder->timestamp = 0;
	arm_spe_clear_stack(&decoder->stack);

	decoder->pkt_state = ARM_SPE_STATE_RECORD_INCOMPLETE;

	err = arm_spe_walk_to_ip(decoder);
	if (err)
		goto needmoredata; /* happens if at end of buffer and need more data */

	do {
		decoder->state.flags = 0;

		switch (decoder->pkt_state) {
		case ARM_SPE_STATE_ERROR:
			break;
		case ARM_SPE_STATE_RECORD_COMPLETE:
			break;
		case ARM_SPE_STATE_RECORD_INCOMPLETE:
			if (decoder->ip) {
				decoder->pkt_state = ARM_SPE_STATE_RECORD_COMPLETE;
				decoder->state.from_ip = decoder->ip;
				decoder->state.to_ip = decoder->tgt_ip;
				decoder->state.type = ARM_SPE_INSTRUCTION;
			}
			err = 0;
			break;
		default:
			fprintf(stderr, "%s %d: default case: bug?\n", __func__, __LINE__);
			err = arm_spe_bug(decoder);
			break;
		}
	} while (err == -ENOLINK);

needmoredata:
	decoder->state.err = err ? arm_spe_ext_err(err) : 0;
	decoder->state.timestamp = decoder->timestamp;
	decoder->state.tot_insn_cnt = decoder->tot_insn_cnt;

	return &decoder->state;
}

/**
 * arm_spe_find_overlap - determine start of non-overlapped trace data.
 * @buf_a: first buffer
 * @len_a: size of first buffer
 * @buf_b: second buffer
 * @len_b: size of second buffer
 * @have_tsc: can use TSC packets to detect overlap
 *
 * When trace samples or snapshots are recorded there is the possibility that
 * the data overlaps.  Note that, for the purposes of decoding, data is only
 * useful if it begins with a PSB packet.
 *
 * Return: A pointer into @buf_b from where non-overlapped data starts, or
 * @buf_b + @len_b if there is no non-overlapped data.
 */
/* FIXME: unuseds */
unsigned char *arm_spe_find_overlap(unsigned char *buf_a __maybe_unused, size_t len_a __maybe_unused,
				     unsigned char *buf_b __maybe_unused, size_t len_b __maybe_unused,
				     bool have_tsc __maybe_unused)
{
	return buf_b + len_b; /* No PSB */

}
