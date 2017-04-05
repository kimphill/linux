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

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "../perf.h"
#include "session.h"
#include "machine.h"
#include "sort.h"
#include "tool.h"
#include "event.h"
#include "evlist.h"
#include "evsel.h"
#include "map.h"
#include "color.h"
#include "util.h"
#include "thread.h"
#include "thread-stack.h"
#include "symbol.h"
#include "callchain.h"
#include "dso.h"
#include "debug.h"
#include "auxtrace.h"
#include "tsc.h"
#include "arm-spe.h"
#include "config.h"

#include "arm-spe-decoder/arm-spe-log.h"
#include "arm-spe-decoder/arm-spe-decoder.h"
#include "arm-spe-decoder/arm-spe-insn-decoder.h"
#include "arm-spe-decoder/arm-spe-pkt-decoder.h"

#define MAX_TIMESTAMP (~0ULL)

struct arm_spe {
	struct auxtrace auxtrace;
	struct auxtrace_queues queues;
	struct auxtrace_heap heap;
	u32 auxtrace_type;
	struct perf_session *session;
	struct machine *machine;
	struct perf_evsel *switch_evsel;
	struct thread *unknown_thread;
	bool sampling_mode;
	bool snapshot_mode;
	bool per_cpu_mmaps;
	bool have_tsc;
	bool data_queued;
	bool est_tsc;
	bool sync_switch;
	bool mispred_all;
	int have_sched_switch;
	u32 pmu_type;
	u64 kernel_start;
	u64 switch_ip;
	u64 ptss_ip;

	struct perf_tsc_conversion tc;
	bool cap_user_time_zero;

	struct itrace_synth_opts synth_opts;

	bool sample_instructions;
	u64 instructions_sample_type;
	u64 instructions_sample_period;
	u64 instructions_id;

	bool sample_branches;
	u32 branches_filter;
	u64 branches_sample_type;
	u64 branches_id;

	bool sample_transactions;
	u64 transactions_sample_type;
	u64 transactions_id;

	bool synth_needs_swap;

	u64 ts_enable;
	u64 pa_enable;
	u64 jitter;
	u64 load_filter;
	u64 store_filter;
	u64 branch_filter;
	u64 min_latency;

	unsigned long num_events;
};

enum switch_state {
	ARM_SPE_SS_NOT_TRACING,
	ARM_SPE_SS_UNKNOWN,
	ARM_SPE_SS_TRACING,
	ARM_SPE_SS_EXPECTING_SWITCH_EVENT,
	ARM_SPE_SS_EXPECTING_SWITCH_IP,
};

struct arm_spe_queue {
	struct arm_spe *spe;
	unsigned int queue_nr;
	struct auxtrace_buffer *buffer;
	void *decoder;
	const struct arm_spe_state *state;
	struct ip_callchain *chain;

	/*
	 * Stack of branches in reverse chronological order that will be copied
	 * to a last branch event sample.
	 */
	struct branch_stack    *last_branch;
	/*
	 * A circular buffer used to record last branches as they are decoded
	 * from the trace.
	 */
	struct branch_stack    *last_branch_rb;
	/*
	 * Position in the circular buffer where the last branch has been
	 * inserted.
	 */
	size_t last_branch_pos;

	union perf_event *event_buf;
	bool on_heap;
	bool stop;
	bool step_through_buffers;
	bool use_buffer_pid_tid;
	pid_t pid, tid;
	int cpu;
	int switch_state;
	pid_t next_tid;
	struct thread *thread;
	bool exclude_kernel;
	bool have_sample;
	u64 time;
	u64 timestamp;
	u32 flags;
	u64 last_insn_cnt;
};


static void arm_spe_dump(struct arm_spe *spe __maybe_unused,
			  unsigned char *buf, size_t len)
{
	struct arm_spe_pkt packet;
	size_t pos = 0;
	int ret, pkt_len, i;
	char desc[ARM_SPE_PKT_DESC_MAX];
	const char *color = PERF_COLOR_BLUE;

	color_fprintf(stdout, color,
		      ". ... ARM SPE data: size %zu bytes\n", len);

	while (len) {
		ret = arm_spe_get_packet(buf, len, &packet);
		if (ret > 0)
			pkt_len = ret;
		else
			pkt_len = 1;
		printf(".");
		color_fprintf(stdout, color, "  %08x: ", pos);
		for (i = 0; i < pkt_len; i++)
			color_fprintf(stdout, color, " %02x", buf[i]);
		for (; i < 16; i++)
			color_fprintf(stdout, color, "   ");
		if (ret > 0) {
			ret = arm_spe_pkt_desc(&packet, desc,
					       ARM_SPE_PKT_DESC_MAX);
			if (ret > 0)
				color_fprintf(stdout, color, " %s\n", desc);
		} else {
			color_fprintf(stdout, color, " Bad packet!\n");
		}
		pos += pkt_len;
		buf += pkt_len;
		len -= pkt_len;
	}
}

static void arm_spe_dump_event(struct arm_spe *spe, unsigned char *buf,
				size_t len)
{
	arm_spe_dump(spe, buf, len);
}

static int arm_spe_do_fix_overlap(struct arm_spe *spe __maybe_unused,
	       			  struct auxtrace_buffer *a,
				  struct auxtrace_buffer *b)
{
	void *start;

	/*start = arm_spe_find_overlap(a->data, a->size, b->data, b->size,
				      spe->have_tsc); */
	start = (void *)a->data;
	if (!start)
		return -EINVAL;
	b->use_size = b->data + b->size - start;
	b->use_data = start;

	return 0;
}

static void arm_spe_use_buffer_pid_tid(struct arm_spe_queue *speq,
				       struct auxtrace_queue *queue,
				       struct auxtrace_buffer *buffer)
{
	if (queue->cpu == -1 && buffer->cpu != -1)
		speq->cpu = buffer->cpu;

	speq->pid = buffer->pid;
	speq->tid = buffer->tid;

	arm_spe_log("queue %u cpu %d pid %d tid %d\n",
		     speq->queue_nr, speq->cpu, speq->pid, speq->tid);

	thread__zput(speq->thread);

	if (speq->tid != -1) {
		if (speq->pid != -1)
			speq->thread = machine__findnew_thread(speq->spe->machine,
							      speq->pid,
							      speq->tid);
		else
			speq->thread = machine__find_thread(speq->spe->machine, -1,
							   speq->tid);
	}
}

/* This function assumes data is processed sequentially only */
static int arm_spe_get_trace(struct arm_spe_buffer *b, void *data)
{
	struct arm_spe_queue *speq = data;
	struct auxtrace_buffer *buffer = speq->buffer, *old_buffer = buffer;
	struct auxtrace_queue *queue;

	if (speq->stop) {
		b->len = 0;
		return 0;
	}

	queue = &speq->spe->queues.queue_array[speq->queue_nr];

	buffer = auxtrace_buffer__next(queue, buffer);
	if (!buffer) {
		if (old_buffer)
			auxtrace_buffer__drop_data(old_buffer);
		b->len = 0;
		return 0;
	}

	speq->buffer = buffer;

	if (!buffer->data) {
		int fd = perf_data_file__fd(speq->spe->session->file);

		buffer->data = auxtrace_buffer__get_data(buffer, fd);
		if (!buffer->data)
			return -ENOMEM;
	}

	if (speq->spe->snapshot_mode && !buffer->consecutive && old_buffer &&
	    arm_spe_do_fix_overlap(speq->spe, old_buffer, buffer))
		return -ENOMEM;

	if (old_buffer)
		auxtrace_buffer__drop_data(old_buffer);

	if (buffer->use_data) {
		b->len = buffer->use_size;
		b->buf = buffer->use_data;
	} else {
		b->len = buffer->size;
		b->buf = buffer->data;
	}
	b->ref_timestamp = buffer->reference;

	if (!old_buffer || speq->spe->sampling_mode || (speq->spe->snapshot_mode &&
						      !buffer->consecutive)) {
		b->consecutive = false;
		b->trace_nr = buffer->buffer_nr + 1;
	} else {
		b->consecutive = true;
	}

	if (speq->use_buffer_pid_tid && (speq->pid != buffer->pid ||
					speq->tid != buffer->tid))
		arm_spe_use_buffer_pid_tid(speq, queue, buffer);

	if (speq->step_through_buffers)
		speq->stop = true;

	if (!b->len)
		return arm_spe_get_trace(b, data);

	return 0;
}

struct arm_spe_cache_entry {
	struct auxtrace_cache_entry	entry;
	u64				insn_cnt;
	u64				byte_cnt;
	enum arm_spe_insn_op		op;
	enum arm_spe_insn_branch	branch;
	int				length;
	int32_t				rel;
};

static int arm_spe_config_div(const char *var, const char *value, void *data)
{
	int *d = data;
	long val;

	/* FIXME */
	if (!strcmp(var, "intel-pt.cache-divisor")) {
		val = strtol(value, NULL, 0);
		if (val > 0 && val <= INT_MAX)
			*d = val;
	}

	return 0;
}

static int arm_spe_cache_divisor(void)
{
	static int d;

	if (d)
		return d;

	perf_config(arm_spe_config_div, &d);

	if (!d)
		d = 64;

	return d;
}

static unsigned int arm_spe_cache_size(struct dso *dso,
					struct machine *machine)
{
	off_t size;

	size = dso__data_size(dso, machine);
	size /= arm_spe_cache_divisor();
	if (size < 1000)
		return 10;
	if (size > (1 << 21))
		return 21;
	return 32 - __builtin_clz(size);
}

static struct auxtrace_cache *arm_spe_cache(struct dso *dso,
					     struct machine *machine)
{
	struct auxtrace_cache *c;
	unsigned int bits;

	if (dso->auxtrace_cache)
		return dso->auxtrace_cache;

	bits = arm_spe_cache_size(dso, machine);

	/* Ignoring cache creation failure */
	c = auxtrace_cache__new(bits, sizeof(struct arm_spe_cache_entry), 200);

	dso->auxtrace_cache = c;

	return c;
}

static int arm_spe_cache_add(struct dso *dso, struct machine *machine,
			      u64 offset, u64 insn_cnt, u64 byte_cnt,
			      struct arm_spe_insn *arm_spe_insn)
{
	struct auxtrace_cache *c = arm_spe_cache(dso, machine);
	struct arm_spe_cache_entry *e;
	int err;

	if (!c)
		return -ENOMEM;

	e = auxtrace_cache__alloc_entry(c);
	if (!e)
		return -ENOMEM;

	e->insn_cnt = insn_cnt;
	e->byte_cnt = byte_cnt;
	e->op = arm_spe_insn->op;
	e->branch = arm_spe_insn->branch;
	e->length = arm_spe_insn->length;
	e->rel = arm_spe_insn->rel;

	err = auxtrace_cache__add(c, offset, &e->entry);
	if (err)
		auxtrace_cache__free_entry(c, e);

	return err;
}

static struct arm_spe_cache_entry *
arm_spe_cache_lookup(struct dso *dso, struct machine *machine, u64 offset)
{
	struct auxtrace_cache *c = arm_spe_cache(dso, machine);

	if (!c)
		return NULL;

	return auxtrace_cache__lookup(dso->auxtrace_cache, offset);
}

static int arm_spe_walk_next_insn(struct arm_spe_insn *arm_spe_insn,
				   uint64_t *insn_cnt_ptr, uint64_t *ip,
				   uint64_t to_ip, uint64_t max_insn_cnt,
				   void *data)
{
	struct arm_spe_queue *speq = data;
	struct machine *machine = speq->spe->machine;
	struct thread *thread;
	struct addr_location al;
	unsigned char buf[1024];
	size_t bufsz;
	ssize_t len;
	u8 cpumode;
	u64 offset, start_offset, start_ip;
	u64 insn_cnt = 0;
	bool one_map = true;

	if (to_ip && *ip == to_ip)
		goto out_no_cache;

	bufsz = 4;

	if (*ip >= speq->spe->kernel_start)
		cpumode = PERF_RECORD_MISC_KERNEL;
	else
		cpumode = PERF_RECORD_MISC_USER;

	thread = speq->thread;
	if (!thread) {
		if (cpumode != PERF_RECORD_MISC_KERNEL)
			return -EINVAL;
		thread = speq->spe->unknown_thread;
	}

	while (1) {
		thread__find_addr_map(thread, cpumode, MAP__FUNCTION, *ip, &al);
		if (!al.map || !al.map->dso)
			return -EINVAL;

		if (al.map->dso->data.status == DSO_DATA_STATUS_ERROR &&
		    dso__data_status_seen(al.map->dso,
					  DSO_DATA_STATUS_SEEN_ITRACE))
			return -ENOENT;

		offset = al.map->map_ip(al.map, *ip);

		if (!to_ip && one_map) {
			struct arm_spe_cache_entry *e;

			e = arm_spe_cache_lookup(al.map->dso, machine, offset);
			if (e &&
			    (!max_insn_cnt || e->insn_cnt <= max_insn_cnt)) {
				*insn_cnt_ptr = e->insn_cnt;
				*ip += e->byte_cnt;
				arm_spe_insn->op = e->op;
				arm_spe_insn->branch = e->branch;
				arm_spe_insn->length = e->length;
				arm_spe_insn->rel = e->rel;
				arm_spe_log_insn_no_data(arm_spe_insn, *ip);
				return 0;
			}
		}

		start_offset = offset;
		start_ip = *ip;

		/* Load maps to ensure dso->is_64_bit has been updated */
		map__load(al.map);

		while (1) {
			len = dso__data_read_offset(al.map->dso, machine,
						    offset, buf, bufsz);
			if (len <= 0)
				return -EINVAL;

			if (0 /*arm_spe_get_insn(buf, len, x86_64, arm_spe_insn)*/)
				return -EINVAL;

			arm_spe_log_insn(arm_spe_insn, *ip);

			insn_cnt += 1;

			if (arm_spe_insn->branch != ARM_SPE_BR_NO_BRANCH)
				goto out;

			if (max_insn_cnt && insn_cnt >= max_insn_cnt)
				goto out_no_cache;

			*ip += arm_spe_insn->length;

			if (to_ip && *ip == to_ip)
				goto out_no_cache;

			if (*ip >= al.map->end)
				break;

			offset += arm_spe_insn->length;
		}
		one_map = false;
	}
out:
	*insn_cnt_ptr = insn_cnt;

	if (!one_map)
		goto out_no_cache;

	/*
	 * Didn't lookup in the 'to_ip' case, so do it now to prevent duplicate
	 * entries.
	 */
	if (to_ip) {
		struct arm_spe_cache_entry *e;

		e = arm_spe_cache_lookup(al.map->dso, machine, start_offset);
		if (e)
			return 0;
	}

	/* Ignore cache errors */
	arm_spe_cache_add(al.map->dso, machine, start_offset, insn_cnt,
			   *ip - start_ip, arm_spe_insn);

	return 0;

out_no_cache:
	*insn_cnt_ptr = insn_cnt;
	return 0;
}

static bool arm_spe_get_config(struct arm_spe *spe,
				struct perf_event_attr *attr, u64 *config)
{
	if (attr->type == spe->pmu_type) {
		if (config)
			*config = attr->config;
		return true;
	}

	return false;
}

static bool arm_spe_exclude_kernel(struct arm_spe *spe)
{
	struct perf_evsel *evsel;

	evlist__for_each_entry(spe->session->evlist, evsel) {
		if (arm_spe_get_config(spe, &evsel->attr, NULL) &&
		    !evsel->attr.exclude_kernel)
			return false;
	}
	return true;
}

static bool arm_spe_tracing_kernel(struct arm_spe *spe)
{
	struct perf_evsel *evsel;

	evlist__for_each_entry(spe->session->evlist, evsel) {
		if (arm_spe_get_config(spe, &evsel->attr, NULL) &&
		    !evsel->attr.exclude_kernel)
			return true;
	}
	return false;
}

static struct arm_spe_queue *arm_spe_alloc_queue(struct arm_spe *spe,
						   unsigned int queue_nr)
{
	struct arm_spe_params params = { .get_trace = 0, };
	struct arm_spe_queue *speq;

	speq = zalloc(sizeof(struct arm_spe_queue));
	if (!speq)
		return NULL;

	if (spe->synth_opts.callchain) {
		size_t sz = sizeof(struct ip_callchain);

		sz += spe->synth_opts.callchain_sz * sizeof(u64);
		speq->chain = zalloc(sz);
		if (!speq->chain)
			goto out_free;
	}

	if (spe->synth_opts.last_branch) {
		size_t sz = sizeof(struct branch_stack);

		sz += spe->synth_opts.last_branch_sz *
		      sizeof(struct branch_entry);
		speq->last_branch = zalloc(sz);
		if (!speq->last_branch)
			goto out_free;
		speq->last_branch_rb = zalloc(sz);
		if (!speq->last_branch_rb)
			goto out_free;
	}

	speq->event_buf = malloc(PERF_SAMPLE_MAX_SIZE);
	if (!speq->event_buf)
		goto out_free;

	speq->spe = spe;
	speq->queue_nr = queue_nr;
	speq->exclude_kernel = arm_spe_exclude_kernel(spe);
	speq->pid = -1;
	speq->tid = -1;
	speq->cpu = 1;
	speq->next_tid = -1;

	params.get_trace = arm_spe_get_trace;
	params.walk_insn = arm_spe_walk_next_insn;
	params.data = speq;

	speq->decoder = (void *) arm_spe_decoder_new(&params);
	if (!speq->decoder)
		goto out_free;

	return speq;

out_free:
	zfree(&speq->event_buf);
	zfree(&speq->last_branch);
	zfree(&speq->last_branch_rb);
	zfree(&speq->chain);
	free(speq);
	return NULL;
}

static void arm_spe_free_queue(void *priv)
{
	struct arm_spe_queue *speq = priv;

	if (!speq)
		return;
	thread__zput(speq->thread);
	fprintf(stderr, "arm_spe_decoder_free needs implementing, %p\n",
	speq->decoder);
	//arm_spe_decoder_free(speq->decoder);
	zfree(&speq->event_buf);
	zfree(&speq->last_branch);
	zfree(&speq->last_branch_rb);
	zfree(&speq->chain);
	free(speq);
}

static void arm_spe_set_pid_tid_cpu(struct arm_spe *spe,
				     struct auxtrace_queue *queue)
{
	struct arm_spe_queue *speq = queue->priv;

	if (queue->tid == -1 || spe->have_sched_switch) {
		speq->tid = machine__get_current_tid(spe->machine, speq->cpu);
		thread__zput(speq->thread);
	}

	if (!speq->thread && speq->tid != -1)
		speq->thread = machine__find_thread(spe->machine, -1, speq->tid);

	if (speq->thread) {
		speq->pid = speq->thread->pid_;
		if (queue->cpu == -1)
			speq->cpu = speq->thread->cpu;
	}
}

static void arm_spe_sample_flags(struct arm_spe_queue *speq)
{
	if (speq->state->flags & ARM_SPE_ABORT_TX) {
		speq->flags = PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_TX_ABORT;
	} else if (speq->state->flags & ARM_SPE_ASYNC) {
		if (speq->state->to_ip)
			speq->flags = PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_CALL |
				     PERF_IP_FLAG_ASYNC |
				     PERF_IP_FLAG_INTERRUPT;
		else
			speq->flags = PERF_IP_FLAG_BRANCH |
				     PERF_IP_FLAG_TRACE_END;
	} else {
		if (speq->state->from_ip)
			/* FIXME */
			pr_err("%s %d: FIXME\n", __func__, __LINE__);
			;
		else
			speq->flags = PERF_IP_FLAG_BRANCH |
				     PERF_IP_FLAG_TRACE_BEGIN;
		if (speq->state->flags & ARM_SPE_IN_TX)
			speq->flags |= PERF_IP_FLAG_IN_TX;
	}
}

static int arm_spe_setup_queue(struct arm_spe *spe,
				struct auxtrace_queue *queue,
				unsigned int queue_nr)
{
	struct arm_spe_queue *speq = queue->priv;

	if (list_empty(&queue->head))
		return 0;

	if (!speq) {
		speq = arm_spe_alloc_queue(spe, queue_nr);
		if (!speq)
			return -ENOMEM;

		queue->priv = speq;

		if (queue->cpu != -1)
			speq->cpu = queue->cpu;
		speq->tid = queue->tid;
	}

	if (!speq->on_heap &&
	    (!spe->sync_switch ||
	     speq->switch_state != ARM_SPE_SS_EXPECTING_SWITCH_EVENT)) {
		const struct arm_spe_state *state;
		int ret;

		arm_spe_log("queue %u getting timestamp\n", queue_nr);
		arm_spe_log("queue %u decoding cpu %d pid %d tid %d\n",
			     queue_nr, speq->cpu, speq->pid, speq->tid);
		while (1) {
			state = arm_spe_decode(speq->decoder);
			if (state->err) {
				if (state->err == ARM_SPE_ERR_NODATA) {
					arm_spe_log("queue %u has no timestamp\n",
						     queue_nr);
					return 0;
				}
				continue;
			}
			/* apparently we need to get an initial timestamp */
			if ( state->timestamp)
				break;
		}

		speq->timestamp = state->timestamp;
		arm_spe_log("queue %u timestamp 0x%" PRIx64 "\n",
			     queue_nr, speq->timestamp);
		speq->state = state;
		speq->have_sample = true;
		arm_spe_sample_flags(speq);
		ret = auxtrace_heap__add(&spe->heap, queue_nr, speq->timestamp);
		if (ret)
			return ret;
		speq->on_heap = true;
	}

	return 0;
}

static int arm_spe_setup_queues(struct arm_spe *spe)
{
	unsigned int i;
	int ret;

	for (i = 0; i < spe->queues.nr_queues; i++) {
		ret = arm_spe_setup_queue(spe, &spe->queues.queue_array[i], i);
		if (ret)
			return ret;
	}
	return 0;
}

static inline void arm_spe_copy_last_branch_rb(struct arm_spe_queue *speq)
{
	struct branch_stack *bs_src = speq->last_branch_rb;
	struct branch_stack *bs_dst = speq->last_branch;
	size_t nr = 0;

	/*
	 * Set the number of records before early exit: ->nr is used to
	 * determine how many branches to copy from ->entries.
	 */
	bs_dst->nr = bs_src->nr;

	/*
	 * Early exit when there is nothing to copy.
	 */
	if (!bs_src->nr)
		return;

	/*
	 * As bs_src->entries is a circular buffer, we need to copy from it in
	 * two steps.  First, copy the branches from the most recently inserted
	 * branch ->last_branch_pos until the end of bs_src->entries buffer.
	 */
	nr = speq->spe->synth_opts.last_branch_sz - speq->last_branch_pos;
	memcpy(&bs_dst->entries[0],
	       &bs_src->entries[speq->last_branch_pos],
	       sizeof(struct branch_entry) * nr);

	/*
	 * If we wrapped around at least once, the branches from the beginning
	 * of the bs_src->entries buffer and until the ->last_branch_pos element
	 * are older valid branches: copy them over.  The total number of
	 * branches copied over will be equal to the number of branches asked by
	 * the user in last_branch_sz.
	 */
	if (bs_src->nr >= speq->spe->synth_opts.last_branch_sz) {
		memcpy(&bs_dst->entries[nr],
		       &bs_src->entries[0],
		       sizeof(struct branch_entry) * speq->last_branch_pos);
	}
}

static inline void arm_spe_reset_last_branch_rb(struct arm_spe_queue *speq)
{
	speq->last_branch_pos = 0;
	speq->last_branch_rb->nr = 0;
}

static void arm_spe_update_last_branch_rb(struct arm_spe_queue *speq)
{
	const struct arm_spe_state *state = speq->state;
	struct branch_stack *bs = speq->last_branch_rb;
	struct branch_entry *be;

	/*
	 * The branches are recorded in a circular buffer in reverse
	 * chronological order: we start recording from the last element of the
	 * buffer down.  After writing the first element of the stack, move the
	 * insert position back to the end of the buffer.
	 */
	if (!speq->last_branch_pos)
		speq->last_branch_pos = speq->spe->synth_opts.last_branch_sz;

	speq->last_branch_pos -= 1;

	be              = &bs->entries[speq->last_branch_pos];
	be->from        = state->from_ip;
	be->to          = state->to_ip;
	be->flags.abort = !!(state->flags & ARM_SPE_ABORT_TX);
	be->flags.in_tx = !!(state->flags & ARM_SPE_IN_TX);
	/* No support for mispredict */
	be->flags.mispred = speq->spe->mispred_all;

	/*
	 * Increment bs->nr until reaching the number of last branches asked by
	 * the user on the command line.
	 */
	if (bs->nr < speq->spe->synth_opts.last_branch_sz)
		bs->nr += 1;
}

static int arm_spe_inject_event(union perf_event *event,
				 struct perf_sample *sample, u64 type,
				 bool swapped)
{
	event->header.size = perf_event__sample_event_size(sample, type, 0);
	return perf_event__synthesize_sample(event, type, 0, sample, swapped);
}

static int arm_spe_synth_branch_sample(struct arm_spe_queue *speq)
{
	int ret;
	struct arm_spe *spe = speq->spe;
	union perf_event *event = speq->event_buf;
	struct perf_sample sample = { .ip = 0, };
	struct dummy_branch_stack {
		u64			nr;
		struct branch_entry	entries;
	} dummy_bs;

	if (spe->branches_filter && !(spe->branches_filter & speq->flags))
		return 0;

	if (spe->synth_opts.initial_skip &&
	    spe->num_events++ < spe->synth_opts.initial_skip)
		return 0;

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = PERF_RECORD_MISC_USER;
	event->sample.header.size = sizeof(struct perf_event_header);

	sample.cpumode = PERF_RECORD_MISC_USER;
	sample.ip = speq->state->from_ip;
	sample.pid = speq->pid;
	sample.tid = speq->tid;
	sample.addr = speq->state->to_ip;
	sample.id = speq->spe->branches_id;
	sample.stream_id = speq->spe->branches_id;
	sample.period = 1;
	sample.cpu = speq->cpu;
	sample.flags = speq->flags;

	/*
	 * perf report cannot handle events without a branch stack when using
	 * SORT_MODE__BRANCH so make a dummy one.
	 */
	if (spe->synth_opts.last_branch && sort__mode == SORT_MODE__BRANCH) {
		dummy_bs = (struct dummy_branch_stack){
			.nr = 1,
			.entries = {
				.from = sample.ip,
				.to = sample.addr,
			},
		};
		sample.branch_stack = (struct branch_stack *)&dummy_bs;
	}

	if (spe->synth_opts.inject) {
		ret = arm_spe_inject_event(event, &sample,
					    spe->branches_sample_type,
					    spe->synth_needs_swap);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(spe->session, event, &sample);
	if (ret)
		pr_err("ARM SPE: failed to deliver branch event, error %d\n",
		       ret);

	return ret;
}

static int arm_spe_synth_instruction_sample(struct arm_spe_queue *speq)
{
	int ret;
	struct arm_spe *spe = speq->spe;
	union perf_event *event = speq->event_buf;
	struct perf_sample sample = { .ip = 0, };

	if (spe->synth_opts.initial_skip &&
	    spe->num_events++ < spe->synth_opts.initial_skip)
		return 0;

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = PERF_RECORD_MISC_USER;
	event->sample.header.size = sizeof(struct perf_event_header);

	sample.cpumode = PERF_RECORD_MISC_USER;
	sample.ip = speq->state->from_ip;
	sample.pid = speq->pid;
	sample.tid = speq->tid;
	sample.addr = speq->state->to_ip;
	sample.id = speq->spe->instructions_id;
	sample.stream_id = speq->spe->instructions_id;
	sample.period = speq->state->tot_insn_cnt - speq->last_insn_cnt;
	sample.cpu = speq->cpu;
	sample.flags = speq->flags;

	speq->last_insn_cnt = speq->state->tot_insn_cnt;

	if (spe->synth_opts.callchain) {
		thread_stack__sample(speq->thread, speq->chain,
				     spe->synth_opts.callchain_sz, sample.ip);
		sample.callchain = speq->chain;
	}

	if (spe->synth_opts.last_branch) {
		arm_spe_copy_last_branch_rb(speq);
		sample.branch_stack = speq->last_branch;
	}

	if (spe->synth_opts.inject) {
		ret = arm_spe_inject_event(event, &sample,
					    spe->instructions_sample_type,
					    spe->synth_needs_swap);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(spe->session, event, &sample);

	if (spe->synth_opts.last_branch)
		arm_spe_reset_last_branch_rb(speq);

	return ret;
}

static int arm_spe_synth_transaction_sample(struct arm_spe_queue *speq)
{
	int ret;
	struct arm_spe *spe = speq->spe;
	union perf_event *event = speq->event_buf;
	struct perf_sample sample = { .ip = 0, };

	if (spe->synth_opts.initial_skip &&
	    spe->num_events++ < spe->synth_opts.initial_skip)
		return 0;

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = PERF_RECORD_MISC_USER;
	event->sample.header.size = sizeof(struct perf_event_header);

	sample.cpumode = PERF_RECORD_MISC_USER;
	sample.ip = speq->state->from_ip;
	sample.pid = speq->pid;
	sample.tid = speq->tid;
	sample.addr = speq->state->to_ip;
	sample.id = speq->spe->transactions_id;
	sample.stream_id = speq->spe->transactions_id;
	sample.period = 1;
	sample.cpu = speq->cpu;
	sample.flags = speq->flags;

	if (spe->synth_opts.callchain) {
		thread_stack__sample(speq->thread, speq->chain,
				     spe->synth_opts.callchain_sz, sample.ip);
		sample.callchain = speq->chain;
	}

	if (spe->synth_opts.last_branch) {
		arm_spe_copy_last_branch_rb(speq);
		sample.branch_stack = speq->last_branch;
	}

	if (spe->synth_opts.inject) {
		ret = arm_spe_inject_event(event, &sample,
					    spe->transactions_sample_type,
					    spe->synth_needs_swap);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(spe->session, event, &sample);

	if (spe->synth_opts.last_branch)
		arm_spe_reset_last_branch_rb(speq);

	return ret;
}

static int arm_spe_synth_error(struct arm_spe *spe, int code, int cpu,
				pid_t pid, pid_t tid, u64 ip)
{
	union perf_event event;
	char msg[MAX_AUXTRACE_ERROR_MSG];
	int err;

	//arm_spe__strerror(code, msg, MAX_AUXTRACE_ERROR_MSG);

	auxtrace_synth_error(&event.auxtrace_error, PERF_AUXTRACE_ERROR_ITRACE,
			     code, cpu, pid, tid, ip, msg);

	err = perf_session__deliver_synth_event(spe->session, &event, NULL);

	return err;
}

static int arm_spe_next_tid(struct arm_spe *spe, struct arm_spe_queue *speq)
{
	struct auxtrace_queue *queue;
	pid_t tid = speq->next_tid;
	int err;

	if (tid == -1)
		return 0;

	arm_spe_log("switch: cpu %d tid %d\n", speq->cpu, tid);

	err = machine__set_current_tid(spe->machine, speq->cpu, -1, tid);

	queue = &spe->queues.queue_array[speq->queue_nr];
	arm_spe_set_pid_tid_cpu(spe, queue);

	speq->next_tid = -1;

	return err;
}

static inline bool arm_spe_is_switch_ip(struct arm_spe_queue *speq, u64 ip)
{
	struct arm_spe *spe = speq->spe;

	return ip == spe->switch_ip &&
	       (speq->flags & PERF_IP_FLAG_BRANCH) &&
	       !(speq->flags & (PERF_IP_FLAG_CONDITIONAL | PERF_IP_FLAG_ASYNC |
			       PERF_IP_FLAG_INTERRUPT | PERF_IP_FLAG_TX_ABORT));
}

static int arm_spe_sample(struct arm_spe_queue *speq)
{
	const struct arm_spe_state *state = speq->state;
	struct arm_spe *spe = speq->spe;
	int err;

	if (!speq->have_sample)
		return 0;

	speq->have_sample = false;

	if (spe->sample_instructions &&
	    (state->type & ARM_SPE_INSTRUCTION) &&
	    (!spe->synth_opts.initial_skip ||
	     spe->num_events++ >= spe->synth_opts.initial_skip)) {
		err = arm_spe_synth_instruction_sample(speq);
		if (err)
			return err;
	}

	if (spe->sample_transactions &&
	    (state->type & ARM_SPE_TRANSACTION) &&
	    (!spe->synth_opts.initial_skip ||
	     spe->num_events++ >= spe->synth_opts.initial_skip)) {
		err = arm_spe_synth_transaction_sample(speq);
		if (err)
			return err;
	}

	if (!(state->type & ARM_SPE_BRANCH))
		return 0;

	if (spe->synth_opts.callchain || spe->synth_opts.thread_stack)
		thread_stack__event(speq->thread, speq->flags, state->from_ip,
				    state->to_ip, 4,
				    state->trace_nr);
	else
		thread_stack__set_trace_nr(speq->thread, state->trace_nr);

	if (spe->sample_branches) {
		err = arm_spe_synth_branch_sample(speq);
		if (err)
			return err;
	}

	if (spe->synth_opts.last_branch)
		arm_spe_update_last_branch_rb(speq);

	if (!spe->sync_switch)
		return 0;

	if (arm_spe_is_switch_ip(speq, state->to_ip)) {
		switch (speq->switch_state) {
		case ARM_SPE_SS_UNKNOWN:
		case ARM_SPE_SS_EXPECTING_SWITCH_IP:
			err = arm_spe_next_tid(spe, speq);
			if (err)
				return err;
			speq->switch_state = ARM_SPE_SS_TRACING;
			break;
		default:
			speq->switch_state = ARM_SPE_SS_EXPECTING_SWITCH_EVENT;
			return 1;
		}
	} else if (!state->to_ip) {
		speq->switch_state = ARM_SPE_SS_NOT_TRACING;
	} else if (speq->switch_state == ARM_SPE_SS_NOT_TRACING) {
		speq->switch_state = ARM_SPE_SS_UNKNOWN;
	} else if (speq->switch_state == ARM_SPE_SS_UNKNOWN &&
		   state->to_ip == spe->ptss_ip &&
		   (speq->flags & PERF_IP_FLAG_CALL)) {
		speq->switch_state = ARM_SPE_SS_TRACING;
	}

	return 0;
}

static u64 arm_spe_switch_ip(struct arm_spe *spe, u64 *ptss_ip)
{
	struct machine *machine = spe->machine;
	struct map *map;
	struct symbol *sym, *start;
	u64 ip, switch_ip = 0;
	const char *ptss;

	if (ptss_ip)
		*ptss_ip = 0;

	map = machine__kernel_map(machine);
	if (!map)
		return 0;

	if (map__load(map))
		return 0;

	start = dso__first_symbol(map->dso, MAP__FUNCTION);

	for (sym = start; sym; sym = dso__next_symbol(sym)) {
		if (sym->binding == STB_GLOBAL &&
		    !strcmp(sym->name, "__switch_to")) {
			ip = map->unmap_ip(map, sym->start);
			if (ip >= map->start && ip < map->end) {
				switch_ip = ip;
				break;
			}
		}
	}

	if (!switch_ip || !ptss_ip)
		return 0;

	if (spe->have_sched_switch == 1)
		ptss = "perf_trace_sched_switch";
	else
		ptss = "__perf_event_task_sched_out";

	for (sym = start; sym; sym = dso__next_symbol(sym)) {
		if (!strcmp(sym->name, ptss)) {
			ip = map->unmap_ip(map, sym->start);
			if (ip >= map->start && ip < map->end) {
				*ptss_ip = ip;
				break;
			}
		}
	}

	return switch_ip;
}

static int arm_spe_run_decoder(struct arm_spe_queue *speq, u64 *timestamp)
{
	const struct arm_spe_state *state = speq->state;
	struct arm_spe *spe = speq->spe;
	int err;

	if (!spe->kernel_start) {
		spe->kernel_start = machine__kernel_start(spe->machine);
		if (spe->per_cpu_mmaps &&
		    (spe->have_sched_switch == 1 || spe->have_sched_switch == 3) &&
		    arm_spe_tracing_kernel(spe) && !spe->sampling_mode) {
			spe->switch_ip = arm_spe_switch_ip(spe, &spe->ptss_ip);
			if (spe->switch_ip) {
				arm_spe_log("switch_ip: %"PRIx64" ptss_ip: %"PRIx64"\n",
					     spe->switch_ip, spe->ptss_ip);
				spe->sync_switch = true;
			}
		}
	}

	arm_spe_log("queue %u decoding cpu %d pid %d tid %d\n",
		     speq->queue_nr, speq->cpu, speq->pid, speq->tid);
	while (1) {
		err = arm_spe_sample(speq);
		if (err)
			return err;

		state = arm_spe_decode(speq->decoder);
		if (state->err) {
			if (state->err == ARM_SPE_ERR_NODATA)
				return 1;
			if (spe->sync_switch &&
			    state->from_ip >= spe->kernel_start) {
				spe->sync_switch = false;
				arm_spe_next_tid(spe, speq);
			}
			if (spe->synth_opts.errors) {
				err = arm_spe_synth_error(spe, state->err,
							   speq->cpu, speq->pid,
							   speq->tid,
							   state->from_ip);
				if (err)
					return err;
			}
			continue;
		}

		speq->state = state;
		speq->have_sample = true;
		arm_spe_sample_flags(speq);

		/* Use estimated TSC upon return to user space */
		if (spe->est_tsc &&
		    (state->from_ip >= spe->kernel_start || !state->from_ip) &&
		    state->to_ip && state->to_ip < spe->kernel_start) {
			arm_spe_log("TSC %"PRIx64" est. TSC %"PRIx64"\n",
				     state->timestamp, state->est_timestamp);
			speq->timestamp = state->est_timestamp;
		/* Use estimated TSC in unknown switch state */
		} else if (spe->sync_switch &&
			   speq->switch_state == ARM_SPE_SS_UNKNOWN &&
			   arm_spe_is_switch_ip(speq, state->to_ip) &&
			   speq->next_tid == -1) {
			arm_spe_log("TSC %"PRIx64" est. TSC %"PRIx64"\n",
				     state->timestamp, state->est_timestamp);
			speq->timestamp = state->est_timestamp;
		} else if (state->timestamp > speq->timestamp) {
			speq->timestamp = state->timestamp;
		}

		if (speq->timestamp >= *timestamp) {
			*timestamp = speq->timestamp;
			return 0;
		}
	}
	return 0;
}

static inline int arm_spe_update_queues(struct arm_spe *spe)
{
	if (spe->queues.new_data) {
		spe->queues.new_data = false;
		return arm_spe_setup_queues(spe);
	}
	return 0;
}

static int arm_spe_process_queues(struct arm_spe *spe, u64 timestamp)
{
	unsigned int queue_nr;
	u64 ts;
	int ret;

	while (1) {
		struct auxtrace_queue *queue;
		struct arm_spe_queue *speq;

		if (!spe->heap.heap_cnt)
			return 0;

		if (spe->heap.heap_array[0].ordinal >= timestamp)
			return 0;

		queue_nr = spe->heap.heap_array[0].queue_nr;
		queue = &spe->queues.queue_array[queue_nr];
		speq = queue->priv;

		arm_spe_log("queue %u processing 0x%" PRIx64 " to 0x%" PRIx64 "\n",
			     queue_nr, spe->heap.heap_array[0].ordinal,
			     timestamp);

		auxtrace_heap__pop(&spe->heap);

		if (spe->heap.heap_cnt) {
			ts = spe->heap.heap_array[0].ordinal + 1;
			if (ts > timestamp)
				ts = timestamp;
		} else {
			ts = timestamp;
		}

		arm_spe_set_pid_tid_cpu(spe, queue);

		ret = arm_spe_run_decoder(speq, &ts);

		if (ret < 0) {
			auxtrace_heap__add(&spe->heap, queue_nr, ts);
			return ret;
		}

		if (!ret) {
			ret = auxtrace_heap__add(&spe->heap, queue_nr, ts);
			if (ret < 0)
				return ret;
		} else {
			speq->on_heap = false;
		}
	}

	return 0;
}

static int arm_spe_lost(struct arm_spe *spe, struct perf_sample *sample)
{
	return arm_spe_synth_error(spe, ARM_SPE_ERR_LOST, sample->cpu,
				    sample->pid, sample->tid, 0);
}

static struct arm_spe_queue *arm_spe_cpu_to_speq(struct arm_spe *spe, int cpu)
{
	unsigned i, j;

	if (cpu < 0 || !spe->queues.nr_queues)
		return NULL;

	if ((unsigned)cpu >= spe->queues.nr_queues)
		i = spe->queues.nr_queues - 1;
	else
		i = cpu;

	if (spe->queues.queue_array[i].cpu == cpu)
		return spe->queues.queue_array[i].priv;

	for (j = 0; i > 0; j++) {
		if (spe->queues.queue_array[--i].cpu == cpu)
			return spe->queues.queue_array[i].priv;
	}

	for (; j < spe->queues.nr_queues; j++) {
		if (spe->queues.queue_array[j].cpu == cpu)
			return spe->queues.queue_array[j].priv;
	}

	return NULL;
}

static int arm_spe_sync_switch(struct arm_spe *spe, int cpu, pid_t tid,
				u64 timestamp)
{
	struct arm_spe_queue *speq;
	int err;

	if (!spe->sync_switch)
		return 1;

	speq = arm_spe_cpu_to_speq(spe, cpu);
	if (!speq)
		return 1;

	switch (speq->switch_state) {
	case ARM_SPE_SS_NOT_TRACING:
		speq->next_tid = -1;
		break;
	case ARM_SPE_SS_UNKNOWN:
	case ARM_SPE_SS_TRACING:
		speq->next_tid = tid;
		speq->switch_state = ARM_SPE_SS_EXPECTING_SWITCH_IP;
		return 0;
	case ARM_SPE_SS_EXPECTING_SWITCH_EVENT:
		if (!speq->on_heap) {
			speq->timestamp = perf_time_to_tsc(timestamp,
							  &spe->tc);
			err = auxtrace_heap__add(&spe->heap, speq->queue_nr,
						 speq->timestamp);
			if (err)
				return err;
			speq->on_heap = true;
		}
		speq->switch_state = ARM_SPE_SS_TRACING;
		break;
	case ARM_SPE_SS_EXPECTING_SWITCH_IP:
		speq->next_tid = tid;
		arm_spe_log("ERROR: cpu %d expecting switch ip\n", cpu);
		break;
	default:
		break;
	}

	return 1;
}

static int arm_spe_process_switch(struct arm_spe *spe,
				   struct perf_sample *sample)
{
	struct perf_evsel *evsel;
	pid_t tid;
	int cpu, ret;

	evsel = perf_evlist__id2evsel(spe->session->evlist, sample->id);
	if (evsel != spe->switch_evsel)
		return 0;

	tid = perf_evsel__intval(evsel, sample, "next_pid");
	cpu = sample->cpu;

	arm_spe_log("sched_switch: cpu %d tid %d time %"PRIu64" tsc %#"PRIx64"\n",
		     cpu, tid, sample->time, perf_time_to_tsc(sample->time,
		     &spe->tc));

	ret = arm_spe_sync_switch(spe, cpu, tid, sample->time);
	if (ret <= 0)
		return ret;

	return machine__set_current_tid(spe->machine, cpu, -1, tid);
}

static int arm_spe_context_switch(struct arm_spe *spe, union perf_event *event,
				   struct perf_sample *sample)
{
	bool out = event->header.misc & PERF_RECORD_MISC_SWITCH_OUT;
	pid_t pid, tid;
	int cpu, ret;

	cpu = sample->cpu;

	if (spe->have_sched_switch == 3) {
		if (!out)
			return 0;
		if (event->header.type != PERF_RECORD_SWITCH_CPU_WIDE) {
			pr_err("Expecting CPU-wide context switch event\n");
			return -EINVAL;
		}
		pid = event->context_switch.next_prev_pid;
		tid = event->context_switch.next_prev_tid;
	} else {
		if (out)
			return 0;
		pid = sample->pid;
		tid = sample->tid;
	}

	if (tid == -1) {
		pr_err("context_switch event has no tid\n");
		return -EINVAL;
	}

	arm_spe_log("context_switch: cpu %d pid %d tid %d time %"PRIu64" tsc %#"PRIx64"\n",
		     cpu, pid, tid, sample->time, perf_time_to_tsc(sample->time,
		     &spe->tc));

	ret = arm_spe_sync_switch(spe, cpu, tid, sample->time);
	if (ret <= 0)
		return ret;

	return machine__set_current_tid(spe->machine, cpu, pid, tid);
}

static int arm_spe_process_itrace_start(struct arm_spe *spe,
					 union perf_event *event,
					 struct perf_sample *sample)
{
	if (!spe->per_cpu_mmaps)
		return 0;

	/* FIXME */
	sample->cpu = 1;
	arm_spe_log("itrace_start: cpu %d pid %d tid %d time %"PRIu64"\n",
		     sample->cpu, event->itrace_start.pid,
		     event->itrace_start.tid, sample->time);

	return machine__set_current_tid(spe->machine, sample->cpu,
					event->itrace_start.pid,
					event->itrace_start.tid);
}

static int arm_spe_process_event(struct perf_session *session,
				  union perf_event *event,
				  struct perf_sample *sample,
				  struct perf_tool *tool)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					   auxtrace);
	u64 timestamp;
	int err = 0;

	if (dump_trace)
		return 0;

	if (!tool->ordered_events) {
		pr_err("ARM SPE requires ordered events\n");
		return -EINVAL;
	}

	/* prevent floating crash until time fixed.
	 * make conditions hit below since we need to
	 * enter process_queues()
	 */
	timestamp = 1;

	if (timestamp) {
		err = arm_spe_update_queues(spe);
		if (err)
			return err;
	}

	if (timestamp)
		err = arm_spe_process_queues(spe, timestamp);
	if (err)
		return err;

	if (event->header.type == PERF_RECORD_AUX &&
	    (event->aux.flags & PERF_AUX_FLAG_TRUNCATED) &&
	    spe->synth_opts.errors) {
		err = arm_spe_lost(spe, sample);
		pr_err("%s %d: err %d\n", __func__, __LINE__, err);
		if (err)
			return err;
	}

	if (spe->switch_evsel && event->header.type == PERF_RECORD_SAMPLE)
		err = arm_spe_process_switch(spe, sample);
	else if (event->header.type == PERF_RECORD_ITRACE_START)
		err = arm_spe_process_itrace_start(spe, event, sample);
	else if (event->header.type == PERF_RECORD_SWITCH ||
		 event->header.type == PERF_RECORD_SWITCH_CPU_WIDE)
		err = arm_spe_context_switch(spe, event, sample);

	arm_spe_log("event %s (%u): cpu %d time %"PRIu64" tsc %#"PRIx64"\n",
		     perf_event__name(event->header.type), event->header.type,
		     sample->cpu, sample->time, timestamp);

	return err;
}

static int arm_spe_flush(struct perf_session *session, struct perf_tool *tool)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					   auxtrace);
	int ret;

	if (dump_trace)
		return 0;

	if (!tool->ordered_events)
		return -EINVAL;

	ret = arm_spe_update_queues(spe);
	if (ret < 0)
		return ret;

	return arm_spe_process_queues(spe, MAX_TIMESTAMP);
}

static void arm_spe_free_events(struct perf_session *session)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					   auxtrace);
	struct auxtrace_queues *queues = &spe->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		arm_spe_free_queue(queues->queue_array[i].priv);
		queues->queue_array[i].priv = NULL;
	}
	arm_spe_log_disable();
	auxtrace_queues__free(queues);
}

static void arm_spe_free(struct perf_session *session)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					   auxtrace);

	auxtrace_heap__free(&spe->heap);
	arm_spe_free_events(session);
	session->auxtrace = NULL;
	thread__put(spe->unknown_thread);
	free(spe);
}

static int arm_spe_process_auxtrace_event(struct perf_session *session,
					   union perf_event *event,
					   struct perf_tool *tool __maybe_unused)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					   auxtrace);

	if (spe->sampling_mode)
		return 0;

	if (!spe->data_queued) {
		struct auxtrace_buffer *buffer;
		off_t data_offset;
		int fd = perf_data_file__fd(session->file);
		int err;

		if (perf_data_file__is_pipe(session->file)) {
			data_offset = 0;
		} else {
			data_offset = lseek(fd, 0, SEEK_CUR);
			if (data_offset == -1)
				return -errno;
		}

		err = auxtrace_queues__add_event(&spe->queues, session, event,
						 data_offset, &buffer);
		if (err)
			return err;

		/* Dump here now we have copied a piped trace out of the pipe */
		if (dump_trace) {
			if (auxtrace_buffer__get_data(buffer, fd)) {
				arm_spe_dump_event(spe, buffer->data,
						    buffer->size);
				auxtrace_buffer__put_data(buffer);
			}
		}
	}

	return 0;
}

struct arm_spe_synth {
	struct perf_tool dummy_tool;
	struct perf_session *session;
};

static int arm_spe_event_synth(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample __maybe_unused,
				struct machine *machine __maybe_unused)
{
	struct arm_spe_synth *arm_spe_synth =
			container_of(tool, struct arm_spe_synth, dummy_tool);

	return perf_session__deliver_synth_event(arm_spe_synth->session, event,
						 NULL);
}

static int arm_spe_synth_event(struct perf_session *session,
				struct perf_event_attr *attr, u64 id)
{
	struct arm_spe_synth arm_spe_synth;

	memset(&arm_spe_synth, 0, sizeof(struct arm_spe_synth));
	arm_spe_synth.session = session;

	return perf_event__synthesize_attr(&arm_spe_synth.dummy_tool, attr, 1,
					   &id, arm_spe_event_synth);
}

static int arm_spe_synth_events(struct arm_spe *spe,
				struct perf_session *session)
{
	struct perf_evlist *evlist = session->evlist;
	struct perf_evsel *evsel;
	struct perf_event_attr attr;
	bool found = false;
	u64 id;
	int err;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.type == spe->pmu_type && evsel->ids) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_debug("There are no selected events with ARM SPE data\n");
		return 0;
	}

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.sample_type = evsel->attr.sample_type & PERF_SAMPLE_MASK;
	attr.sample_type |= PERF_SAMPLE_IP | PERF_SAMPLE_TID |
			    PERF_SAMPLE_PERIOD;
	attr.sample_type |= PERF_SAMPLE_TIME;
	if (!spe->per_cpu_mmaps)
		attr.sample_type &= ~(u64)PERF_SAMPLE_CPU;
	attr.exclude_user = evsel->attr.exclude_user;
	attr.exclude_kernel = evsel->attr.exclude_kernel;
	attr.exclude_hv = evsel->attr.exclude_hv;
	attr.exclude_host = evsel->attr.exclude_host;
	attr.exclude_guest = evsel->attr.exclude_guest;
	attr.sample_id_all = evsel->attr.sample_id_all;
	attr.read_format = evsel->attr.read_format;

	id = evsel->id[0] + 1000000000;
	if (!id)
		id = 1;

	if (spe->synth_opts.instructions) {
		attr.config = PERF_COUNT_HW_INSTRUCTIONS;
		if (spe->synth_opts.period_type == PERF_ITRACE_PERIOD_NANOSECS)
			attr.sample_period = 1024; /* FIXME */
		else
			attr.sample_period = spe->synth_opts.period;
		spe->instructions_sample_period = attr.sample_period;
		if (spe->synth_opts.callchain)
			attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
		if (spe->synth_opts.last_branch)
			attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
		pr_err("Synthesizing 'instructions' event with id %" PRIu64
			" sample type %#" PRIx64 "\n",
			 id, (u64)attr.sample_type);
		err = arm_spe_synth_event(session, &attr, id);
		if (err)
			return err;
		spe->sample_instructions = true;
		spe->instructions_sample_type = attr.sample_type;
		spe->instructions_id = id;
		id += 1;
	}

	if (spe->synth_opts.transactions) {
		attr.config = PERF_COUNT_HW_INSTRUCTIONS;
		attr.sample_period = 1;
		if (spe->synth_opts.callchain)
			attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
		if (spe->synth_opts.last_branch)
			attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
		err = arm_spe_synth_event(session, &attr, id);
		if (err)
			return err;
		spe->sample_transactions = true;
		spe->transactions_id = id;
		id += 1;
		evlist__for_each_entry(evlist, evsel) {
			if (evsel->id && evsel->id[0] == spe->transactions_id) {
				if (evsel->name)
					zfree(&evsel->name);
				evsel->name = strdup("transactions");
				break;
			}
		}
	}

	if (spe->synth_opts.branches) {
		attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
		attr.sample_period = 1;
		attr.sample_type |= PERF_SAMPLE_ADDR;
		attr.sample_type &= ~(u64)PERF_SAMPLE_CALLCHAIN;
		attr.sample_type &= ~(u64)PERF_SAMPLE_BRANCH_STACK;
		err = arm_spe_synth_event(session, &attr, id);
		if (err)
			return err;
		spe->sample_branches = true;
		spe->branches_sample_type = attr.sample_type;
		spe->branches_id = id;
	}

	spe->synth_needs_swap = evsel->needs_swap;

	return 0;
}

static struct perf_evsel *arm_spe_find_sched_switch(struct perf_evlist *evlist)
{
	struct perf_evsel *evsel;

	evlist__for_each_entry_reverse(evlist, evsel) {
		const char *name = perf_evsel__name(evsel);

		if (!strcmp(name, "sched:sched_switch"))
			return evsel;
	}

	return NULL;
}

static bool arm_spe_find_switch(struct perf_evlist *evlist)
{
	struct perf_evsel *evsel;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.context_switch)
			return true;
	}

	return false;
}

static int arm_spe_perf_config(const char *var, const char *value, void *data)
{
	struct arm_spe *spe = data;

	if (!strcmp(var, "intel-pt.mispred-all"))
		spe->mispred_all = perf_config_bool(var, value);

	return 0;
}

static const char * const arm_spe_info_fmts[] = {
	[ARM_SPE_PMU_TYPE]		= "  PMU Type            %"PRId64"\n",
	[ARM_SPE_TS_ENABLE]		= "  Timestamps          %"PRId64"\n",
	[ARM_SPE_PA_ENABLE]		= "  Physical Addresses  %"PRId64"\n",
	[ARM_SPE_JITTER]		= "  jitter              %"PRId64"\n",
	[ARM_SPE_LOAD_FILTER]		= "  Load filter         %"PRId64"\n",
	[ARM_SPE_STORE_FILTER]		= "  Store filter        %"PRId64"\n",
	[ARM_SPE_BRANCH_FILTER]		= "  Branch filter       %"PRId64"\n",
	[ARM_SPE_MIN_LATENCY]		= "  Minimum Latency     %"PRId64"\n",
	[ARM_SPE_HAVE_SCHED_SWITCH]	= "  Have sched_switch   %"PRId64"\n",
	[ARM_SPE_SNAPSHOT_MODE]		= "  Snapshot mode       %"PRId64"\n",
	[ARM_SPE_PER_CPU_MMAPS]		= "  Per-cpu maps        %"PRId64"\n",
};

static void arm_spe_print_info(u64 *arr, int start, int finish)
{
	int i;

	if (!dump_trace)
		return;

	for (i = start; i <= finish; i++)
		fprintf(stdout, arm_spe_info_fmts[i], arr[i]);
}

int arm_spe_process_auxtrace_info(union perf_event *event,
				   struct perf_session *session)
{
	struct auxtrace_info_event *auxtrace_info = &event->auxtrace_info;
	size_t min_sz = sizeof(u64) * ARM_SPE_PER_CPU_MMAPS;
	struct arm_spe *spe;
	int err;


	if (auxtrace_info->header.size < sizeof(struct auxtrace_info_event) +
					min_sz)
		return -EINVAL;

	spe = zalloc(sizeof(struct arm_spe));
	if (!spe)
		return -ENOMEM;

	perf_config(arm_spe_perf_config, spe);

	err = auxtrace_queues__init(&spe->queues);
	if (err)
		goto err_free;

	arm_spe_log_set_name(ARM_SPE_PMU_NAME);

	spe->session = session;
	spe->machine = &session->machines.host; /* No kvm support */
	spe->auxtrace_type = auxtrace_info->type;
	spe->pmu_type = auxtrace_info->priv[ARM_SPE_PMU_TYPE];
	spe->ts_enable = auxtrace_info->priv[ARM_SPE_TS_ENABLE];
	spe->pa_enable = auxtrace_info->priv[ARM_SPE_PA_ENABLE];
	spe->jitter = auxtrace_info->priv[ARM_SPE_JITTER];
	spe->load_filter = auxtrace_info->priv[ARM_SPE_LOAD_FILTER];
	spe->store_filter = auxtrace_info->priv[ARM_SPE_STORE_FILTER];
	spe->branch_filter = auxtrace_info->priv[ARM_SPE_BRANCH_FILTER];
	spe->min_latency = auxtrace_info->priv[ARM_SPE_MIN_LATENCY];
	spe->have_sched_switch = auxtrace_info->priv[ARM_SPE_HAVE_SCHED_SWITCH];
	spe->snapshot_mode = auxtrace_info->priv[ARM_SPE_SNAPSHOT_MODE];
	spe->per_cpu_mmaps = auxtrace_info->priv[ARM_SPE_PER_CPU_MMAPS];
	arm_spe_print_info(&auxtrace_info->priv[0], ARM_SPE_PMU_TYPE,
			    ARM_SPE_PER_CPU_MMAPS);

	spe->have_tsc = false;
	spe->sampling_mode = false;

	spe->unknown_thread = thread__new(999999999, 999999999);
	if (!spe->unknown_thread) {
		err = -ENOMEM;
		goto err_free_queues;
	}

	/*
	 * Since this thread will not be kept in any rbtree not in a
	 * list, initialize its list node so that at thread__put() the
	 * current thread lifetime assuption is kept and we don't segfault
	 * at list_del_init().
	 */
	INIT_LIST_HEAD(&spe->unknown_thread->node);

	err = thread__set_comm(spe->unknown_thread, "unknown", 0);
	if (err)
		goto err_delete_thread;
	if (thread__init_map_groups(spe->unknown_thread, spe->machine)) {
		err = -ENOMEM;
		goto err_delete_thread;
	}

	spe->auxtrace.process_event = arm_spe_process_event;
	spe->auxtrace.process_auxtrace_event = arm_spe_process_auxtrace_event;
	spe->auxtrace.flush_events = arm_spe_flush;
	spe->auxtrace.free_events = arm_spe_free_events;
	spe->auxtrace.free = arm_spe_free;
	session->auxtrace = &spe->auxtrace;

	if (dump_trace)
		return 0;

	if (spe->have_sched_switch == 1) {
		spe->switch_evsel = arm_spe_find_sched_switch(session->evlist);
		if (!spe->switch_evsel)
			goto err_delete_thread;
	} else if (spe->have_sched_switch == 2 &&
		   !arm_spe_find_switch(session->evlist))
		goto err_delete_thread;

	if (session->itrace_synth_opts && session->itrace_synth_opts->set) {
		spe->synth_opts = *session->itrace_synth_opts;
	} else {
		itrace_synth_opts__set_default(&spe->synth_opts);
		if (use_browser != -1) {
			spe->synth_opts.branches = false;
			spe->synth_opts.callchain = true;
		}
		if (session->itrace_synth_opts)
			spe->synth_opts.thread_stack =
				session->itrace_synth_opts->thread_stack;
	}

	if (spe->synth_opts.log)
		arm_spe_log_enable();

	if (spe->synth_opts.calls)
		spe->branches_filter |= PERF_IP_FLAG_CALL | PERF_IP_FLAG_ASYNC |
				       PERF_IP_FLAG_TRACE_END;
	if (spe->synth_opts.returns)
		spe->branches_filter |= PERF_IP_FLAG_RETURN |
				       PERF_IP_FLAG_TRACE_BEGIN;

	if (spe->synth_opts.callchain && !symbol_conf.use_callchain) {
		symbol_conf.use_callchain = true;
		if (callchain_register_param(&callchain_param) < 0) {
			symbol_conf.use_callchain = false;
			spe->synth_opts.callchain = false;
		}
	}

	err = arm_spe_synth_events(spe, session);
	if (err)
		goto err_delete_thread;

	err = auxtrace_queues__process_index(&spe->queues, session);
	if (err)
		goto err_delete_thread;

	if (spe->queues.populated)
		spe->data_queued = true;

	return 0;

err_delete_thread:
	thread__zput(spe->unknown_thread);
err_free_queues:
	arm_spe_log_disable();
	auxtrace_queues__free(&spe->queues);
	session->auxtrace = NULL;
err_free:
	free(spe);
	return err;
}
