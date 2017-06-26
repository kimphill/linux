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

#include <endian.h>
#include <errno.h>
#include <byteswap.h>
#include <inttypes.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>

#include "cpumap.h"
#include "color.h"
#include "evsel.h"
#include "evlist.h"
#include "machine.h"
#include "session.h"
#include "util.h"
#include "thread.h"
#include "thread-stack.h"
#include "debug.h"
#include "tsc.h"
#include "auxtrace.h"
#include "arm-spe.h"
#include "arm-spe-pkt-decoder.h"

#define MAX_TIMESTAMP (~0ULL)

#define ARM_SPE_ERR_NOINSN  5
#define ARM_SPE_ERR_LOST    9

#if __BYTE_ORDER == __BIG_ENDIAN
#define le64_to_cpu bswap_64
#else
#define le64_to_cpu
#endif

struct arm_spe {
	struct auxtrace			auxtrace;
	struct auxtrace_queues		queues;
	struct auxtrace_heap		heap;
	u32				auxtrace_type;
	struct perf_session		*session;
	struct machine			*machine;
	bool				data_queued;
	u32				pmu_type;
	struct perf_tsc_conversion	tc;
	bool				cap_user_time_zero;
	struct itrace_synth_opts	synth_opts;
	bool				sample_branches;
	u32				branches_filter;
	u64				branches_sample_type;
	u64				branches_id;
	size_t				branches_event_size;
	bool				synth_needs_swap;
	unsigned long			num_events;
};

struct arm_spe_queue {
	struct arm_spe		*spe;
	unsigned int		queue_nr;
	struct auxtrace_buffer	*buffer;
	bool			on_heap;
	bool			done;
	pid_t			pid;
	pid_t			tid;
	int			cpu;
	u64			time;
	u8			arm_insn[4];
	u32			sample_flags;
};

/* FIXME: rmthis: bts h/w struct */
struct branch {
	u64 from;
	u64 to;
	u64 misc;
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
		      ". ... ARM SPE data: size %zu bytes\n",
		      len);

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
	printf(".\n");
	arm_spe_dump(spe, buf, len);
}

static int arm_spe_lost(struct arm_spe *spe, struct perf_sample *sample)
{
	union perf_event event;
	int err;

	auxtrace_synth_error(&event.auxtrace_error, PERF_AUXTRACE_ERROR_ITRACE,
			     ARM_SPE_ERR_LOST, sample->cpu, sample->pid,
			     sample->tid, 0, "Lost trace data");

	err = perf_session__deliver_synth_event(spe->session, &event, NULL);
	if (err)
		pr_err("ARM SPE: failed to deliver error event, error %d\n",
		       err);

	return err;
}

static struct arm_spe_queue *arm_spe_alloc_queue(struct arm_spe *spe,
						     unsigned int queue_nr)
{
	struct arm_spe_queue *speq;

	speq = zalloc(sizeof(struct arm_spe_queue));
	if (!speq)
		return NULL;

	speq->spe = spe;
	speq->queue_nr = queue_nr;
	speq->pid = -1;
	speq->tid = -1;
	speq->cpu = -1;

	return speq;
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

	if (!speq->on_heap && !speq->buffer) {
		int ret;

		speq->buffer = auxtrace_buffer__next(queue, NULL);
		if (!speq->buffer)
			return 0;

		ret = auxtrace_heap__add(&spe->heap, queue_nr,
					 speq->buffer->reference);
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
		ret = arm_spe_setup_queue(spe, &spe->queues.queue_array[i],
					    i);
		if (ret)
			return ret;
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

static unsigned char *arm_spe_find_overlap(unsigned char *buf_a, size_t len_a,
					     unsigned char *buf_b, size_t len_b)
{
	size_t offs, len;

	if (len_a > len_b)
		offs = len_a - len_b;
	else
		offs = 0;

	for (; offs < len_a; offs += sizeof(struct branch)) {
		len = len_a - offs;
		if (!memcmp(buf_a + offs, buf_b, len))
			return buf_b + len;
	}

	return buf_b;
}

static int arm_spe_do_fix_overlap(struct auxtrace_queue *queue,
				    struct auxtrace_buffer *b)
{
	struct auxtrace_buffer *a;
	void *start;

	if (b->list.prev == &queue->head)
		return 0;
	a = list_entry(b->list.prev, struct auxtrace_buffer, list);
	start = arm_spe_find_overlap(a->data, a->size, b->data, b->size);
	if (!start)
		return -EINVAL;
	b->use_size = b->data + b->size - start;
	b->use_data = start;
	return 0;
}

static int arm_spe_synth_branch_sample(struct arm_spe_queue *speq,
					 struct branch *branch)
{
	int ret;
	struct arm_spe *spe = speq->spe;
	union perf_event event;
	struct perf_sample sample = { .ip = 0, };

	if (spe->synth_opts.initial_skip &&
	    spe->num_events++ <= spe->synth_opts.initial_skip)
		return 0;

	event.sample.header.type = PERF_RECORD_SAMPLE;
	event.sample.header.misc = PERF_RECORD_MISC_USER;
	event.sample.header.size = sizeof(struct perf_event_header);

	sample.cpumode = PERF_RECORD_MISC_USER;
	sample.ip = le64_to_cpu(branch->from);
	sample.pid = speq->pid;
	sample.tid = speq->tid;
	sample.addr = le64_to_cpu(branch->to);
	sample.id = speq->spe->branches_id;
	sample.stream_id = speq->spe->branches_id;
	sample.period = 1;
	sample.cpu = speq->cpu;
	sample.flags = speq->sample_flags;
	sample.insn_len = sizeof(speq->arm_insn);
	memcpy(sample.insn, &speq->arm_insn, sizeof(speq->arm_insn));

	if (spe->synth_opts.inject) {
		event.sample.header.size = spe->branches_event_size;
		ret = perf_event__synthesize_sample(&event,
						    spe->branches_sample_type,
						    0, &sample,
						    spe->synth_needs_swap);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(spe->session, &event, &sample);
	if (ret)
		pr_err("ARM SPE: failed to deliver branch event, error %d\n",
		       ret);

	return ret;
}

static int arm_spe_get_next_insn(struct arm_spe_queue *speq, u64 ip)
{
	struct machine *machine = speq->spe->machine;
	struct thread *thread;
	struct addr_location al;
	size_t len;
	uint8_t cpumode;
	int err = -1;

	if (machine__kernel_ip(machine, ip))
		cpumode = PERF_RECORD_MISC_KERNEL;
	else
		cpumode = PERF_RECORD_MISC_USER;

	thread = machine__find_thread(machine, -1, speq->tid);
	if (!thread)
		return -1;

	thread__find_addr_map(thread, cpumode, MAP__FUNCTION, ip, &al);
	if (!al.map || !al.map->dso)
		goto out_put;

	len = dso__data_read_addr(al.map->dso, al.map, machine, ip,
				  speq->arm_insn, sizeof(speq->arm_insn));
	if (len < sizeof(speq->arm_insn))
		goto out_put;

	/* Load maps to ensure dso->is_64_bit has been updated */
	//FIXME: verify if needed: map__load(al.map);

	err = 0;
out_put:
	thread__put(thread);
	return err;
}

static int arm_spe_synth_error(struct arm_spe *spe, int cpu, pid_t pid,
				 pid_t tid, u64 ip)
{
	union perf_event event;
	int err;

	auxtrace_synth_error(&event.auxtrace_error, PERF_AUXTRACE_ERROR_ITRACE,
			     ARM_SPE_ERR_NOINSN, cpu, pid, tid, ip,
			     "Failed to get instruction");

	err = perf_session__deliver_synth_event(spe->session, &event, NULL);
	if (err)
		pr_err("ARM SPE: failed to deliver error event, error %d\n",
		       err);

	return err;
}


#if 0
/* FIXME: really need, or garner from raw SPE data? */
int arm_insn_type(void /*enum intel_pt_insn_op op*/)
{
	return PERF_IP_FLAG_BRANCH;

	PERF_IP_FLAG_BRANCH		= 1ULL << 0,
	PERF_IP_FLAG_CALL		= 1ULL << 1,
	PERF_IP_FLAG_RETURN		= 1ULL << 2,
	PERF_IP_FLAG_CONDITIONAL	= 1ULL << 3,
	PERF_IP_FLAG_SYSCALLRET		= 1ULL << 4,
	PERF_IP_FLAG_ASYNC		= 1ULL << 5,
	PERF_IP_FLAG_INTERRUPT		= 1ULL << 6,
	PERF_IP_FLAG_TX_ABORT		= 1ULL << 7,
	PERF_IP_FLAG_TRACE_BEGIN	= 1ULL << 8,
	PERF_IP_FLAG_TRACE_END		= 1ULL << 9,
	PERF_IP_FLAG_IN_TX		= 1ULL << 10,

221         case INTEL_PT_OP_OTHER:
222                 return 0;
223         case INTEL_PT_OP_CALL:
224                 return PERF_IP_FLAG_BRANCH | PERF_IP_FLAG_CALL;
...
}
#endif

static int arm_spe_get_branch_type(struct arm_spe_queue *speq,
				     struct branch *branch)
{
	int err;

	if (!branch->from) {
		if (branch->to)
			speq->sample_flags = PERF_IP_FLAG_BRANCH |
					     PERF_IP_FLAG_TRACE_BEGIN;
		else
			speq->sample_flags = 0;
		/* FIXME was length = 0 */
		memset(speq->arm_insn, 0, sizeof(speq->arm_insn));
	} else if (!branch->to) {
		speq->sample_flags = PERF_IP_FLAG_BRANCH |
				     PERF_IP_FLAG_TRACE_END;
		/* FIXME was length = 0 */
		memset(speq->arm_insn, 0, sizeof(speq->arm_insn));
	} else {
		err = arm_spe_get_next_insn(speq, branch->from);
		if (err) {
			speq->sample_flags = 0;
			/* FIXME was length = 0 */
			memset(speq->arm_insn, 0, sizeof(speq->arm_insn));
			if (!speq->spe->synth_opts.errors)
				return 0;
			err = arm_spe_synth_error(speq->spe, speq->cpu,
						    speq->pid, speq->tid,
						    branch->from);
			return err;
		}
		//FIXME: was: arm_insn_type(/*speq->intel_pt_insn.op*/);
		speq->sample_flags = PERF_IP_FLAG_BRANCH;
		/* Check for an async branch into the kernel */
		if (!machine__kernel_ip(speq->spe->machine, branch->from) &&
		    machine__kernel_ip(speq->spe->machine, branch->to) &&
		    speq->sample_flags != (PERF_IP_FLAG_BRANCH |
					   PERF_IP_FLAG_CALL |
					   PERF_IP_FLAG_SYSCALLRET))
			speq->sample_flags = PERF_IP_FLAG_BRANCH |
					     PERF_IP_FLAG_CALL |
					     PERF_IP_FLAG_ASYNC |
					     PERF_IP_FLAG_INTERRUPT;
	}

	return 0;
}

static int arm_spe_process_buffer(struct arm_spe_queue *speq,
				  struct auxtrace_buffer *buffer,
				  struct thread *thread __maybe_unused)
{
	struct arm_spe_pkt packet;
	void *buf;
	struct branch branch;
	int buf_len, ret, pkt_len;

	if (buffer->use_data) {
		buf_len = buffer->use_size;
		buf = buffer->use_data;
	} else {
		buf_len = buffer->size;
		buf = buffer->data;
	}

	if (!speq->spe->sample_branches)
		return 0;

	while (buf_len) {
		ret = arm_spe_get_packet(buf, buf_len, &packet);
		if (ret > 0)
			pkt_len = ret;
		else
			pkt_len = 1;
		if (ret > 0) {
			/* check for branches */
/*
.  000000ad:  4a 00                                           B
.  000000af:  b1 60 dd 37 08 00 00 ff ff                      TGT ff00000837dd60 el3 ns=1
.  000000b8:  42 02                                           RETIRED 
.  000000ba:  b0 e8 1f 20 08 00 00 ff ff                      PC ff000008201fe8 el3 ns=1
.  000000c3:  98 00 00                                        LAT 0 TOT
.  000000c6:  01                                              END
*/

			if (packet.type == ARM_SPE_INSN_TYPE &&
			    packet.index == 2) {
				branch.to = *(u64 *)((void *)buf + 3);
				branch.from = *(u64 *)((void *)buf + 14);
				branch.misc = 0;
				arm_spe_get_branch_type(speq, &branch);
#if 0
		if (speq->spe->synth_opts.thread_stack)
			thread_stack__event(thread, speq->sample_flags,
					    le64_to_cpu(branch.from),
					    le64_to_cpu(branch.to),
					    4 /*speq->intel_pt_insn.length */,
					    buffer->buffer_nr + 1);
#endif
				ret = arm_spe_synth_branch_sample(speq, &branch);
				if (ret)
					break;  /* FIXME: breaking from? */
				
			}
		}
		buf += pkt_len;
		buf_len -= pkt_len;
	}

#if 0
	for (; sz > bsz; branch += 1, sz -= bsz) {
		if (!branch->from && !branch->to)
			continue;
		arm_spe_get_branch_type(speq, branch);
		if (speq->spe->synth_opts.thread_stack)
			thread_stack__event(thread, speq->sample_flags,
					    le64_to_cpu(branch->from),
					    le64_to_cpu(branch->to),
					    4 /*speq->intel_pt_insn.length */,
					    buffer->buffer_nr + 1);
		if (filter && !(filter & speq->sample_flags))
			continue;
		err = arm_spe_synth_branch_sample(speq, branch);
		if (err)
			break;
	}
#endif
	return ret;
}

static int arm_spe_process_queue(struct arm_spe_queue *speq, u64 *timestamp)
{
	struct auxtrace_buffer *buffer = speq->buffer;
	struct auxtrace_queue *queue;
	struct thread *thread;
	int err;

	if (speq->done)
		return 1;

	if (speq->pid == -1) {
		thread = machine__find_thread(speq->spe->machine, -1,
					      speq->tid);
		if (thread)
			speq->pid = thread->pid_;
	} else {
		thread = machine__findnew_thread(speq->spe->machine, speq->pid,
						 speq->tid);
	}

	queue = &speq->spe->queues.queue_array[speq->queue_nr];

	if (!buffer)
		buffer = auxtrace_buffer__next(queue, NULL);

	if (!buffer) {
		err = 1;
		goto out_put;
	}

	/* Currently there is no support for split buffers */
	if (buffer->consecutive) {
		err = -EINVAL;
		goto out_put;
	}

	if (!buffer->data) {
		int fd = perf_data_file__fd(speq->spe->session->file);

		buffer->data = auxtrace_buffer__get_data(buffer, fd);
		if (!buffer->data) {
			err = -ENOMEM;
			goto out_put;
		}
	}

	if (!speq->spe->synth_opts.callchain &&
	    !speq->spe->synth_opts.thread_stack && thread)
		thread_stack__set_trace_nr(thread, buffer->buffer_nr + 1);

	err = arm_spe_process_buffer(speq, buffer, thread);

	auxtrace_buffer__drop_data(buffer);

	speq->buffer = auxtrace_buffer__next(queue, buffer);
	if (speq->buffer)
		if (timestamp)
			*timestamp = speq->buffer->reference;
out_put:
	thread__put(thread);
	return err;
}

static int arm_spe_flush_queue(struct arm_spe_queue *speq)
{
	u64 ts = 0;
	int ret;

	while (1) {
		ret = arm_spe_process_queue(speq, &ts);
		if (ret < 0)
			return ret;
		if (ret)
			break;
	}
	return 0;
}

static int arm_spe_process_tid_exit(struct arm_spe *spe, pid_t tid)
{
	struct auxtrace_queues *queues = &spe->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		struct auxtrace_queue *queue = &spe->queues.queue_array[i];
		struct arm_spe_queue *speq = queue->priv;

		if (speq && speq->tid == tid)
			return arm_spe_flush_queue(speq);
	}
	return 0;
}

static int arm_spe_process_queues(struct arm_spe *spe, u64 timestamp)
{
	while (1) {
		unsigned int queue_nr;
		struct auxtrace_queue *queue;
		struct arm_spe_queue *speq;
		u64 ts = 0;
		int ret;

		if (!spe->heap.heap_cnt)
			return 0;

		if (spe->heap.heap_array[0].ordinal > timestamp)
			return 0;

		queue_nr = spe->heap.heap_array[0].queue_nr;
		queue = &spe->queues.queue_array[queue_nr];
		speq = queue->priv;

		auxtrace_heap__pop(&spe->heap);

		ret = arm_spe_process_queue(speq, &ts);
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

static int arm_spe_process_event(struct perf_session *session,
				   union perf_event *event,
				   struct perf_sample *sample,
				   struct perf_tool *tool)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					     auxtrace);
	u64 timestamp;
	int err;

	if (dump_trace)
		return 0;

	if (!tool->ordered_events) {
		pr_err("ARM SPE requires ordered events\n");
		return -EINVAL;
	}

#if 0
	/* FIXME: cause of SIGFPE in non-D report */
	if (sample->time && sample->time != (u64)-1)
		timestamp = perf_time_to_tsc(sample->time, &spe->tc);
	else
#endif
		timestamp = 0;

	err = arm_spe_update_queues(spe);
	if (err)
		return err;

	err = arm_spe_process_queues(spe, timestamp);
	if (err)
		return err;
	if (event->header.type == PERF_RECORD_EXIT) {
		err = arm_spe_process_tid_exit(spe, event->fork.tid);
		if (err)
			return err;
	}

	if (event->header.type == PERF_RECORD_AUX &&
	    (event->aux.flags & PERF_AUX_FLAG_TRUNCATED) &&
	    spe->synth_opts.errors)
		err = arm_spe_lost(spe, sample);

	return err;
}

static int arm_spe_process_auxtrace_event(struct perf_session *session,
					    union perf_event *event,
					    struct perf_tool *tool __maybe_unused)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					     auxtrace);

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

static int arm_spe_flush(struct perf_session *session,
			   struct perf_tool *tool __maybe_unused)
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

static void arm_spe_free_queue(void *priv)
{
	struct arm_spe_queue *speq = priv;

	if (!speq)
		return;
	free(speq);
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
	auxtrace_queues__free(queues);
}

static void arm_spe_free(struct perf_session *session)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					     auxtrace);

	auxtrace_heap__free(&spe->heap);
	arm_spe_free_events(session);
	session->auxtrace = NULL;
	free(spe);
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

	return perf_session__deliver_synth_event(arm_spe_synth->session,
						 event, NULL);
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
	attr.sample_type &= ~(u64)PERF_SAMPLE_TIME;
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

	if (spe->synth_opts.branches) {
		attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
		attr.sample_period = 1;
		attr.sample_type |= PERF_SAMPLE_ADDR;
		pr_debug("Synthesizing 'branches' event with id %" PRIu64 " sample type %#" PRIx64 "\n",
			 id, (u64)attr.sample_type);
		err = arm_spe_synth_event(session, &attr, id);
		if (err) {
			pr_err("%s: failed to synthesize 'branches' event type\n",
			       __func__);
			return err;
		}
		spe->sample_branches = true;
		spe->branches_sample_type = attr.sample_type;
		spe->branches_id = id;
		/*
		 * We only use sample types from PERF_SAMPLE_MASK so we can use
		 * __perf_evsel__sample_size() here.
		 */
		spe->branches_event_size = sizeof(struct sample_event) +
				__perf_evsel__sample_size(attr.sample_type);
	}

	spe->synth_needs_swap = evsel->needs_swap;

	return 0;
}

static const char * const arm_spe_info_fmts[] = {
	[ARM_SPE_PMU_TYPE]		= "  PMU Type           %"PRId64"\n",
};

static void arm_spe_print_info(u64 *arr)
{
	if (!dump_trace)
		return;

	fprintf(stdout, arm_spe_info_fmts[ARM_SPE_PMU_TYPE], arr[ARM_SPE_PMU_TYPE]);
}

int arm_spe_process_auxtrace_info(union perf_event *event,
				    struct perf_session *session)
{
	struct auxtrace_info_event *auxtrace_info = &event->auxtrace_info;
	size_t min_sz = sizeof(u64) * ARM_SPE_PMU_TYPE;
	struct arm_spe *spe;
	int err;

	if (auxtrace_info->header.size < sizeof(struct auxtrace_info_event) +
					min_sz)
		return -EINVAL;

	spe = zalloc(sizeof(struct arm_spe));
	if (!spe)
		return -ENOMEM;

	err = auxtrace_queues__init(&spe->queues);
	if (err)
		goto err_free;

	spe->session = session;
	spe->machine = &session->machines.host; /* No kvm support */
	spe->auxtrace_type = auxtrace_info->type;
	spe->pmu_type = auxtrace_info->priv[ARM_SPE_PMU_TYPE];

	spe->auxtrace.process_event = arm_spe_process_event;
	spe->auxtrace.process_auxtrace_event = arm_spe_process_auxtrace_event;
	spe->auxtrace.flush_events = arm_spe_flush;
	spe->auxtrace.free_events = arm_spe_free_events;
	spe->auxtrace.free = arm_spe_free;
	session->auxtrace = &spe->auxtrace;

	arm_spe_print_info(&auxtrace_info->priv[0]);
	if (dump_trace)
		return 0;

	if (session->itrace_synth_opts && session->itrace_synth_opts->set) {
		spe->synth_opts = *session->itrace_synth_opts;
	} else {
		itrace_synth_opts__set_default(&spe->synth_opts);
		if (session->itrace_synth_opts)
			spe->synth_opts.thread_stack =
				session->itrace_synth_opts->thread_stack;
	}

	if (spe->synth_opts.calls)
		spe->branches_filter |= PERF_IP_FLAG_CALL | PERF_IP_FLAG_ASYNC |
					PERF_IP_FLAG_TRACE_END;
	if (spe->synth_opts.returns)
		spe->branches_filter |= PERF_IP_FLAG_RETURN |
					PERF_IP_FLAG_TRACE_BEGIN;

	err = arm_spe_synth_events(spe, session);
	if (err)
		goto err_free_queues;

	err = auxtrace_queues__process_index(&spe->queues, session);
	if (err)
		goto err_free_queues;

	if (spe->queues.populated)
		spe->data_queued = true;

	return 0;

err_free_queues:
	auxtrace_queues__free(&spe->queues);
	session->auxtrace = NULL;
err_free:
	free(spe);
	return err;
}
