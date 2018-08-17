// SPDX-License-Identifier: GPL-2.0
/*
 * Arm Statistical Profiling Extensions (SPE) support
 * Copyright (c) 2017-2018, Arm Ltd.
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
#include "auxtrace.h"
#include "arm-spe.h"
#include "arm-spe-pkt-decoder.h"

/* duped.  Should move into pkt-decoder.h file */
#define BIT(n)		(1ULL << (n))

#define NS_FLAG		BIT(63)
#define EL_FLAG		(BIT(62) | BIT(61))

struct arm_spe {
	struct auxtrace			auxtrace;
	struct auxtrace_queues		queues;
	struct auxtrace_heap		heap;
	u32				auxtrace_type;
	struct perf_session		*session;
	struct machine			*machine;
	bool				sampling_mode;
	bool				snapshot_mode;
	u32				pmu_type;
	bool				data_queued;
	struct itrace_synth_opts	synth_opts;
	bool				sample_branches;
	u32				branches_filter;
	u64				branches_sample_type;
	u64				branches_id;
	size_t				branches_event_size;
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
	u32			arm_insn;
	u32			sample_flags;

};


#define ARM_SPE_RECORD_END_REACHED 1 /* XXX: arbitrary? */

/* BTS specific...what does an SPE Branch record look like? */
#define ARM_SPE_ERR_NOINSN  5
#define ARM_SPE_ERR_LOST    9

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

	if (spe->sampling_mode)
		return 0;

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

#if 0
static int arm_spe_synth_branch_sample(struct arm_spe_queue *speq, void *buf __maybe_unused)
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

//	sample.cpumode = PERF_RECORD_MISC_USER;
//	sample.ip = le64_to_cpu(branch->from);
	sample.pid = speq->pid;
	sample.tid = speq->tid;
//	sample.addr = le64_to_cpu(branch->to);
	sample.id = speq->spe->branches_id;
	sample.stream_id = speq->spe->branches_id;
	sample.period = 1;
	sample.cpu = speq->cpu;
	sample.flags = speq->sample_flags;
	sample.insn_len = 4;
	memcpy(sample.insn, &speq->arm_insn, 4 /*INTEL_PT_INSN_BUF_SZ*/);

	if (spe->synth_opts.inject) {
		event.sample.header.size = spe->branches_event_size;
		ret = perf_event__synthesize_sample(&event,
						    spe->branches_sample_type,
						    0, &sample);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(spe->session, &event, &sample);
	if (ret)
		pr_err("ARM SPE: failed to deliver branch event, error %d\n",
		       ret);

	return ret;
}
#endif

#if 0
static int arm_spe_get_next_insn(struct arm_spe_queue *speq, u64 ip)
{
	struct machine *machine = speq->spe->machine;
	struct thread *thread;
	struct addr_location al;
	unsigned char buf[4 /*INTEL_PT_INSN_BUF_SZ*/];
	ssize_t len;
//	int x86_64;
	uint8_t cpumode;
	int err = -1;

	if (machine__kernel_ip(machine, ip))
		cpumode = PERF_RECORD_MISC_KERNEL;
	else
		cpumode = PERF_RECORD_MISC_USER;

	thread = machine__find_thread(machine, -1, speq->tid);
	if (!thread)
		return -1;

	if (!thread__find_map(thread, cpumode, ip, &al) || !al.map->dso)
		goto out_put;

	len = dso__data_read_addr(al.map->dso, al.map, machine, ip, buf,
				  4 /*INTEL_PT_INSN_BUF_SZ*/);
	if (len <= 0)
		goto out_put;

	/* Load maps to ensure dso->is_64_bit has been updated */
	map__load(al.map);

//	x86_64 = al.map->dso->is_64_bit;

//	if (arm_speget_insn(buf, len, true, &speq->arm_insn))
//		goto out_put;
	memcpy(&speq->arm_insn, buf, len);

	err = 0;
out_put:
	thread__put(thread);
	return err;
}
#endif

#if 0
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
		pr_err("ARM_SPE: failed to deliver error event, error %d\n",
		       err);

	return err;
}
#endif

/*
 * extract data needed from the packets in a record.
 * returns ARM_SPE_NEED_MORE_BYTES if more packets are expected
 * returns 0 if no more packets are needed and/or the end of the record has
 * been detected (END or TIMESTAMP packet).
 * returns ARM_SPE_BAD_PACKET if the input is not recognized as a valid packet
 */
static int arm_spe_process_packet(struct arm_spe_queue *speq,
				   struct perf_sample *sample,
				   struct arm_spe_pkt *packet)
{
	int el, idx = packet->index;
	unsigned long long payload = packet->payload;
	int ret = ARM_SPE_NEED_MORE_BYTES;

	switch (packet->type) {
	case ARM_SPE_BAD:
		return ARM_SPE_BAD_PACKET;
	case ARM_SPE_PAD:
		return ret;
	case ARM_SPE_END:
		return 0;
	case ARM_SPE_EVENTS:
		if (payload & 0x2) { /* RETIRED */
		}
		if (payload & 0x40) { /* NOT-TAKEN */
		}
		if (payload & 0x80) { /* MISPRED */
		}

		return ret;
	case ARM_SPE_OP_TYPE:
		switch (idx) {
		case 2:	speq->sample_flags = PERF_IP_FLAG_BRANCH;
			if (payload & 0x1) {
				speq->sample_flags |= PERF_IP_FLAG_CONDITIONAL;
			}
			if (payload & 0x2) {
				speq->sample_flags |= PERF_IP_FLAG_CONDITIONAL;
				// no PERF_IP_FLAG_INDIRECT.
			}
			break;
		default:
			break;
		}
		return ret;
	case ARM_SPE_DATA_SOURCE:
		return ret;
	case ARM_SPE_TIMESTAMP:
		sample->time = payload;
		return 0;  /* doubles as END packet */
	case ARM_SPE_ADDRESS:
		switch (idx) {
		case 0: /* fall through */
		case 1: //ns = !!(packet->payload & NS_FLAG);
			el = (packet->payload & EL_FLAG) >> 61;
			switch (el) {
			case 0: sample->cpumode = PERF_RECORD_MISC_USER; break;
			case 1: sample->cpumode = PERF_RECORD_MISC_KERNEL; break;
			/* following case 2 can also be KERNEL if VHE is set */
			//HYPERVISOR with non-VHE check?  or should this all 
			//be done with kernel addresses?; break;
			case 2: sample->cpumode = PERF_RECORD_MISC_KERNEL; break;
			/* case 3 is SECURE mode, but that doesn't occur in linux, right? */
			case 3: sample->cpumode = PERF_RECORD_MISC_HYPERVISOR; break;
			default: sample->cpumode = PERF_RECORD_MISC_CPUMODE_UNKNOWN;
			}
			payload &= ~(0xffULL << 56);
			if (idx == 1)
				sample->addr = payload; /* "to" */
			else
				sample->ip = payload; /* "from" */

			return ret;
//		case 2:	return ret; //snprintf(buf, buf_len, "VA 0x%llx", payload);
//		case 3:	//ns = !!(packet->payload & NS_FLAG);
			//payload &= ~(0xffULL << 56);
//			return ret; //snprintf(buf, buf_len, "PA 0x%llx ns=%d",
				  //	payload, ns);
		default: return ret;
		}

	case ARM_SPE_CONTEXT:
		/* fall through */
	case ARM_SPE_COUNTER:
		switch (idx) { /* LATency type */
		case 0:	sample->period = (unsigned short)payload; break; /* TOT */
		case 1:	break; /* ISSUE */
		case 2:	break; /* XLAT */
		default: pr_debug("bad SPE_COUNTER type %d\n", idx); break;
			 // signal error? : ret = 0;
		}
		return ret;
	default: 
		return ARM_SPE_BAD_PACKET; /* not a recognized packet type */
	}

	return 0;
}

static int arm_spe_process_buffer(struct arm_spe_queue *speq,
				  struct auxtrace_buffer *buffer,
				  struct thread *thread __maybe_unused)
{
        struct arm_spe *spe = speq->spe;
	size_t sz;
	union perf_event event;
	struct perf_sample sample = { .ip = 0, .insn_len = 4 };
	struct arm_spe_pkt packet;
	u32 filter = spe->branches_filter;
	int ret = 0, pkt_len;
	void *buf;

	memset(&sample, 0, sizeof(sample));

	if (buffer->use_data) {
		sz = buffer->use_size;
		buf = buffer->use_data;
	} else {
		sz = buffer->size;
		buf = buffer->data;
	}

#if 0  /* pt does instructions.  this had branches only */
	if (!speq->spe->sample_branches) {
		pr_debug4("%s: !speq->spe->sample_branches\n", __func__);
		return 0;
	}
#endif

	while (sz > sizeof(packet)) { //ARM_SPE_RECORD_BYTES_MAX) {
		ret = arm_spe_get_packet(buf, sz, &packet);
		if (ret > 0)
			pkt_len = ret;
		else
			pkt_len = 1;
		buf += pkt_len;
		sz -= pkt_len;

		ret = arm_spe_process_packet(speq, &sample, &packet);
		/* only proceed with synthesis until we've
		 * processed all packets in a record
		 */
		if (ret == ARM_SPE_NEED_MORE_BYTES)
			continue;

		if (ret == ARM_SPE_BAD_PACKET || ret != 0) {
			pr_debug("%s: error %d processing SPE packet data.  Continuing anyway\n",
				 __func__, ret);
			memset(&sample, 0, sizeof(sample));
			continue;
		}

#if 0
		if (!(speq->sample_flags | PERF_IP_FLAG_BRANCH)) {
			continue; /* only branches supported for now */
		}
#endif

		event.sample.header.type = PERF_RECORD_SAMPLE;
		event.sample.header.size = sizeof(struct perf_event_header);
		event.sample.header.misc = sample.cpumode ? : PERF_RECORD_MISC_USER;
		sample.pid = speq->pid;
		sample.tid = speq->tid;
		sample.id = speq->spe->branches_id;
		sample.stream_id = speq->spe->branches_id;
		sample.period = 1;
		sample.cpu = speq->cpu;
		sample.flags = speq->sample_flags;
		sample.insn_len = 4;
		memcpy(sample.insn, &speq->arm_insn, 4 /*INTEL_PT_INSN_BUF_SZ*/);

#if 0  /* SPE samples without stack memory/history */
		if (speq->spe->synth_opts.thread_stack)
			thread_stack__event(thread, speq->sample_flags,
					    sample.ip,
					    sample.addr,
					    4, buffer->buffer_nr + 1);
#endif
		if (filter && !(filter & speq->sample_flags))
			continue;

		if (spe->synth_opts.inject) {
			event.sample.header.size = spe->branches_event_size;
			ret = perf_event__synthesize_sample(&event,
							    spe->branches_sample_type,
							    0, &sample);
			if (ret) {
				fprintf(stderr, "%s %d: error synthesizing sample\n",
					__func__, __LINE__);
				return ret;
			}
		}

		ret = perf_session__deliver_synth_event(spe->session, &event, &sample);
		if (ret) {
			pr_err("ARM SPE: failed to deliver event, error %d\n",
			       ret);
			fprintf(stderr, "%s %d: error delivering synthesized event\n",
				__func__, __LINE__);
			continue;
		}
		memset(&sample, 0, sizeof(sample));
		memset(&event, 0, sizeof(event));
	}

#if 0 /* not sure if we can do this:  @thread_stack: feed branches to the thread_stack */
		err = arm_spe_synth_sample(speq, buf);
		if (err)
			break;
#endif

	ret = 0;
	pr_debug4("%s: returning %d\n",__func__, ret);
	return ret;
}

static int arm_spe_process_queue(struct arm_spe_queue *speq, u64 *timestamp)
{
	struct auxtrace_buffer *buffer = speq->buffer, *old_buffer = buffer;
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
		if (!speq->spe->sampling_mode)
			speq->done = 1;
		err = 1;
		goto out_put;
	}

	/* Currently there is no support for split buffers */
	if (buffer->consecutive) {
		err = -EINVAL;
		goto out_put;
	}

	if (!buffer->data) {
		int fd = perf_data__fd(speq->spe->session->data);

		buffer->data = auxtrace_buffer__get_data(buffer, fd);
		if (!buffer->data) {
			err = -ENOMEM;
			goto out_put;
		}
	}

	if (speq->spe->snapshot_mode && !buffer->consecutive &&
	    arm_spe_do_fix_overlap(queue, buffer)) {
		err = -ENOMEM;
		goto out_put;
	}

	if (!speq->spe->synth_opts.callchain &&
	    !speq->spe->synth_opts.thread_stack && thread &&
	    (!old_buffer || speq->spe->sampling_mode ||
	     (speq->spe->snapshot_mode && !buffer->consecutive)))
		thread_stack__set_trace_nr(thread, buffer->buffer_nr + 1);

	err = arm_spe_process_buffer(speq, buffer, thread);
	pr_debug4("%s: arm_spe_process_buffer returned %d\n",__func__, err);

	auxtrace_buffer__drop_data(buffer);

	speq->buffer = auxtrace_buffer__next(queue, buffer);
	if (speq->buffer) {
		if (timestamp)
			*timestamp = speq->buffer->reference;
	} else {
		if (!speq->spe->sampling_mode)
			speq->done = 1;
	}
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

static int arm_spe_process_queues(struct arm_spe *spe, u64 timestamp __maybe_unused)
{
	while (1) {
		unsigned int queue_nr;
		struct auxtrace_queue *queue;
		struct arm_spe_queue *speq;
		u64 ts = 0;
		int ret;

		if (!spe->heap.heap_cnt)
			return 0;

#if 1  /* ordinal 168301447, timestamp 0 */
		if (spe->heap.heap_array[0].ordinal > timestamp)
			return 0;
#endif

		queue_nr = spe->heap.heap_array[0].queue_nr;
		queue = &spe->queues.queue_array[queue_nr];
		speq = queue->priv;

		auxtrace_heap__pop(&spe->heap);

		ret = arm_spe_process_queue(speq, &ts);
		pr_debug4("%s: arm_spe_process_queue returned %d\n",__func__, ret);
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

#if 0
u64 perf_time_to_tsc(void)
{
	fprintf(stderr, "%s %d: IMPLEMENTME!\n", __func__, __LINE__);

	return 0;
}
#endif

/* process_event: lets the decoder see all session events */
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

	if (sample->time && sample->time != (u64)-1)
		timestamp = sample->time; //perf_time_to_tsc(/*sample->time, &spe->tc*/);
	else
		timestamp = 0;

	err = arm_spe_update_queues(spe);
	if (err) {
		pr_debug("%s: propagating arm_spe_update_queues error %d\n",
			 __func__, err);
		return err;
	}

	err = arm_spe_process_queues(spe, timestamp);
	if (err) {
		pr_debug("%s: propagating arm_spe_process_queues error %d\n",
			 __func__, err);
		return err;
	}
	if (event->header.type == PERF_RECORD_EXIT) {
		err = arm_spe_process_tid_exit(spe, event->fork.tid);
		if (err) {
			pr_debug("%s: propagating arm_spe_process_tid_exit error %d\n",
				 __func__, err);
			return err;
		}
	}

	if (event->header.type == PERF_RECORD_AUX &&
	    (event->aux.flags & PERF_AUX_FLAG_TRUNCATED) &&
	    spe->synth_opts.errors)
		err = arm_spe_lost(spe, sample);

	return err;
}

/* @process_auxtrace_event: process a PERF_RECORD_AUXTRACE event */
static int arm_spe_process_auxtrace_event(struct perf_session *session,
					  union perf_event *event,
					  struct perf_tool *tool __maybe_unused)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					     auxtrace);
	struct auxtrace_buffer *buffer;
	off_t data_offset;
	int fd = perf_data__fd(session->data);
	int err;

	if (perf_data__is_pipe(session->data)) {
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

	return 0;
}

static int arm_spe_flush(struct perf_session *session __maybe_unused,
			 struct perf_tool *tool __maybe_unused)
{
	return 0;
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
	/* check if there are timestamps in the SPE data, then sample_type |= PERF_SAMPLE_TIME? */
	attr.sample_type &= ~(u64)PERF_SAMPLE_TIME;
	/* check if there are CPU IDs in the SPE data? */
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
