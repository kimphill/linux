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
#include "debug.h"
#include "auxtrace.h"
#include "arm-spe.h"
#include "arm-spe-pkt-decoder.h"

struct arm_spe {
	struct auxtrace			auxtrace;
	struct auxtrace_queues		queues;
	struct auxtrace_heap		heap;
	u32				auxtrace_type;
	struct perf_session		*session;
	struct machine			*machine;
	u32				pmu_type;
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

static int arm_spe_process_event(struct perf_session *session __maybe_unused,
				   union perf_event *event __maybe_unused,
				   struct perf_sample *sample __maybe_unused,
				   struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int arm_spe_process_auxtrace_event(struct perf_session *session,
					    union perf_event *event,
					    struct perf_tool *tool __maybe_unused)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					     auxtrace);
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

	return 0;

err_free:
	free(spe);
	return err;
}
