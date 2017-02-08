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

#ifndef INCLUDE__PERF_ARM_SPE_H__
#define INCLUDE__PERF_ARM_SPE_H__

#define ARM_SPE_PMU_NAME "arm_spe_0"

enum {
	ARM_SPE_PMU_TYPE,
	ARM_SPE_PER_CPU_MMAPS,
	ARM_SPE_AUXTRACE_PRIV_MAX,
};

#define ARM_SPE_AUXTRACE_PRIV_SIZE (ARM_SPE_AUXTRACE_PRIV_MAX * sizeof(u64))

struct auxtrace_record;
struct perf_tool;
union perf_event;
struct perf_session;

struct auxtrace_record *arm_spe_recording_init(int *err);

int arm_spe_process_auxtrace_info(union perf_event *event,
				  struct perf_session *session);

#endif
