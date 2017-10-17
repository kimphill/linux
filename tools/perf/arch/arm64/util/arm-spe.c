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

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>
#include <time.h>

#include "../../util/cpumap.h"
#include "../../util/evsel.h"
#include "../../util/evlist.h"
#include "../../util/session.h"
#include "../../util/util.h"
#include "../../util/pmu.h"
#include "../../util/debug.h"
#include "../../util/tsc.h"
#include "../../util/auxtrace.h"
#include "../../util/arm-spe.h"

#define KiB(x) ((x) * 1024)
#define MiB(x) ((x) * 1024 * 1024)

struct arm_spe_recording {
	struct auxtrace_record		itr;
	struct perf_pmu			*arm_spe_pmu; // more than 1
	struct perf_evlist		*evlist;
//	struct perf_pmu_attr			*arm_spe_pmu; // more than 1
//	int				min_interval;
//	int				count_size;
};

static size_t
arm_spe_info_priv_size(struct auxtrace_record *itr __maybe_unused,
		       struct perf_evlist *evlist __maybe_unused)
{
	return ARM_SPE_AUXTRACE_PRIV_SIZE;
}

static int arm_spe_info_fill(struct auxtrace_record *itr,
			     struct perf_session *session,
			     struct auxtrace_info_event *auxtrace_info,
			     size_t priv_size)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_pmu *arm_spe_pmu = sper->arm_spe_pmu;

	pr_err("%s %d: priv_size %lu should == ARM_SPE_AUXTRACE_PRIV_SIZE %lu\n",
		__func__, __LINE__, priv_size, ARM_SPE_AUXTRACE_PRIV_SIZE);

	if (priv_size != ARM_SPE_AUXTRACE_PRIV_SIZE)
		return -EINVAL;

	pr_err("%s %d: session->evlist->nr_mmaps %d (if 0 returning EINVAL)\n",
		__func__, __LINE__, session->evlist->nr_mmaps);

	if (!session->evlist->nr_mmaps)
		return -EINVAL;

	auxtrace_info->type = PERF_AUXTRACE_ARM_SPE;
	pr_err("%s %d: auxtrace_info->type = PERF_AUXTRACE_ARM_SPE (%d)\n",
		__func__, __LINE__, auxtrace_info->type);
	pr_err("auxtrace_info->priv[ARM_SPE_PMU_TYPE] = arm_spe_pmu->type (%d)\n", 
		arm_spe_pmu->type);
	auxtrace_info->priv[ARM_SPE_PMU_TYPE] = arm_spe_pmu->type;

	return 0;
}

static int arm_spe_recording_options(struct auxtrace_record *itr,
				     struct perf_evlist *evlist,
				     struct record_opts *opts)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_pmu *arm_spe_pmu = sper->arm_spe_pmu;
	struct perf_evsel *evsel, *arm_spe_evsel = NULL;
	const struct cpu_map *cpus = evlist->cpus;
	bool privileged = geteuid() == 0 || perf_event_paranoid() < 0;
	struct perf_evsel *tracking_evsel;
	int err;

	sper->evlist = evlist;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.type == arm_spe_pmu->type) {
			if (arm_spe_evsel) {
				pr_err("There may be only one " ARM_SPE_PMU_NAME " event\n");
				return -EINVAL;
			}
			evsel->attr.freq = 0;
			pr_err("%s %d: opts->default_interval %lu\n", __func__, __LINE__,
				opts->default_interval); 
			evsel->attr.sample_period = 1;
			arm_spe_evsel = evsel;
			opts->full_auxtrace = true;
		}
	}

	if (!opts->full_auxtrace)
		return 0;

//	opts->default_interval = 
			pr_err("%s %d: opts->default_interval %lu\n", __func__, __LINE__,
				opts->default_interval); 

	/* We are in full trace mode but '-m,xyz' wasn't specified */
	if (opts->full_auxtrace && !opts->auxtrace_mmap_pages) {
		if (privileged) {
			opts->auxtrace_mmap_pages = MiB(4) / page_size;
		} else {
			opts->auxtrace_mmap_pages = KiB(128) / page_size;
			if (opts->mmap_pages == UINT_MAX)
				opts->mmap_pages = KiB(256) / page_size;
		}
	}

	/* Validate auxtrace_mmap_pages */
	if (opts->auxtrace_mmap_pages) {
		size_t sz = opts->auxtrace_mmap_pages * (size_t)page_size;
		size_t min_sz = KiB(8);

		if (sz < min_sz || !is_power_of_2(sz)) {
			pr_err("Invalid mmap size for ARM SPE: must be at least %zuKiB and a power of 2\n",
			       min_sz / 1024);
			return -EINVAL;
		}
	}

	/*
	 * To obtain the auxtrace buffer file descriptor, the auxtrace event
	 * must come first.
	 */
	perf_evlist__to_front(evlist, arm_spe_evsel);

	/*
	 * In the case of per-cpu mmaps, we need the CPU on the
	 * AUX event.
	 */
	if (!cpu_map__empty(cpus))
		perf_evsel__set_sample_bit(arm_spe_evsel, CPU);

	/* Add dummy event to keep tracking */
	err = parse_events(evlist, "dummy:u", NULL);
	if (err)
		return err;

	tracking_evsel = perf_evlist__last(evlist);
	perf_evlist__set_tracking_event(evlist, tracking_evsel);

	tracking_evsel->attr.freq = 0;
	tracking_evsel->attr.sample_period = 1;
	perf_evsel__reset_sample_bit(tracking_evsel, BRANCH_STACK);

	/* In per-cpu case, always need the time of mmap events etc */
	if (!cpu_map__empty(cpus))
		perf_evsel__set_sample_bit(tracking_evsel, TIME);

	return 0;
}

static u64 arm_spe_reference(struct auxtrace_record *itr __maybe_unused)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

	return ts.tv_sec ^ ts.tv_nsec;
}

static void arm_spe_recording_free(struct auxtrace_record *itr)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);

       free(sper);
}

static int arm_spe_read_finish(struct auxtrace_record *itr, int idx)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_evsel *evsel;

	evlist__for_each_entry(sper->evlist, evsel) {
		if (evsel->attr.type == sper->arm_spe_pmu->type)
			return perf_evlist__enable_event_idx(sper->evlist,
							     evsel, idx);
	}
	return -EINVAL;
}

struct auxtrace_record *arm_spe_recording_init(int *err, 
					       struct perf_pmu *arm_spe_pmu)
{
//	struct perf_pmu *arm_spe_pmu = perf_pmu__find(ARM_SPE_PMU_NAME);
	struct arm_spe_recording *sper;

	pr_err("%s %d: \n", __func__, __LINE__);

	if (!arm_spe_pmu) {
		*err = -ENODEV;
		pr_err("%s %d: -ENODEV\n", __func__, __LINE__);

		return NULL;
	}

	pr_err("%s %d: \n", __func__, __LINE__);

	sper = zalloc(sizeof(struct arm_spe_recording));
	if (!sper) {
		*err = -ENOMEM;
		pr_err("%s %d: -ENOMEM\n", __func__, __LINE__);
		return NULL;
	}

	sper->arm_spe_pmu = arm_spe_pmu;
	sper->itr.recording_options = arm_spe_recording_options;
	sper->itr.info_priv_size = arm_spe_info_priv_size;
	sper->itr.info_fill = arm_spe_info_fill;
	sper->itr.free = arm_spe_recording_free;
	sper->itr.reference = arm_spe_reference;
	sper->itr.read_finish = arm_spe_read_finish;
	sper->itr.alignment = 0;

	pr_err("%s %d: returning &sper->itr %p\n", __func__, __LINE__ , &sper->itr);

	return &sper->itr;
}

static int arm_spe_parse_terms_with_default(struct list_head *formats,
					     const char *str,
					     u64 *config)
{
	struct list_head *terms;
	struct perf_event_attr attr = { .size = 0, };
	int err;

	terms = malloc(sizeof(struct list_head));
	if (!terms)
		return -ENOMEM;

	INIT_LIST_HEAD(terms);

	err = parse_events_terms(terms, str);
	if (err)
		goto out_free;

	attr.config = *config;
	err = perf_pmu__config_terms(formats, &attr, terms, true, NULL);
	if (err)
		goto out_free;

	*config = attr.config;
out_free:
	parse_events_terms__delete(terms);
	return err;
}

static int arm_spe_parse_terms(struct list_head *formats, const char *str,
				u64 *config)
{
	*config = 0;
	return arm_spe_parse_terms_with_default(formats, str, config);
}

static u64 arm_spe_default_config(struct perf_pmu *arm_spe_pmu)
{
	char buf[256];
	u64 config;

	scnprintf(buf, sizeof(buf), "");

	pr_warning/*debug2*/("%s default config: %s\n", arm_spe_pmu->name, buf);

	arm_spe_parse_terms(&arm_spe_pmu->format, buf, &config);

	return config;
}

struct perf_event_attr
*arm_spe_pmu_default_config(struct perf_pmu *arm_spe_pmu)
{
	struct perf_event_attr *attr;
	int sample_period, count_size;

	pr_warning("%s %d: entered\n", __func__, __LINE__);

	attr = zalloc(sizeof(struct perf_event_attr));
	if (!attr)
		return NULL;

	/* check count_size */
	if (perf_pmu__scan_file(arm_spe_pmu, "caps/count_size", "%d",
				&count_size) != 1) {
		/* driver doesn't advertise a count_size
		 * use ...12? */
		pr_warning("arm_spe driver doesn't advertise a count_size. Oh well!\n");
		//count_size = 12;
	} else
		// put somewhere to check against later user specification
		pr_warning("got %d count_size from arm_spe driver\n", count_size);

	if (perf_pmu__scan_file(arm_spe_pmu, "caps/min_interval", "%d",
				  &sample_period) != 1) {
		/* driver doesn't advertise a minimum,
		 * use max allowable by PMSIDR_EL1.INTERVAL */
		pr_warning("arm_spe driver doesn't advertise a min. interval. Using 4096\n");
		attr->sample_period = 4096;
	} else {
		pr_warning("got %d sample_period from arm_spe driver\n", sample_period);
		attr->sample_period = sample_period; 
	}

	//if (ret <= 1 || ret > 10 * count_size /* check if its 10 based, not 2 */) {
	attr->config = arm_spe_default_config(arm_spe_pmu);

//assign a type? to match evsel->attr.type in auxtrace_record__init?
	arm_spe_pmu->selectable = true;
	arm_spe_pmu->is_uncore = false;
	//arm_spe_pmu->type = PERF_TYPE_HARDWARE;
	//arm_spe_pmu->type = PERF_AUXTRACE_ARM_SPE;
//not ARM_SPE_PMU_TYPE...that' sfor the type of the auxtrace data in the perf.data file

	return attr;
}
