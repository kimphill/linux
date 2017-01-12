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

#include <stdbool.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>

#include "../../perf.h"
#include "../../util/session.h"
#include "../../util/event.h"
#include "../../util/evlist.h"
#include "../../util/evsel.h"
#include "../../util/cpumap.h"
#include <subcmd/parse-options.h>
#include "../../util/parse-events.h"
#include "../../util/pmu.h"
#include "../../util/debug.h"
#include "../../util/auxtrace.h"
#include "../../util/tsc.h"
#include "../../util/arm-spe.h"

#define KiB(x) ((x) * 1024)
#define MiB(x) ((x) * 1024 * 1024)
#define KiB_MASK(x) (KiB(x) - 1)
#define MiB_MASK(x) (MiB(x) - 1)

#define ARM_SPE_DEFAULT_SAMPLE_SIZE	KiB(4)

#define ARM_SPE_MAX_SAMPLE_SIZE	KiB(60)

#define ARM_SPE_PSB_PERIOD_NEAR	256

struct arm_spe_snapshot_ref {
	void *ref_buf;
	size_t ref_offset;
	bool wrapped;
};

struct arm_spe_recording {
	struct auxtrace_record		itr;
	struct perf_pmu			*arm_spe_pmu;
	int				have_sched_switch;
	struct perf_evlist		*evlist;
	bool				snapshot_mode;
	bool				snapshot_init_done;
	size_t				snapshot_size;
	size_t				snapshot_ref_buf_size;
	int				snapshot_ref_cnt;
	struct arm_spe_snapshot_ref	*snapshot_refs;
};

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

static u64 arm_spe_masked_bits(u64 mask, u64 bits)
{
	const u64 top_bit = 1ULL << 63;
	u64 res = 0;
	int i;

	for (i = 0; i < 64; i++) {
		if (mask & top_bit) {
			res <<= 1;
			if (bits & top_bit)
				res |= 1;
		}
		mask <<= 1;
		bits <<= 1;
	}

	return res;
}

static int arm_spe_read_config(struct perf_pmu *arm_spe_pmu, const char *str,
				struct perf_evlist *evlist, u64 *res)
{
	struct perf_evsel *evsel;
	u64 mask;

	*res = 0;

	mask = perf_pmu__format_bits(&arm_spe_pmu->format, str);
	if (!mask)
		return -EINVAL;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.type == arm_spe_pmu->type) {
			*res = arm_spe_masked_bits(mask, evsel->attr.config);
			return 0;
		}
	}

	return -EINVAL;
}

static size_t arm_spe_psb_period(struct perf_pmu *arm_spe_pmu,
				  struct perf_evlist *evlist)
{
	u64 val;
	int err, topa_multiple_entries;
	size_t psb_period;

	if (perf_pmu__scan_file(arm_spe_pmu, "caps/topa_multiple_entries",
				"%d", &topa_multiple_entries) != 1)
		topa_multiple_entries = 0;

	/*
	 * Use caps/topa_multiple_entries to indicate early hardware that had
	 * extra frequent PSBs.
	 */
	if (!topa_multiple_entries) {
		psb_period = 256;
		goto out;
	}

	err = arm_spe_read_config(arm_spe_pmu, "psb_period", evlist, &val);
	if (err)
		val = 0;

	psb_period = 1 << (val + 11);
out:
	pr_debug2("%s psb_period %zu\n", arm_spe_pmu->name, psb_period);
	return psb_period;
}

static u64 arm_spe_default_config(struct perf_pmu *arm_spe_pmu)
{
	char buf[256];
	u64 config;

	arm_spe_parse_terms(&arm_spe_pmu->format, buf, &config);

	return config;
}

static int arm_spe_parse_snapshot_options(struct auxtrace_record *itr,
					   struct record_opts *opts,
					   const char *str)
{
	struct arm_spe_recording *ptr =
			container_of(itr, struct arm_spe_recording, itr);
	unsigned long long snapshot_size = 0;
	char *endptr;

	if (str) {
		snapshot_size = strtoull(str, &endptr, 0);
		if (*endptr || snapshot_size > SIZE_MAX)
			return -1;
	}

	opts->auxtrace_snapshot_mode = true;
	opts->auxtrace_snapshot_size = snapshot_size;

	ptr->snapshot_size = snapshot_size;

	return 0;
}

struct perf_event_attr *
arm_spe_pmu_default_config(struct perf_pmu *arm_spe_pmu)
{
	struct perf_event_attr *attr;

	attr = zalloc(sizeof(struct perf_event_attr));
	if (!attr)
		return NULL;

	attr->config = arm_spe_default_config(arm_spe_pmu);

	arm_spe_pmu->selectable = true;

	return attr;
}

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
	struct arm_spe_recording *ptr =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_pmu *arm_spe_pmu = ptr->arm_spe_pmu;
	bool per_cpu_mmaps;
	u64 ts_enable, pa_enable, jitter, load_filter, store_filter, branch_filter, min_latency;

	if (priv_size != ARM_SPE_AUXTRACE_PRIV_SIZE)
		return -EINVAL;

	arm_spe_parse_terms(&arm_spe_pmu->format, "ts_enable", &ts_enable);
	arm_spe_parse_terms(&arm_spe_pmu->format, "pa_enable", &pa_enable);
	arm_spe_parse_terms(&arm_spe_pmu->format, "jitter", &jitter);
	arm_spe_parse_terms(&arm_spe_pmu->format, "load_filter", &load_filter);
	arm_spe_parse_terms(&arm_spe_pmu->format, "store_filter", &store_filter);
	arm_spe_parse_terms(&arm_spe_pmu->format, "branch_filter", &branch_filter);
	arm_spe_parse_terms(&arm_spe_pmu->format, "min_latency", &min_latency);

	if (!session->evlist->nr_mmaps)
		return -EINVAL;

	per_cpu_mmaps = !cpu_map__empty(session->evlist->cpus);

	auxtrace_info->type = PERF_AUXTRACE_ARM_SPE;
	auxtrace_info->priv[ARM_SPE_PMU_TYPE] = arm_spe_pmu->type;
	auxtrace_info->priv[ARM_SPE_TS_ENABLE] = !!ts_enable;
	auxtrace_info->priv[ARM_SPE_PA_ENABLE] = !!pa_enable;
	auxtrace_info->priv[ARM_SPE_JITTER] = !!jitter;
	auxtrace_info->priv[ARM_SPE_LOAD_FILTER] = !!load_filter;
	auxtrace_info->priv[ARM_SPE_STORE_FILTER] = !!store_filter;
	auxtrace_info->priv[ARM_SPE_BRANCH_FILTER] = !!branch_filter;
	auxtrace_info->priv[ARM_SPE_MIN_LATENCY] = min_latency;
	auxtrace_info->priv[ARM_SPE_HAVE_SCHED_SWITCH] = ptr->have_sched_switch;
	auxtrace_info->priv[ARM_SPE_SNAPSHOT_MODE] = ptr->snapshot_mode;
	auxtrace_info->priv[ARM_SPE_PER_CPU_MMAPS] = per_cpu_mmaps;

	return 0;
}

static void arm_spe_valid_str(char *str, size_t len, u64 valid)
{
	unsigned int val, last = 0, state = 1;
	int p = 0;

	str[0] = '\0';

	for (val = 0; val <= 64; val++, valid >>= 1) {
		if (valid & 1) {
			last = val;
			switch (state) {
			case 0:
				p += scnprintf(str + p, len - p, ",");
				/* Fall through */
			case 1:
				p += scnprintf(str + p, len - p, "%u", val);
				state = 2;
				break;
			case 2:
				state = 3;
				break;
			case 3:
				state = 4;
				break;
			default:
				break;
			}
		} else {
			switch (state) {
			case 3:
				p += scnprintf(str + p, len - p, ",%u", last);
				state = 0;
				break;
			case 4:
				p += scnprintf(str + p, len - p, "-%u", last);
				state = 0;
				break;
			default:
				break;
			}
			if (state != 1)
				state = 0;
		}
	}
}

static int arm_spe_val_config_term(struct perf_pmu *arm_spe_pmu,
				    const char *caps, const char *name,
				    const char *supported, u64 config)
{
	char valid_str[256];
	unsigned int shift;
	unsigned long long valid;
	u64 bits;
	int ok;

	if (perf_pmu__scan_file(arm_spe_pmu, caps, "%llx", &valid) != 1)
		valid = 0;

	if (supported &&
	    perf_pmu__scan_file(arm_spe_pmu, supported, "%d", &ok) == 1 && !ok)
		valid = 0;

	valid |= 1;

	bits = perf_pmu__format_bits(&arm_spe_pmu->format, name);

	config &= bits;

	for (shift = 0; bits && !(bits & 1); shift++)
		bits >>= 1;

	config >>= shift;

	if (config > 63)
		goto out_err;

	if (valid & (1 << config))
		return 0;
out_err:
	arm_spe_valid_str(valid_str, sizeof(valid_str), valid);
	return -EINVAL;
}

static int arm_spe_validate_config(struct perf_pmu *arm_spe_pmu,
				    struct perf_evsel *evsel)
{
	int err;

	if (!evsel)
		return 0;

	err = arm_spe_val_config_term(arm_spe_pmu, "caps/cycle_thresholds",
				       "cyc_thresh", "caps/psb_cyc",
				       evsel->attr.config);
	if (err)
		return err;

	err = arm_spe_val_config_term(arm_spe_pmu, "caps/mtc_periods",
				       "mtc_period", "caps/mtc",
				       evsel->attr.config);
	if (err)
		return err;

	return arm_spe_val_config_term(arm_spe_pmu, "caps/psb_periods",
					"psb_period", "caps/psb_cyc",
					evsel->attr.config);
}

static int arm_spe_recording_options(struct auxtrace_record *itr,
				      struct perf_evlist *evlist,
				      struct record_opts *opts)
{
	struct arm_spe_recording *ptr =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_pmu *arm_spe_pmu = ptr->arm_spe_pmu;
	bool have_timing_info;
	struct perf_evsel *evsel, *arm_spe_evsel = NULL;
	const struct cpu_map *cpus = evlist->cpus;
	bool privileged = geteuid() == 0 || perf_event_paranoid() < 0;
	int err;

	ptr->evlist = evlist;
	ptr->snapshot_mode = opts->auxtrace_snapshot_mode;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.type == arm_spe_pmu->type) {
			if (arm_spe_evsel) {
				pr_err("There may be only one "
					ARM_SPE_PMU_NAME " event\n");
				return -EINVAL;
			}
			evsel->attr.freq = 0;
			evsel->attr.sample_period = 1;
			arm_spe_evsel = evsel;
			opts->full_auxtrace = true;
		}
	}

	if (opts->auxtrace_snapshot_mode && !opts->full_auxtrace) {
		pr_err("Snapshot mode (-S option) requires " ARM_SPE_PMU_NAME
		       " PMU event (-e " ARM_SPE_PMU_NAME ")\n");
		return -EINVAL;
	}

	if (opts->use_clockid) {
		pr_err("Cannot use clockid (-k option) with " ARM_SPE_PMU_NAME "\n");
		return -EINVAL;
	}

	/* more cs-etm than intel-pt here */
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

	/* Add dummy event to keep tracking */
	if (opts->full_auxtrace) {
		struct perf_evsel *tracking_evsel;

		err = parse_events(evlist, "dummy:u", NULL);
		if (err)
			return err;

		tracking_evsel = perf_evlist__last(evlist);
		perf_evlist__set_tracking_event(evlist, tracking_evsel);

		tracking_evsel->attr.freq = 0;
		tracking_evsel->attr.sample_period = 1024;

		/* In per-cpu case, always need the time of mmap events etc */
		if (!cpu_map__empty(cpus))
			perf_evsel__set_sample_bit(tracking_evsel, TIME);
	}

	err = arm_spe_validate_config(arm_spe_pmu, arm_spe_evsel);
	if (err)
		return err;

	/* Set default sizes for snapshot mode */
	if (opts->auxtrace_snapshot_mode) {
		size_t psb_period = arm_spe_psb_period(arm_spe_pmu, evlist);

		if (!opts->auxtrace_snapshot_size && !opts->auxtrace_mmap_pages) {
			if (privileged) {
				opts->auxtrace_mmap_pages = MiB(4) / page_size;
			} else {
				opts->auxtrace_mmap_pages = KiB(128) / page_size;
				if (opts->mmap_pages == UINT_MAX)
					opts->mmap_pages = KiB(256) / page_size;
			}
		} else if (!opts->auxtrace_mmap_pages && !privileged &&
			   opts->mmap_pages == UINT_MAX) {
			opts->mmap_pages = KiB(256) / page_size;
		}
		if (!opts->auxtrace_snapshot_size)
			opts->auxtrace_snapshot_size =
				opts->auxtrace_mmap_pages * (size_t)page_size;
		if (!opts->auxtrace_mmap_pages) {
			size_t sz = opts->auxtrace_snapshot_size;

			sz = round_up(sz, page_size) / page_size;
			opts->auxtrace_mmap_pages = roundup_pow_of_two(sz);
		}
		if (opts->auxtrace_snapshot_size >
				opts->auxtrace_mmap_pages * (size_t)page_size) {
			pr_err("Snapshot size %zu must not be greater than AUX area tracing mmap size %zu\n",
			       opts->auxtrace_snapshot_size,
			       opts->auxtrace_mmap_pages * (size_t)page_size);
			return -EINVAL;
		}
		if (!opts->auxtrace_snapshot_size || !opts->auxtrace_mmap_pages) {
			pr_err("Failed to calculate default snapshot size and/or AUX area tracing mmap pages\n");
			return -EINVAL;
		}
		pr_debug2("ARM SPE snapshot size: %zu\n",
			  opts->auxtrace_snapshot_size);
		if (psb_period &&
		    opts->auxtrace_snapshot_size <= psb_period +
						  ARM_SPE_PSB_PERIOD_NEAR)
			ui__warning("ARM SPE snapshot size (%zu) may be too small for PSB period (%zu)\n",
				    opts->auxtrace_snapshot_size, psb_period);
	}

	/* Set default sizes for full trace mode */
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
		size_t min_sz;

		if (opts->auxtrace_snapshot_mode)
			min_sz = KiB(4);
		else
			min_sz = KiB(8);

		if (sz < min_sz || !is_power_of_2(sz)) {
			pr_err("Invalid mmap size for ARM SPE: must be at least %zuKiB and a power of 2\n",
			       min_sz / 1024);
			return -EINVAL;
		}
	}

	have_timing_info = false;

	/*
	 * Per-cpu recording needs sched_switch events to distinguish different
	 * threads.
	 */
	if (have_timing_info && !cpu_map__empty(cpus)) {
		if (perf_can_record_switch_events()) {
			bool cpu_wide = !target__none(&opts->target) &&
					!target__has_task(&opts->target);

			if (!cpu_wide && perf_can_record_cpu_wide()) {
				struct perf_evsel *switch_evsel;

				err = parse_events(evlist, "dummy:u", NULL);
				if (err)
					return err;

				switch_evsel = perf_evlist__last(evlist);

				switch_evsel->attr.freq = 0;
				switch_evsel->attr.sample_period = 1;
				switch_evsel->attr.context_switch = 1;

				switch_evsel->system_wide = true;
				switch_evsel->no_aux_samples = true;
				switch_evsel->immediate = true;

				perf_evsel__set_sample_bit(switch_evsel, TID);
				perf_evsel__set_sample_bit(switch_evsel, TIME);
				perf_evsel__set_sample_bit(switch_evsel, CPU);

				opts->record_switch_events = false;
				ptr->have_sched_switch = 3;
			} else {
				opts->record_switch_events = true;
				if (cpu_wide)
					ptr->have_sched_switch = 3;
				else
					ptr->have_sched_switch = 2;
			}
		} else {
			err = -EPERM; // implement arm_spe_track_switches(evlist);
			if (err == -EPERM)
				pr_debug2("Unable to select sched:sched_switch\n");
			else if (err)
				return err;
			else
				ptr->have_sched_switch = 1;
		}
	}

	if (arm_spe_evsel) {
		/*
		 * To obtain the auxtrace buffer file descriptor, the auxtrace
		 * event must come first.
		 */
		perf_evlist__to_front(evlist, arm_spe_evsel);
		/*
		 * In the case of per-cpu mmaps, we need the CPU on the
		 * AUX event.
		 */
		if (!cpu_map__empty(cpus))
			perf_evsel__set_sample_bit(arm_spe_evsel, CPU);
	}

	/*
	 * Warn the user when we do not have enough information to decode i.e.
	 * per-cpu with no sched_switch (except workload-only).
	 */
	if (!ptr->have_sched_switch && !cpu_map__empty(cpus) &&
	    !target__none(&opts->target))
		ui__warning("ARM SPE decoding will not be possible except for kernel tracing!\n");

	return 0;
}

static int arm_spe_snapshot_start(struct auxtrace_record *itr)
{
	struct arm_spe_recording *ptr =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_evsel *evsel;

	evlist__for_each_entry(ptr->evlist, evsel) {
		if (evsel->attr.type == ptr->arm_spe_pmu->type)
			return perf_evsel__disable(evsel);
	}
	return -EINVAL;
}

static int arm_spe_snapshot_finish(struct auxtrace_record *itr)
{
	struct arm_spe_recording *ptr =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_evsel *evsel;

	evlist__for_each_entry(ptr->evlist, evsel) {
		if (evsel->attr.type == ptr->arm_spe_pmu->type)
			return perf_evsel__enable(evsel);
	}
	return -EINVAL;
}

static int arm_spe_alloc_snapshot_refs(struct arm_spe_recording *ptr, int idx)
{
	const size_t sz = sizeof(struct arm_spe_snapshot_ref);
	int cnt = ptr->snapshot_ref_cnt, new_cnt = cnt * 2;
	struct arm_spe_snapshot_ref *refs;

	if (!new_cnt)
		new_cnt = 16;

	while (new_cnt <= idx)
		new_cnt *= 2;

	refs = calloc(new_cnt, sz);
	if (!refs)
		return -ENOMEM;

	memcpy(refs, ptr->snapshot_refs, cnt * sz);

	ptr->snapshot_refs = refs;
	ptr->snapshot_ref_cnt = new_cnt;

	return 0;
}

static void arm_spe_free_snapshot_refs(struct arm_spe_recording *ptr)
{
	int i;

	for (i = 0; i < ptr->snapshot_ref_cnt; i++)
		zfree(&ptr->snapshot_refs[i].ref_buf);
	zfree(&ptr->snapshot_refs);
}

static void arm_spe_recording_free(struct auxtrace_record *itr)
{
	struct arm_spe_recording *ptr =
			container_of(itr, struct arm_spe_recording, itr);

	arm_spe_free_snapshot_refs(ptr);
	free(ptr);
}

static int arm_spe_alloc_snapshot_ref(struct arm_spe_recording *ptr, int idx,
				       size_t snapshot_buf_size)
{
	size_t ref_buf_size = ptr->snapshot_ref_buf_size;
	void *ref_buf;

	ref_buf = zalloc(ref_buf_size);
	if (!ref_buf)
		return -ENOMEM;

	ptr->snapshot_refs[idx].ref_buf = ref_buf;
	ptr->snapshot_refs[idx].ref_offset = snapshot_buf_size - ref_buf_size;

	return 0;
}

static size_t arm_spe_snapshot_ref_buf_size(struct arm_spe_recording *ptr,
					     size_t snapshot_buf_size)
{
	const size_t max_size = 256 * 1024;
	size_t buf_size = 0, psb_period;

	if (ptr->snapshot_size <= 64 * 1024)
		return 0;

	psb_period = arm_spe_psb_period(ptr->arm_spe_pmu, ptr->evlist);
	if (psb_period)
		buf_size = psb_period * 2;

	if (!buf_size || buf_size > max_size)
		buf_size = max_size;

	if (buf_size >= snapshot_buf_size)
		return 0;

	if (buf_size >= ptr->snapshot_size / 2)
		return 0;

	return buf_size;
}

static int arm_spe_snapshot_init(struct arm_spe_recording *ptr,
				  size_t snapshot_buf_size)
{
	if (ptr->snapshot_init_done)
		return 0;

	ptr->snapshot_init_done = true;

	ptr->snapshot_ref_buf_size = arm_spe_snapshot_ref_buf_size(ptr,
							snapshot_buf_size);

	return 0;
}

/**
 * arm_spe_compare_buffers - compare bytes in a buffer to a circular buffer.
 * @buf1: first buffer
 * @compare_size: number of bytes to compare
 * @buf2: second buffer (a circular buffer)
 * @offs2: offset in second buffer
 * @buf2_size: size of second buffer
 *
 * The comparison allows for the possibility that the bytes to compare in the
 * circular buffer are not contiguous.  It is assumed that @compare_size <=
 * @buf2_size.  This function returns %false if the bytes are identical, %true
 * otherwise.
 */
static bool arm_spe_compare_buffers(void *buf1, size_t compare_size,
				     void *buf2, size_t offs2, size_t buf2_size)
{
	size_t end2 = offs2 + compare_size, part_size;

	if (end2 <= buf2_size)
		return memcmp(buf1, buf2 + offs2, compare_size);

	part_size = end2 - buf2_size;
	if (memcmp(buf1, buf2 + offs2, part_size))
		return true;

	compare_size -= part_size;

	return memcmp(buf1 + part_size, buf2, compare_size);
}

static bool arm_spe_compare_ref(void *ref_buf, size_t ref_offset,
				 size_t ref_size, size_t buf_size,
				 void *data, size_t head)
{
	size_t ref_end = ref_offset + ref_size;

	if (ref_end > buf_size) {
		if (head > ref_offset || head < ref_end - buf_size)
			return true;
	} else if (head > ref_offset && head < ref_end) {
		return true;
	}

	return arm_spe_compare_buffers(ref_buf, ref_size, data, ref_offset,
					buf_size);
}

static void arm_spe_copy_ref(void *ref_buf, size_t ref_size, size_t buf_size,
			      void *data, size_t head)
{
	if (head >= ref_size) {
		memcpy(ref_buf, data + head - ref_size, ref_size);
	} else {
		memcpy(ref_buf, data, head);
		ref_size -= head;
		memcpy(ref_buf + head, data + buf_size - ref_size, ref_size);
	}
}

static bool arm_spe_wrapped(struct arm_spe_recording *ptr, int idx,
			     struct auxtrace_mmap *mm, unsigned char *data,
			     u64 head)
{
	struct arm_spe_snapshot_ref *ref = &ptr->snapshot_refs[idx];
	bool wrapped;

	wrapped = arm_spe_compare_ref(ref->ref_buf, ref->ref_offset,
				       ptr->snapshot_ref_buf_size, mm->len,
				       data, head);

	arm_spe_copy_ref(ref->ref_buf, ptr->snapshot_ref_buf_size, mm->len,
			  data, head);

	return wrapped;
}

static bool arm_spe_first_wrap(u64 *data, size_t buf_size)
{
	int i, a, b;

	b = buf_size >> 3;
	a = b - 512;
	if (a < 0)
		a = 0;

	for (i = a; i < b; i++) {
		if (data[i])
			return true;
	}

	return false;
}

static int arm_spe_find_snapshot(struct auxtrace_record *itr, int idx,
				  struct auxtrace_mmap *mm, unsigned char *data,
				  u64 *head, u64 *old)
{
	struct arm_spe_recording *ptr =
			container_of(itr, struct arm_spe_recording, itr);
	bool wrapped;
	int err;

	pr_debug3("%s: mmap index %d old head %zu new head %zu\n",
		  __func__, idx, (size_t)*old, (size_t)*head);

	err = arm_spe_snapshot_init(ptr, mm->len);
	if (err)
		goto out_err;

	if (idx >= ptr->snapshot_ref_cnt) {
		err = arm_spe_alloc_snapshot_refs(ptr, idx);
		if (err)
			goto out_err;
	}

	if (ptr->snapshot_ref_buf_size) {
		if (!ptr->snapshot_refs[idx].ref_buf) {
			err = arm_spe_alloc_snapshot_ref(ptr, idx, mm->len);
			if (err)
				goto out_err;
		}
		wrapped = arm_spe_wrapped(ptr, idx, mm, data, *head);
	} else {
		wrapped = ptr->snapshot_refs[idx].wrapped;
		if (!wrapped && arm_spe_first_wrap((u64 *)data, mm->len)) {
			ptr->snapshot_refs[idx].wrapped = true;
			wrapped = true;
		}
	}

	/*
	 * In full trace mode 'head' continually increases.  However in snapshot
	 * mode 'head' is an offset within the buffer.  Here 'old' and 'head'
	 * are adjusted to match the full trace case which expects that 'old' is
	 * always less than 'head'.
	 */
	if (wrapped) {
		*old = *head;
		*head += mm->len;
	} else {
		if (mm->mask)
			*old &= mm->mask;
		else
			*old %= mm->len;
		if (*old > *head)
			*head += mm->len;
	}

	pr_debug3("%s: wrap-around %sdetected, adjusted old head %zu adjusted new head %zu\n",
		  __func__, wrapped ? "" : "not ", (size_t)*old, (size_t)*head);

	return 0;

out_err:
	return err;
}

static u64 arm_spe_reference(struct auxtrace_record *itr __maybe_unused)
{
	u64 ts;

	asm volatile ("isb; mrs %0, cntvct_el0" : "=r" (ts));

	return ts;
}

static int arm_spe_read_finish(struct auxtrace_record *itr, int idx)
{
	struct arm_spe_recording *ptr =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_evsel *evsel;

	evlist__for_each_entry(ptr->evlist, evsel) {
		if (evsel->attr.type == ptr->arm_spe_pmu->type)
			return perf_evlist__enable_event_idx(ptr->evlist, evsel,
							     idx);
	}
	return -EINVAL;
}

struct auxtrace_record *arm_spe_record__init(int *err)
{
	struct perf_pmu *arm_spe_pmu = perf_pmu__find(ARM_SPE_PMU_NAME);
	struct arm_spe_recording *ptr;

	if (!arm_spe_pmu)
		return NULL;

	if (setenv("JITDUMP_USE_ARCH_TIMESTAMP", "1", 1)) {
		*err = -errno;
		return NULL;
	}

	ptr = zalloc(sizeof(struct arm_spe_recording));
	if (!ptr) {
		*err = -ENOMEM;
		return NULL;
	}

	ptr->arm_spe_pmu = arm_spe_pmu;
	ptr->itr.recording_options = arm_spe_recording_options;
	ptr->itr.info_priv_size = arm_spe_info_priv_size;
	ptr->itr.info_fill = arm_spe_info_fill;
	ptr->itr.free = arm_spe_recording_free;
	ptr->itr.snapshot_start = arm_spe_snapshot_start;
	ptr->itr.snapshot_finish = arm_spe_snapshot_finish;
	ptr->itr.find_snapshot = arm_spe_find_snapshot;
	ptr->itr.parse_snapshot_options = arm_spe_parse_snapshot_options;
	ptr->itr.reference = arm_spe_reference;
	ptr->itr.read_finish = arm_spe_read_finish;

	return &ptr->itr;
}
