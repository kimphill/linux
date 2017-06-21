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
#define KiB_MASK(x) (KiB(x) - 1)
#define MiB_MASK(x) (MiB(x) - 1)

struct arm_spe_snapshot_ref {
	void	*ref_buf;
	size_t	ref_offset;
	bool	wrapped;
};

struct arm_spe_recording {
	struct auxtrace_record		itr;
	struct perf_pmu			*arm_spe_pmu;
	struct perf_evlist		*evlist;
	bool				snapshot_mode;
	size_t				snapshot_size;
	int				snapshot_ref_cnt;
	struct arm_spe_snapshot_ref	*snapshot_refs;
};

struct branch {
	u64 from;
	u64 to;
	u64 misc;
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

	if (priv_size != ARM_SPE_AUXTRACE_PRIV_SIZE)
		return -EINVAL;

	if (!session->evlist->nr_mmaps)
{
pr_err("when does this occur?\n");
		return -EINVAL;
}

	auxtrace_info->type = PERF_AUXTRACE_ARM_SPE;
	auxtrace_info->priv[ARM_SPE_PMU_TYPE] = arm_spe_pmu->type;
	auxtrace_info->priv[ARM_SPE_SNAPSHOT_MODE] = sper->snapshot_mode;

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

	sper->evlist = evlist;
	sper->snapshot_mode = opts->auxtrace_snapshot_mode;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.type == arm_spe_pmu->type) {
			if (arm_spe_evsel) {
				pr_err("There may be only one " ARM_SPE_PMU_NAME " event\n");
				return -EINVAL;
			}
			evsel->attr.freq = 0;
			evsel->attr.sample_period = 1;
			arm_spe_evsel = evsel;
			opts->full_auxtrace = true;
		}
	}

	if (opts->auxtrace_snapshot_mode && !opts->full_auxtrace) {
		pr_err("Snapshot mode (-S option) requires " ARM_SPE_PMU_NAME " PMU event (-e " ARM_SPE_PMU_NAME ")\n");
		return -EINVAL;
	}

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

	if (!opts->full_auxtrace)
		return 0;

#if 0 /* want to push to not have to specify --per-thread, in case get past failed to mmap */
	if (opts->full_auxtrace && !cpu_map__empty(cpus)) {
		pr_err(ARM_SPE_PMU_NAME " does not support per-cpu recording\n");
		return -EINVAL;
	}
#endif

	/* Set default sizes for snapshot mode */
	if (opts->auxtrace_snapshot_mode) {
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

	if (arm_spe_evsel) {
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
	}

#if 0 /* 1 is use intel bts  way */
	/* Add dummy event to keep tracking */
	if (opts->full_auxtrace) {
		struct perf_evsel *tracking_evsel;
		int err;

		err = parse_events(evlist, "dummy:u", NULL);
		if (err)
			return err;

		tracking_evsel = perf_evlist__last(evlist);

		perf_evlist__set_tracking_event(evlist, tracking_evsel);

		tracking_evsel->attr.freq = 0;
		tracking_evsel->attr.sample_period = 1;
	}
#else
	/* Add dummy event to keep tracking */
	if (opts->full_auxtrace) {
		struct perf_evsel *tracking_evsel;
		int err;

		err = parse_events(evlist, "dummy:u", NULL);
		if (err)
			return err;

		tracking_evsel = perf_evlist__last(evlist);
		perf_evlist__set_tracking_event(evlist, tracking_evsel);

		tracking_evsel->attr.freq = 0;
		tracking_evsel->attr.sample_period = 1;

		/* In per-cpu case, always need the time of mmap events etc */
		if (!cpu_map__empty(cpus))
			perf_evsel__set_sample_bit(tracking_evsel, TIME);
	}
#endif

	return 0;
}

static int arm_spe_parse_snapshot_options(struct auxtrace_record *itr,
					    struct record_opts *opts,
					    const char *str)
{
	struct arm_spe_recording *sper =
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

	sper->snapshot_size = snapshot_size;

	return 0;
}

static u64 arm_spe_reference(struct auxtrace_record *itr __maybe_unused)
{
	return rdtsc();
}

static int arm_spe_alloc_snapshot_refs(struct arm_spe_recording *sper,
					 int idx)
{
	const size_t sz = sizeof(struct arm_spe_snapshot_ref);
	int cnt = sper->snapshot_ref_cnt, new_cnt = cnt * 2;
	struct arm_spe_snapshot_ref *refs;

	if (!new_cnt)
		new_cnt = 16;

	while (new_cnt <= idx)
		new_cnt *= 2;

	refs = calloc(new_cnt, sz);
	if (!refs)
		return -ENOMEM;

	memcpy(refs, sper->snapshot_refs, cnt * sz);

	sper->snapshot_refs = refs;
	sper->snapshot_ref_cnt = new_cnt;

	return 0;
}

static void arm_spe_free_snapshot_refs(struct arm_spe_recording *sper)
{
	int i;

	for (i = 0; i < sper->snapshot_ref_cnt; i++)
		zfree(&sper->snapshot_refs[i].ref_buf);
	zfree(&sper->snapshot_refs);
}

static void arm_spe_recording_free(struct auxtrace_record *itr)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);

	arm_spe_free_snapshot_refs(sper);
	free(sper);
}

static int arm_spe_snapshot_start(struct auxtrace_record *itr)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_evsel *evsel;

	evlist__for_each_entry(sper->evlist, evsel) {
		if (evsel->attr.type == sper->arm_spe_pmu->type)
			return perf_evsel__disable(evsel);
	}
	return -EINVAL;
}

static int arm_spe_snapshot_finish(struct auxtrace_record *itr)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_evsel *evsel;

	evlist__for_each_entry(sper->evlist, evsel) {
		if (evsel->attr.type == sper->arm_spe_pmu->type)
			return perf_evsel__enable(evsel);
	}
	return -EINVAL;
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
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	bool wrapped;
	int err;

	pr_debug3("%s: mmap index %d old head %zu new head %zu\n",
		  __func__, idx, (size_t)*old, (size_t)*head);

	if (idx >= sper->snapshot_ref_cnt) {
		err = arm_spe_alloc_snapshot_refs(sper, idx);
		if (err)
			goto out_err;
	}

	wrapped = sper->snapshot_refs[idx].wrapped;
	if (!wrapped && arm_spe_first_wrap((u64 *)data, mm->len)) {
		sper->snapshot_refs[idx].wrapped = true;
		wrapped = true;
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
	pr_err("%s: failed, error %d\n", __func__, err);
	return err;
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

struct auxtrace_record *arm_spe_recording_init(int *err)
{
	struct perf_pmu *arm_spe_pmu = perf_pmu__find(ARM_SPE_PMU_NAME);
	struct arm_spe_recording *sper;

	if (!arm_spe_pmu)
		return NULL;

	if (setenv("JITDUMP_USE_ARCH_TIMESTAMP", "1", 1)) {
		*err = -errno;
		return NULL;
	}

	sper = zalloc(sizeof(struct arm_spe_recording));
	if (!sper) {
		*err = -ENOMEM;
		return NULL;
	}

	sper->arm_spe_pmu = arm_spe_pmu;
	sper->itr.recording_options = arm_spe_recording_options;
	sper->itr.info_priv_size = arm_spe_info_priv_size;
	sper->itr.info_fill = arm_spe_info_fill;
	sper->itr.free = arm_spe_recording_free;
	sper->itr.snapshot_start = arm_spe_snapshot_start;
	sper->itr.snapshot_finish = arm_spe_snapshot_finish;
	sper->itr.find_snapshot = arm_spe_find_snapshot;
	sper->itr.parse_snapshot_options = arm_spe_parse_snapshot_options;
	sper->itr.reference = arm_spe_reference;
	sper->itr.read_finish = arm_spe_read_finish;
	sper->itr.alignment = 0;
	return &sper->itr;
}
