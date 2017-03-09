/*
 * Perf support for the Statistical Profiling Extension, introduced as
 * part of ARMv8.2.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2016 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */

#define PMUNAME				"arm_spe"
#define DRVNAME				PMUNAME "_pmu"
#define pr_fmt(fmt)			DRVNAME ": " fmt

#include <linux/cpuhotplug.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include <asm/sysreg.h>

/* ID registers */
#define PMSIDR_EL1			sys_reg(3, 0, 9, 9, 7)
#define PMSIDR_EL1_FE_SHIFT		0
#define PMSIDR_EL1_FT_SHIFT		1
#define PMSIDR_EL1_FL_SHIFT		2
#define PMSIDR_EL1_ARCHINST_SHIFT	3
#define PMSIDR_EL1_LDS_SHIFT		4
#define PMSIDR_EL1_ERND_SHIFT		5
#define PMSIDR_EL1_INTERVAL_SHIFT	8
#define PMSIDR_EL1_INTERVAL_MASK	0xfUL
#define PMSIDR_EL1_MAXSIZE_SHIFT	12
#define PMSIDR_EL1_MAXSIZE_MASK		0xfUL
#define PMSIDR_EL1_COUNTSIZE_SHIFT	16
#define PMSIDR_EL1_COUNTSIZE_MASK	0xfUL

#define PMBIDR_EL1			sys_reg(3, 0, 9, 10, 7)
#define PMBIDR_EL1_ALIGN_SHIFT		0
#define PMBIDR_EL1_ALIGN_MASK		0xfU
#define PMBIDR_EL1_P_SHIFT		4
#define PMBIDR_EL1_F_SHIFT		5

/* Sampling controls */
#define PMSCR_EL1			sys_reg(3, 0, 9, 9, 0)
#define PMSCR_EL1_E0SPE_SHIFT		0
#define PMSCR_EL1_E1SPE_SHIFT		1
#define PMSCR_EL1_CX_SHIFT		3
#define PMSCR_EL1_PA_SHIFT		4
#define PMSCR_EL1_TS_SHIFT		5
#define PMSCR_EL1_PCT_SHIFT		6

#define PMSICR_EL1			sys_reg(3, 0, 9, 9, 2)

#define PMSIRR_EL1			sys_reg(3, 0, 9, 9, 3)
#define PMSIRR_EL1_RND_SHIFT		0
#define PMSIRR_EL1_IVAL_MASK		0xffUL

/* Filtering controls */
#define PMSFCR_EL1			sys_reg(3, 0, 9, 9, 4)
#define PMSFCR_EL1_FE_SHIFT		0
#define PMSFCR_EL1_FT_SHIFT		1
#define PMSFCR_EL1_FL_SHIFT		2
#define PMSFCR_EL1_B_SHIFT		16
#define PMSFCR_EL1_LD_SHIFT		17
#define PMSFCR_EL1_ST_SHIFT		18

#define PMSEVFR_EL1			sys_reg(3, 0, 9, 9, 5)
#define PMSEVFR_EL1_RES0		0x0000ffff00ff0f55UL

#define PMSLATFR_EL1			sys_reg(3, 0, 9, 9, 6)
#define PMSLATFR_EL1_MINLAT_SHIFT	0

/* Buffer controls */
#define PMBLIMITR_EL1			sys_reg(3, 0, 9, 10, 0)
#define PMBLIMITR_EL1_E_SHIFT		0
#define PMBLIMITR_EL1_FM_SHIFT		1
#define PMBLIMITR_EL1_FM_MASK		0x3UL
#define PMBLIMITR_EL1_FM_STOP_IRQ	(0 << PMBLIMITR_EL1_FM_SHIFT)

#define PMBPTR_EL1			sys_reg(3, 0, 9, 10, 1)

/* Buffer error reporting */
#define PMBSR_EL1			sys_reg(3, 0, 9, 10, 3)
#define PMBSR_EL1_COLL_SHIFT		16
#define PMBSR_EL1_S_SHIFT		17
#define PMBSR_EL1_EA_SHIFT		18
#define PMBSR_EL1_DL_SHIFT		19
#define PMBSR_EL1_EC_SHIFT		26
#define PMBSR_EL1_EC_MASK		0x3fUL

#define PMBSR_EL1_EC_BUF		(0x0UL << PMBSR_EL1_EC_SHIFT)
#define PMBSR_EL1_EC_FAULT_S1		(0x24UL << PMBSR_EL1_EC_SHIFT)
#define PMBSR_EL1_EC_FAULT_S2		(0x25UL << PMBSR_EL1_EC_SHIFT)

#define PMBSR_EL1_FAULT_FSC_SHIFT	0
#define PMBSR_EL1_FAULT_FSC_MASK	0x3fUL

#define PMBSR_EL1_BUF_BSC_SHIFT		0
#define PMBSR_EL1_BUF_BSC_MASK		0x3fUL

#define PMBSR_EL1_BUF_BSC_FULL		(0x1UL << PMBSR_EL1_BUF_BSC_SHIFT)

#define psb_csync()			asm volatile("hint #17")

struct arm_spe_pmu_buf {
	int					nr_pages;
	bool					snapshot;
	void					*base;
};

struct arm_spe_pmu {
	struct pmu				pmu;
	struct platform_device			*pdev;
	cpumask_t				supported_cpus;
	struct hlist_node			hotplug_node;

	int					irq; /* PPI */

	u16					min_period;
	u16					cnt_width;

#define SPE_PMU_FEAT_FILT_EVT			(1UL << 0)
#define SPE_PMU_FEAT_FILT_TYP			(1UL << 1)
#define SPE_PMU_FEAT_FILT_LAT			(1UL << 2)
#define SPE_PMU_FEAT_ARCH_INST			(1UL << 3)
#define SPE_PMU_FEAT_LDS			(1UL << 4)
#define SPE_PMU_FEAT_ERND			(1UL << 5)
#define SPE_PMU_FEAT_DEV_PROBED			(1UL << 63)
	u64					features;

	u16					max_record_sz;
	u16					align;
	struct perf_output_handle __percpu	*handle;
};

#define to_spe_pmu(p) (container_of(p, struct arm_spe_pmu, pmu))

/* Convert a free-running index from perf into an SPE buffer offset */
#define PERF_IDX2OFF(idx, buf)	((idx) & (((buf)->nr_pages << PAGE_SHIFT) - 1))

/* Keep track of our dynamic hotplug state */
static enum cpuhp_state arm_spe_pmu_online;

/* This sysfs gunk was really good fun to write. */
enum arm_spe_pmu_capabilities {
	SPE_PMU_CAP_ARCH_INST = 0,
	SPE_PMU_CAP_ERND,
	SPE_PMU_CAP_FEAT_MAX,
	SPE_PMU_CAP_CNT_SZ = SPE_PMU_CAP_FEAT_MAX,
	SPE_PMU_CAP_MIN_IVAL,
};

static int arm_spe_pmu_feat_caps[SPE_PMU_CAP_FEAT_MAX] = {
	[SPE_PMU_CAP_ARCH_INST]	= SPE_PMU_FEAT_ARCH_INST,
	[SPE_PMU_CAP_ERND]	= SPE_PMU_FEAT_ERND,
};

static u32 arm_spe_pmu_cap_get(struct arm_spe_pmu *spe_pmu, int cap)
{
	if (cap < SPE_PMU_CAP_FEAT_MAX)
		return !!(spe_pmu->features & arm_spe_pmu_feat_caps[cap]);

	switch (cap) {
	case SPE_PMU_CAP_CNT_SZ:
		return spe_pmu->cnt_width;
	case SPE_PMU_CAP_MIN_IVAL:
		return spe_pmu->min_period;
	default:
		WARN(1, "unknown cap %d\n", cap);
	}

	return 0;
}

static ssize_t arm_spe_pmu_cap_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct arm_spe_pmu *spe_pmu = platform_get_drvdata(pdev);
	struct dev_ext_attribute *ea =
		container_of(attr, struct dev_ext_attribute, attr);
	int cap = (long)ea->var;

	return snprintf(buf, PAGE_SIZE, "%u\n",
		arm_spe_pmu_cap_get(spe_pmu, cap));
}

#define SPE_EXT_ATTR_ENTRY(_name, _func, _var)				\
	&((struct dev_ext_attribute[]) {				\
		{ __ATTR(_name, S_IRUGO, _func, NULL), (void *)_var }	\
	})[0].attr.attr

#define SPE_CAP_EXT_ATTR_ENTRY(_name, _var)				\
	SPE_EXT_ATTR_ENTRY(_name, arm_spe_pmu_cap_show, _var)

static struct attribute *arm_spe_pmu_cap_attr[] = {
	SPE_CAP_EXT_ATTR_ENTRY(arch_inst, SPE_PMU_CAP_ARCH_INST),
	SPE_CAP_EXT_ATTR_ENTRY(ernd, SPE_PMU_CAP_ERND),
	SPE_CAP_EXT_ATTR_ENTRY(count_size, SPE_PMU_CAP_CNT_SZ),
	SPE_CAP_EXT_ATTR_ENTRY(min_interval, SPE_PMU_CAP_MIN_IVAL),
	NULL,
};

static struct attribute_group arm_spe_pmu_cap_group = {
	.name	= "caps",
	.attrs	= arm_spe_pmu_cap_attr,
};

/* User ABI */
#define ATTR_CFG_FLD_ts_enable_CFG		config	/* PMSCR_EL1.TS */
#define ATTR_CFG_FLD_ts_enable_LO		0
#define ATTR_CFG_FLD_ts_enable_HI		0
#define ATTR_CFG_FLD_pa_enable_CFG		config	/* PMSCR_EL1.PA */
#define ATTR_CFG_FLD_pa_enable_LO		1
#define ATTR_CFG_FLD_pa_enable_HI		1
#define ATTR_CFG_FLD_jitter_CFG			config	/* PMSIRR_EL1.RND */
#define ATTR_CFG_FLD_jitter_LO			16
#define ATTR_CFG_FLD_jitter_HI			16
#define ATTR_CFG_FLD_branch_filter_CFG		config	/* PMSFCR_EL1.B */
#define ATTR_CFG_FLD_branch_filter_LO		32
#define ATTR_CFG_FLD_branch_filter_HI		32
#define ATTR_CFG_FLD_load_filter_CFG		config	/* PMSFCR_EL1.LD */
#define ATTR_CFG_FLD_load_filter_LO		33
#define ATTR_CFG_FLD_load_filter_HI		33
#define ATTR_CFG_FLD_store_filter_CFG		config	/* PMSFCR_EL1.ST */
#define ATTR_CFG_FLD_store_filter_LO		34
#define ATTR_CFG_FLD_store_filter_HI		34

#define ATTR_CFG_FLD_event_filter_CFG		config1	/* PMSEVFR_EL1 */
#define ATTR_CFG_FLD_event_filter_LO		0
#define ATTR_CFG_FLD_event_filter_HI		63

#define ATTR_CFG_FLD_min_latency_CFG		config2	/* PMSLATFR_EL1.MINLAT */
#define ATTR_CFG_FLD_min_latency_LO		0
#define ATTR_CFG_FLD_min_latency_HI		11

/* Why does everything I do descend into this? */
#define __GEN_PMU_FORMAT_ATTR(cfg, lo, hi)				\
	(lo) == (hi) ? #cfg ":" #lo "\n" : #cfg ":" #lo "-" #hi

#define _GEN_PMU_FORMAT_ATTR(cfg, lo, hi)				\
	__GEN_PMU_FORMAT_ATTR(cfg, lo, hi)

#define GEN_PMU_FORMAT_ATTR(name)					\
	PMU_FORMAT_ATTR(name,						\
	_GEN_PMU_FORMAT_ATTR(ATTR_CFG_FLD_##name##_CFG,			\
			     ATTR_CFG_FLD_##name##_LO,			\
			     ATTR_CFG_FLD_##name##_HI))

#define _ATTR_CFG_GET_FLD(attr, cfg, lo, hi)				\
	((((attr)->cfg) >> lo) & GENMASK(hi - lo, 0))

#define ATTR_CFG_GET_FLD(attr, name)					\
	_ATTR_CFG_GET_FLD(attr,						\
			  ATTR_CFG_FLD_##name##_CFG,			\
			  ATTR_CFG_FLD_##name##_LO,			\
			  ATTR_CFG_FLD_##name##_HI)

GEN_PMU_FORMAT_ATTR(ts_enable);
GEN_PMU_FORMAT_ATTR(pa_enable);
GEN_PMU_FORMAT_ATTR(jitter);
GEN_PMU_FORMAT_ATTR(load_filter);
GEN_PMU_FORMAT_ATTR(store_filter);
GEN_PMU_FORMAT_ATTR(branch_filter);
GEN_PMU_FORMAT_ATTR(event_filter);
GEN_PMU_FORMAT_ATTR(min_latency);

static struct attribute *arm_spe_pmu_formats_attr[] = {
	&format_attr_ts_enable.attr,
	&format_attr_pa_enable.attr,
	&format_attr_jitter.attr,
	&format_attr_load_filter.attr,
	&format_attr_store_filter.attr,
	&format_attr_branch_filter.attr,
	&format_attr_event_filter.attr,
	&format_attr_min_latency.attr,
	NULL,
};

static struct attribute_group arm_spe_pmu_format_group = {
	.name	= "format",
	.attrs	= arm_spe_pmu_formats_attr,
};

static ssize_t arm_spe_pmu_get_attr_cpumask(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct arm_spe_pmu *spe_pmu = platform_get_drvdata(pdev);

	pr_err("%s %d: entry\n", __func__, __LINE__);

	return cpumap_print_to_pagebuf(true, buf, &spe_pmu->supported_cpus);
}
static DEVICE_ATTR(cpumask, S_IRUGO, arm_spe_pmu_get_attr_cpumask, NULL);

static struct attribute *arm_spe_pmu_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group arm_spe_pmu_group = {
	.attrs	= arm_spe_pmu_attrs,
};

static const struct attribute_group *arm_spe_pmu_attr_groups[] = {
	&arm_spe_pmu_group,
	&arm_spe_pmu_cap_group,
	&arm_spe_pmu_format_group,
	NULL,
};

/* Convert between user ABI and register values */
static u64 arm_spe_event_to_pmscr(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	u64 reg = 0;

	reg |= ATTR_CFG_GET_FLD(attr, ts_enable) << PMSCR_EL1_TS_SHIFT;
	reg |= ATTR_CFG_GET_FLD(attr, pa_enable) << PMSCR_EL1_PA_SHIFT;

	if (!attr->exclude_user)
		reg |= BIT(PMSCR_EL1_E0SPE_SHIFT);

	if (!attr->exclude_kernel)
		reg |= BIT(PMSCR_EL1_E1SPE_SHIFT);

	if (IS_ENABLED(CONFIG_PID_IN_CONTEXTIDR))
		reg |= BIT(PMSCR_EL1_CX_SHIFT);

	return reg;
}

static void arm_spe_event_sanitise_period(struct perf_event *event)
{
	struct arm_spe_pmu *spe_pmu = to_spe_pmu(event->pmu);
	u64 period = event->hw.sample_period & ~PMSIRR_EL1_IVAL_MASK;

	if (period < spe_pmu->min_period)
		period = spe_pmu->min_period;

	event->hw.sample_period = period;
}

static u64 arm_spe_event_to_pmsirr(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	u64 reg = 0;

	arm_spe_event_sanitise_period(event);

	reg |= ATTR_CFG_GET_FLD(attr, jitter) << PMSIRR_EL1_RND_SHIFT;
	reg |= event->hw.sample_period;

	return reg;
}

static u64 arm_spe_event_to_pmsfcr(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	u64 reg = 0;

	reg |= ATTR_CFG_GET_FLD(attr, load_filter) << PMSFCR_EL1_LD_SHIFT;
	reg |= ATTR_CFG_GET_FLD(attr, store_filter) << PMSFCR_EL1_ST_SHIFT;
	reg |= ATTR_CFG_GET_FLD(attr, branch_filter) << PMSFCR_EL1_B_SHIFT;

	if (reg)
		reg |= BIT(PMSFCR_EL1_FT_SHIFT);

	if (ATTR_CFG_GET_FLD(attr, event_filter))
		reg |= BIT(PMSFCR_EL1_FE_SHIFT);

	if (ATTR_CFG_GET_FLD(attr, min_latency))
		reg |= BIT(PMSFCR_EL1_FL_SHIFT);

	return reg;
}

static u64 arm_spe_event_to_pmsevfr(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	return ATTR_CFG_GET_FLD(attr, event_filter);
}

static u64 arm_spe_event_to_pmslatfr(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	return ATTR_CFG_GET_FLD(attr, min_latency) << PMSLATFR_EL1_MINLAT_SHIFT;
}

static bool arm_spe_pmu_buffer_mgmt_pending(u64 pmbsr)
{
	const char *err_str;

	/* Service required? */
	if (!(pmbsr & BIT(PMBSR_EL1_S_SHIFT)))
		return false;

	/* We only expect buffer management events */
	switch (pmbsr & (PMBSR_EL1_EC_MASK << PMBSR_EL1_EC_SHIFT)) {
	case PMBSR_EL1_EC_BUF:
		/* Handled below */
		break;
	case PMBSR_EL1_EC_FAULT_S1:
	case PMBSR_EL1_EC_FAULT_S2:
		err_str = "Unexpected buffer fault";
		goto out_err;
	default:
		err_str = "Unknown error code";
		goto out_err;
	}

	/* Buffer management event */
	switch (pmbsr & (PMBSR_EL1_BUF_BSC_MASK << PMBSR_EL1_BUF_BSC_SHIFT)) {
	case PMBSR_EL1_BUF_BSC_FULL:
		return true;
	default:
		err_str = "Unknown buffer status code";
	}

out_err:
	pr_err_ratelimited("%s on CPU %d [PMBSR=0x%08llx]\n", err_str,
			   smp_processor_id(), pmbsr);
	return false;
}

static u64 arm_spe_pmu_next_snapshot_off(struct perf_output_handle *handle)
{
	struct arm_spe_pmu_buf *buf = perf_get_aux(handle);
	struct arm_spe_pmu *spe_pmu = to_spe_pmu(handle->event->pmu);
	u64 head = PERF_IDX2OFF(handle->head, buf);
	u64 limit = buf->nr_pages * PAGE_SIZE;

	/*
	 * The trace format isn't parseable in reverse, so clamp
	 * the limit to half of the buffer size in snapshot mode
	 * so that the worst case is half a buffer of records, as
	 * opposed to a single record.
	 */
	if (head < limit >> 1)
		limit >>= 1;

	/*
	 * If we're within max_record_sz of the limit, we must
	 * pad, move the head index and recompute the limit.
	 */
	if (limit - head < spe_pmu->max_record_sz) {
		memset(buf->base + head, 0, limit - head);
		handle->head = PERF_IDX2OFF(limit, buf);
		limit = ((buf->nr_pages * PAGE_SIZE) >> 1) + handle->head;
	}

	return limit;
}

static u64 __arm_spe_pmu_next_off(struct perf_output_handle *handle)
{
	struct arm_spe_pmu_buf *buf = perf_get_aux(handle);
	u64 head = PERF_IDX2OFF(handle->head, buf);
	u64 tail = PERF_IDX2OFF(handle->head + handle->size, buf);
	u64 wakeup = PERF_IDX2OFF(handle->wakeup, buf);
	u64 limit = buf->nr_pages * PAGE_SIZE;

	/*
	 * Set the limit pointer to either the watermark or the
	 * current tail pointer; whichever comes first.
	 */
	if (handle->head + handle->size <= handle->wakeup) {
		/* The tail is next, so check for wrapping */
		if (tail >= head) {
			/*
			 * No wrapping, but need to align downwards to
			 * avoid corrupting unconsumed data.
			 */
			limit = round_down(tail, PAGE_SIZE);

		}
	} else if (wakeup >= head) {
		/*
		 * The wakeup is next and doesn't wrap. Align upwards to
		 * ensure that we do indeed reach the watermark.
		 */
		limit = round_up(wakeup, PAGE_SIZE);

		/*
		 * If rounding up crosses the tail, then we have to
		 * round down to avoid corrupting unconsumed data.
		 * Hopefully the tail will have moved by the time we
		 * hit the new limit.
		 */
		if (wakeup < tail && limit > tail)
			limit = round_down(wakeup, PAGE_SIZE);
	}

	/*
	 * If rounding down crosses the head, then the buffer is full,
	 * so pad to tail and end the session.
	 */
	if (limit <= head) {
		memset(buf->base + head, 0, handle->size);
		perf_aux_output_skip(handle, handle->size);
		perf_aux_output_end(handle, 0, PERF_AUX_FLAG_TRUNCATED);
		limit = 0;
	}

	return limit;
}

static u64 arm_spe_pmu_next_off(struct perf_output_handle *handle)
{
	struct arm_spe_pmu_buf *buf = perf_get_aux(handle);
	struct arm_spe_pmu *spe_pmu = to_spe_pmu(handle->event->pmu);
	u64 limit = __arm_spe_pmu_next_off(handle);
	u64 head = PERF_IDX2OFF(handle->head, buf);

	/*
	 * If the head has come too close to the end of the buffer,
	 * then pad to the end and recompute the limit.
	 */
	if (limit && (limit - head < spe_pmu->max_record_sz)) {
		memset(buf->base + head, 0, limit - head);
		perf_aux_output_skip(handle, limit - head);
		limit = __arm_spe_pmu_next_off(handle);
	}

	return limit;
}

static void arm_spe_perf_aux_output_begin(struct perf_output_handle *handle,
					  struct perf_event *event)
{
	u64 base, limit;
	struct arm_spe_pmu_buf *buf;

	/* Start a new aux session */
	buf = perf_aux_output_begin(handle, event);
	if (!buf) {
		event->hw.state |= PERF_HES_STOPPED;
		/*
		 * We still need to clear the limit pointer, since the
		 * profiler might only be disabled by virtue of a fault.
		 */
		limit = 0;
		goto out_write_limit;
	}

	limit = buf->snapshot ? arm_spe_pmu_next_snapshot_off(handle)
			      : arm_spe_pmu_next_off(handle);
	if (limit)
		limit |= BIT(PMBLIMITR_EL1_E_SHIFT);

	base = (u64)buf->base + PERF_IDX2OFF(handle->head, buf);
	write_sysreg_s(base, PMBPTR_EL1);
	limit += (u64)buf->base;

out_write_limit:
	write_sysreg_s(limit, PMBLIMITR_EL1);
}

static bool arm_spe_perf_aux_output_end(struct perf_output_handle *handle,
					struct perf_event *event,
					bool resume)
{
	u64 pmbptr, pmbsr, offset, size;
	struct arm_spe_pmu *spe_pmu = to_spe_pmu(event->pmu);
	struct arm_spe_pmu_buf *buf = perf_get_aux(handle);
	bool truncated, collided;

	/*
	 * We can be called via IRQ work trying to disable the PMU after
	 * a buffer full event. In this case, the aux session has already
	 * been stopped, so there's nothing to do here.
	 */
	if (!buf)
		return false;

	/*
	 * Work out how much data has been written since the last update
	 * to the head index.
	 */
	pmbptr = round_down(read_sysreg_s(PMBPTR_EL1), spe_pmu->align);
	offset = pmbptr - (u64)buf->base;
	size = offset - PERF_IDX2OFF(handle->head, buf);

	if (buf->snapshot)
		handle->head = offset;

	/*
	 * If there isn't a pending management event and we're not stopping
	 * the current session, then just leave everything alone.
	 */
	pmbsr = read_sysreg_s(PMBSR_EL1);
	if (!arm_spe_pmu_buffer_mgmt_pending(pmbsr) && resume)
		return false; /* Spurious IRQ */

	/*
	 * Either the buffer is full or we're stopping the session. Check
	 * that we didn't write a partial record, since this can result
	 * in unparseable trace and we must disable the event.
	 */
	collided = pmbsr & BIT(PMBSR_EL1_COLL_SHIFT);
	truncated = pmbsr & BIT(PMBSR_EL1_DL_SHIFT);
	perf_aux_output_end(handle, size,
			   (truncated ? PERF_AUX_FLAG_TRUNCATED : 0) |
			   (collided ? PERF_AUX_FLAG_COLLISION : 0));

	/*
	 * If we're not resuming the session, then we can clear the fault
	 * and we're done, otherwise we need to start a new session.
	 */
	if (!resume)
		write_sysreg_s(0, PMBSR_EL1);
	else if (!truncated)
		arm_spe_perf_aux_output_begin(handle, event);

	return true;
}

/* IRQ handling */
static irqreturn_t arm_spe_pmu_irq_handler(int irq, void *dev)
{
	struct perf_output_handle *handle = dev;

	if (!perf_get_aux(handle))
		return IRQ_NONE;

	if (!arm_spe_perf_aux_output_end(handle, handle->event, true))
		return IRQ_NONE;

	irq_work_run();
	isb(); /* Ensure the buffer is disabled if data loss has occurred */
	write_sysreg_s(0, PMBSR_EL1);
	return IRQ_HANDLED;
}

/* Perf callbacks */
static int arm_spe_pmu_event_init(struct perf_event *event)
{
	u64 reg;
	struct perf_event_attr *attr = &event->attr;
	struct arm_spe_pmu *spe_pmu = to_spe_pmu(event->pmu);
	struct device *dev = &spe_pmu->pdev->dev;

	/* This is, of course, deeply driver-specific */
	if (attr->type != event->pmu->type)
		return -ENOENT;

	if (event->cpu >= 0 &&
	    !cpumask_test_cpu(event->cpu, &spe_pmu->supported_cpus)) {
		dev_err_ratelimited(dev, "%s %d: return -ENOENT;\n", __func__, __LINE__);
		return -ENOENT;
	}

	if (arm_spe_event_to_pmsevfr(event) & PMSEVFR_EL1_RES0) {
		dev_err_ratelimited(dev, "%s %d: return -EOPNOTSUPP\n", __func__, __LINE__);
		return -EOPNOTSUPP;
	}

	if (event->hw.sample_period < spe_pmu->min_period ||
	    event->hw.sample_period & PMSIRR_EL1_IVAL_MASK) {
		dev_err_ratelimited(dev, "Cannot set a sample period that is below the minimum interval\n");
		return -EOPNOTSUPP;
	}

	if (attr->exclude_idle) {
		dev_err_ratelimited(dev, "Cannot exclude profiling when idle\n");
		return -EOPNOTSUPP;
	}

	/*
	 * Feedback-directed frequency throttling doesn't work when we
	 * have a buffer of samples. We'd need to manually count the
	 * samples in the buffer when it fills up and adjust the event
	 * count to reflect that. Instead, force the user to specify a
	 * sample period instead.
	 */
	if (attr->freq) {
		dev_err_ratelimited(dev, "sample period must be specified\n");
		return -EINVAL;
	}

	if (is_kernel_in_hyp_mode()) {
		if (attr->exclude_kernel != attr->exclude_hv) {
			dev_err_ratelimited(dev, "VHE is enabled but exclude_kernel and exclude_hv have different values\n");
			return -EOPNOTSUPP;
		}
	} else if (!attr->exclude_hv) {
		dev_err_ratelimited(dev, "VHE is disabled but exclude_hv is not set\n");
		return -EOPNOTSUPP;
	}

	reg = arm_spe_event_to_pmsfcr(event);
	if ((reg & BIT(PMSFCR_EL1_FE_SHIFT)) &&
	    !(spe_pmu->features & SPE_PMU_FEAT_FILT_EVT)) {
		dev_err_ratelimited(dev, "unsupported filter (EVT)\n");
		return -EOPNOTSUPP;
	}

	if ((reg & BIT(PMSFCR_EL1_FT_SHIFT)) &&
	    !(spe_pmu->features & SPE_PMU_FEAT_FILT_TYP)) {
		dev_err_ratelimited(dev, "unsupported filter (TYP)\n");
		return -EOPNOTSUPP;
	}

	if ((reg & BIT(PMSFCR_EL1_FL_SHIFT)) &&
	    !(spe_pmu->features & SPE_PMU_FEAT_FILT_LAT)) {
		dev_err_ratelimited(dev, "unsupported filter (LAT)\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static void arm_spe_pmu_start(struct perf_event *event, int flags)
{
	u64 reg;
	struct arm_spe_pmu *spe_pmu = to_spe_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	struct perf_output_handle *handle = this_cpu_ptr(spe_pmu->handle);

	hwc->state = 0;
	arm_spe_perf_aux_output_begin(handle, event);
	if (hwc->state)
		return;

	reg = arm_spe_event_to_pmsfcr(event);
	write_sysreg_s(reg, PMSFCR_EL1);

	reg = arm_spe_event_to_pmsevfr(event);
	write_sysreg_s(reg, PMSEVFR_EL1);

	reg = arm_spe_event_to_pmslatfr(event);
	write_sysreg_s(reg, PMSLATFR_EL1);

	if (flags & PERF_EF_RELOAD) {
		reg = arm_spe_event_to_pmsirr(event);
		write_sysreg_s(reg, PMSIRR_EL1);
		isb();
		reg = local64_read(&hwc->period_left);
		write_sysreg_s(reg, PMSICR_EL1);
	}

	reg = arm_spe_event_to_pmscr(event);
	isb();
	write_sysreg_s(reg, PMSCR_EL1);
}

static void arm_spe_pmu_disable_and_drain_local(void)
{
	/* Disable profiling at EL0 and EL1 */
	write_sysreg_s(0, PMSCR_EL1);
	isb();

	/* Drain any buffered data */
	psb_csync();
	dsb(nsh);

	/* Disable the profiling buffer */
	write_sysreg_s(0, PMBLIMITR_EL1);
}

static void arm_spe_pmu_stop(struct perf_event *event, int flags)
{
	struct arm_spe_pmu *spe_pmu = to_spe_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	struct perf_output_handle *handle = this_cpu_ptr(spe_pmu->handle);

	pr_err("%s %d: entry\n", __func__, __LINE__);

	/* If we're already stopped, then nothing to do */
	if (hwc->state & PERF_HES_STOPPED)
		return;

	/* Stop all trace generation */
	arm_spe_pmu_disable_and_drain_local();

	if (flags & PERF_EF_UPDATE) {
		/* Ensure hardware updates to PMBPTR_EL1 are visible */
		isb();
		arm_spe_perf_aux_output_end(handle, event, false);
		/*
		 * This may also contain ECOUNT, but nobody else should
		 * be looking at period_left, since we forbid frequency
		 * based sampling.
		 */
		local64_set(&hwc->period_left, read_sysreg_s(PMSICR_EL1));
		hwc->state |= PERF_HES_UPTODATE;
	}

	hwc->state |= PERF_HES_STOPPED;
}

static int arm_spe_pmu_add(struct perf_event *event, int flags)
{
	int ret = 0;
	struct arm_spe_pmu *spe_pmu = to_spe_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int cpu = event->cpu == -1 ? smp_processor_id() : event->cpu;

	if (!cpumask_test_cpu(cpu, &spe_pmu->supported_cpus))
		return -ENOENT;

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;

	if (flags & PERF_EF_START) {
		arm_spe_pmu_start(event, PERF_EF_RELOAD);
		if (hwc->state & PERF_HES_STOPPED)
			ret = -EINVAL;
	}

	return ret;
}

static void arm_spe_pmu_del(struct perf_event *event, int flags)
{
	arm_spe_pmu_stop(event, PERF_EF_UPDATE);
}

static void arm_spe_pmu_read(struct perf_event *event)
{
}

static void *arm_spe_pmu_setup_aux(int cpu, void **pages, int nr_pages,
				   bool snapshot)
{
	int i;
	struct page **pglist;
	struct arm_spe_pmu_buf *buf;

pr_err("%s %d: entry\n", __func__, __LINE__);

	/*
	 * We require an even number of pages for snapshot mode, so that
	 * we can effectively treat the buffer as consisting of two equal
	 * parts and give userspace a fighting chance of getting some
	 * useful data out of it.
	 */
	if (!nr_pages || (snapshot && (nr_pages & 1)))
{ pr_err("%s %d: uh oh\n", __func__, __LINE__);
		return NULL;
}

	buf = kzalloc_node(sizeof(*buf), GFP_KERNEL, cpu_to_node(cpu));
	if (!buf)
{ pr_err("%s %d: uh oh\n", __func__, __LINE__);
		return NULL;
}

	pglist = kcalloc(nr_pages, sizeof(*pglist), GFP_KERNEL);
	if (!pglist)
{ pr_err("%s %d: uh oh\n", __func__, __LINE__);
		goto out_free_buf;
}

	for (i = 0; i < nr_pages; ++i) {
		struct page *page = virt_to_page(pages[i]);

		if (PagePrivate(page)) {
pr_err("%s %d: uh oh\n", __func__, __LINE__);
			pr_warn("unexpected high-order page for auxbuf!");
			goto out_free_pglist;
		}

		pglist[i] = virt_to_page(pages[i]);
	}

	buf->base = vmap(pglist, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!buf->base)
{ pr_err("%s %d: uh oh\n", __func__, __LINE__);
		goto out_free_pglist;
}

	buf->nr_pages	= nr_pages;
	buf->snapshot	= snapshot;

	kfree(pglist);
	return buf;

out_free_pglist:
	kfree(pglist);
out_free_buf:
	kfree(buf);
	return NULL;
}

static void arm_spe_pmu_free_aux(void *aux)
{
	struct arm_spe_pmu_buf *buf = aux;
pr_err("%s %d: entry\n", __func__, __LINE__);

	vunmap(buf->base);
	kfree(buf);
}

/* Initialisation and teardown functions */
static int arm_spe_pmu_perf_init(struct arm_spe_pmu *spe_pmu)
{
	static atomic_t pmu_idx = ATOMIC_INIT(-1);

	int idx;
	char *name;
	struct device *dev = &spe_pmu->pdev->dev;

pr_err("%s %d: entry\n", __func__, __LINE__);
	spe_pmu->pmu = (struct pmu) {
		.capabilities	= PERF_PMU_CAP_EXCLUSIVE | PERF_PMU_CAP_ITRACE,
		.attr_groups	= arm_spe_pmu_attr_groups,
		/*
		 * We hitch a ride on the software context here, so that
		 * we can support per-task profiling (which is not possible
		 * with the invalid context as it doesn't get sched callbacks).
		 * This requires that userspace either uses a dummy event for
		 * perf_event_open, since the aux buffer is not setup until
		 * a subsequent mmap, or creates the profiling event in a
		 * disabled state and explicitly PERF_EVENT_IOC_ENABLEs it
		 * once the buffer has been created.
		 */
		.task_ctx_nr	= perf_sw_context,
		.event_init	= arm_spe_pmu_event_init,
		.add		= arm_spe_pmu_add,
		.del		= arm_spe_pmu_del,
		.start		= arm_spe_pmu_start,
		.stop		= arm_spe_pmu_stop,
		.read		= arm_spe_pmu_read,
		.setup_aux	= arm_spe_pmu_setup_aux,
		.free_aux	= arm_spe_pmu_free_aux,
	};

	idx = atomic_inc_return(&pmu_idx);
	name = devm_kasprintf(dev, GFP_KERNEL, "%s_%d", PMUNAME, idx);
	return perf_pmu_register(&spe_pmu->pmu, name, -1);
}

static void arm_spe_pmu_perf_destroy(struct arm_spe_pmu *spe_pmu)
{
	perf_pmu_unregister(&spe_pmu->pmu);
}

static void __arm_spe_pmu_dev_probe(void *info)
{
	int fld;
	u64 reg;
	struct arm_spe_pmu *spe_pmu = info;
	struct device *dev = &spe_pmu->pdev->dev;

	fld = cpuid_feature_extract_unsigned_field(read_cpuid(ID_AA64DFR0_EL1),
						   ID_AA64DFR0_PMSVER_SHIFT);
	if (!fld) {
		dev_err(dev,
			"unsupported ID_AA64DFR0_EL1.PMSVer [%d] on CPU %d\n",
			fld, smp_processor_id());
		return;
	}

	/* Read PMBIDR first to determine whether or not we have access */
	reg = read_sysreg_s(PMBIDR_EL1);
	if (reg & BIT(PMBIDR_EL1_P_SHIFT)) {
		dev_err(dev,
			"profiling buffer owned by higher exception level\n");
		return;
	}

	/* Minimum alignment. If it's out-of-range, then fail the probe */
	fld = reg >> PMBIDR_EL1_ALIGN_SHIFT & PMBIDR_EL1_ALIGN_MASK;
	spe_pmu->align = 1 << fld;
	if (spe_pmu->align > SZ_2K) {
		dev_err(dev, "unsupported PMBIDR.Align [%d] on CPU %d\n",
			fld, smp_processor_id());
		return;
	}

	/* It's now safe to read PMSIDR and figure out what we've got */
	reg = read_sysreg_s(PMSIDR_EL1);
	if (reg & BIT(PMSIDR_EL1_FE_SHIFT))
		spe_pmu->features |= SPE_PMU_FEAT_FILT_EVT;

	if (reg & BIT(PMSIDR_EL1_FT_SHIFT))
		spe_pmu->features |= SPE_PMU_FEAT_FILT_TYP;

	if (reg & BIT(PMSIDR_EL1_FL_SHIFT))
		spe_pmu->features |= SPE_PMU_FEAT_FILT_LAT;

	if (reg & BIT(PMSIDR_EL1_ARCHINST_SHIFT))
		spe_pmu->features |= SPE_PMU_FEAT_ARCH_INST;

	if (reg & BIT(PMSIDR_EL1_LDS_SHIFT))
		spe_pmu->features |= SPE_PMU_FEAT_LDS;

	if (reg & BIT(PMSIDR_EL1_ERND_SHIFT))
		spe_pmu->features |= SPE_PMU_FEAT_ERND;

	/* This field has a spaced out encoding, so just use a look-up */
	fld = reg >> PMSIDR_EL1_INTERVAL_SHIFT & PMSIDR_EL1_INTERVAL_MASK;
	switch (fld) {
	case 0:
		spe_pmu->min_period = 256;
		break;
	case 2:
		spe_pmu->min_period = 512;
		break;
	case 3:
		spe_pmu->min_period = 768;
		break;
	case 4:
		spe_pmu->min_period = 1024;
		break;
	case 5:
		spe_pmu->min_period = 1536;
		break;
	case 6:
		spe_pmu->min_period = 2048;
		break;
	case 7:
		spe_pmu->min_period = 3072;
		break;
	default:
		dev_warn(dev, "unknown PMSIDR_EL1.Interval [%d]; assuming 8\n",
			 fld);
		/* Fallthrough */
	case 8:
		spe_pmu->min_period = 4096;
	}

	/* Maximum record size. If it's out-of-range, then fail the probe */
	fld = reg >> PMSIDR_EL1_MAXSIZE_SHIFT & PMSIDR_EL1_MAXSIZE_MASK;
	spe_pmu->max_record_sz = 1 << fld;
	if (spe_pmu->max_record_sz > SZ_2K || spe_pmu->max_record_sz < 16) {
		dev_err(dev, "unsupported PMSIDR_EL1.MaxSize [%d] on CPU %d\n",
			fld, smp_processor_id());
		return;
	}

	fld = reg >> PMSIDR_EL1_COUNTSIZE_SHIFT & PMSIDR_EL1_COUNTSIZE_MASK;
	switch (fld) {
	default:
		dev_warn(dev, "unknown PMSIDR_EL1.CountSize [%d]; assuming 2\n",
			 fld);
		/* Fallthrough */
	case 2:
		spe_pmu->cnt_width = 12;
	}

	dev_info(dev,
		 "probed for CPUs %*pbl [max_record_sz %u, align %u, features 0x%llx]\n",
		 cpumask_pr_args(&spe_pmu->supported_cpus),
		 spe_pmu->max_record_sz, spe_pmu->align, spe_pmu->features);

	spe_pmu->features |= SPE_PMU_FEAT_DEV_PROBED;
	return;
}

static void __arm_spe_pmu_reset_local(void)
{
	/*
	 * This is probably overkill, as we have no idea where we're
	 * draining any buffered data to...
	 */
	arm_spe_pmu_disable_and_drain_local();

	/* Reset the buffer base pointer */
	write_sysreg_s(0, PMBPTR_EL1);
	isb();

	/* Clear any pending management interrupts */
	write_sysreg_s(0, PMBSR_EL1);
	isb();
}

static void __arm_spe_pmu_setup_one(void *info)
{
	struct arm_spe_pmu *spe_pmu = info;

	__arm_spe_pmu_reset_local();
	enable_percpu_irq(spe_pmu->irq, IRQ_TYPE_NONE);
}

static void __arm_spe_pmu_stop_one(void *info)
{
	struct arm_spe_pmu *spe_pmu = info;

	disable_percpu_irq(spe_pmu->irq);
	__arm_spe_pmu_reset_local();
}

static int arm_spe_pmu_cpu_startup(unsigned int cpu, struct hlist_node *node)
{
	struct arm_spe_pmu *spe_pmu;

	spe_pmu = hlist_entry_safe(node, struct arm_spe_pmu, hotplug_node);
	if (!cpumask_test_cpu(cpu, &spe_pmu->supported_cpus))
		return 0;

	__arm_spe_pmu_setup_one(spe_pmu);
	return 0;
}

static int arm_spe_pmu_cpu_teardown(unsigned int cpu, struct hlist_node *node)
{
	struct arm_spe_pmu *spe_pmu;

	pr_err("%s %d: entry\n", __func__, __LINE__);

	spe_pmu = hlist_entry_safe(node, struct arm_spe_pmu, hotplug_node);
	if (!cpumask_test_cpu(cpu, &spe_pmu->supported_cpus))
		return 0;

	__arm_spe_pmu_stop_one(spe_pmu);
	return 0;
}

static int arm_spe_pmu_dev_init(struct arm_spe_pmu *spe_pmu)
{
	int ret;
	cpumask_t *mask = &spe_pmu->supported_cpus;

	pr_err("%s %d: entry\n", __func__, __LINE__);

	/* Keep the hotplug state steady whilst we probe */
	get_online_cpus();

	/* Make sure we probe the hardware on a relevant CPU */
	ret = smp_call_function_any(mask,  __arm_spe_pmu_dev_probe, spe_pmu, 1);
	if (ret || !(spe_pmu->features & SPE_PMU_FEAT_DEV_PROBED)) {
		ret = -ENXIO;
		goto out_put_cpus;
	}

	/* Request our PPIs (note that the IRQ is still disabled) */
	ret = request_percpu_irq(spe_pmu->irq, arm_spe_pmu_irq_handler, DRVNAME,
				 spe_pmu->handle);
	if (ret)
		goto out_put_cpus;

	/* Setup the CPUs in our mask -- this enables the IRQ */
	on_each_cpu_mask(mask, __arm_spe_pmu_setup_one, spe_pmu, 1);

	/* Register our hotplug notifier now so we don't miss any events */
	ret = cpuhp_state_add_instance_nocalls(arm_spe_pmu_online,
					       &spe_pmu->hotplug_node);
out_put_cpus:
	put_online_cpus();
	return ret;
}

/* Driver and device probing */
static int arm_spe_pmu_irq_probe(struct arm_spe_pmu *spe_pmu)
{
	struct platform_device *pdev = spe_pmu->pdev;
	int irq = platform_get_irq(pdev, 0);

	if (irq < 0) {
		dev_err(&pdev->dev, "failed to get IRQ (%d)\n", irq);
		return -ENXIO;
	}

	if (!irq_is_percpu(irq)) {
		dev_err(&pdev->dev, "expected PPI but got SPI (%d)\n", irq);
		return -EINVAL;
	}

	if (irq_get_percpu_devid_partition(irq, &spe_pmu->supported_cpus)) {
		dev_err(&pdev->dev, "failed to get PPI partition (%d)\n", irq);
		return -EINVAL;
	}

	spe_pmu->irq = irq;
	return 0;
}

static const struct of_device_id arm_spe_pmu_of_match[] = {
	{ .compatible = "arm,statistical-profiling-extension-v1", .data = (void *)1 },
};

static int arm_spe_pmu_device_dt_probe(struct platform_device *pdev)
{
	int ret;
	struct arm_spe_pmu *spe_pmu;
	struct device *dev = &pdev->dev;

	pr_err("%s %d: entry\n", __func__, __LINE__);

	spe_pmu = devm_kzalloc(dev, sizeof(*spe_pmu), GFP_KERNEL);
	if (!spe_pmu) {
		dev_err(dev, "failed to allocate spe_pmu\n");
		return -ENOMEM;
	}

	spe_pmu->handle = alloc_percpu(typeof(*spe_pmu->handle));
	if (!spe_pmu->handle)
		return -ENOMEM;

	spe_pmu->pdev = pdev;
	platform_set_drvdata(pdev, spe_pmu);

	ret = arm_spe_pmu_irq_probe(spe_pmu);
	if (ret)
		goto out_free_handle;

	ret = arm_spe_pmu_dev_init(spe_pmu);
	if (ret)
		goto out_free_handle;

	ret = arm_spe_pmu_perf_init(spe_pmu);
	if (ret)
		goto out_free_handle;

	pr_err("%s %d: successful exit\n", __func__, __LINE__);
	return 0;

out_free_handle:
	free_percpu(spe_pmu->handle);
	return ret;
}

static int arm_spe_pmu_device_remove(struct platform_device *pdev)
{
	struct arm_spe_pmu *spe_pmu = platform_get_drvdata(pdev);
	cpumask_t *mask = &spe_pmu->supported_cpus;

	pr_err("%s %d: entry\n", __func__, __LINE__);

	arm_spe_pmu_perf_destroy(spe_pmu);

	get_online_cpus();
	cpuhp_state_remove_instance_nocalls(arm_spe_pmu_online,
					    &spe_pmu->hotplug_node);
	on_each_cpu_mask(mask, __arm_spe_pmu_stop_one, spe_pmu, 1);
	free_percpu_irq(spe_pmu->irq, spe_pmu->handle);
	free_percpu(spe_pmu->handle);
	put_online_cpus();

	pr_err("%s %d: successful exit\n", __func__, __LINE__);

	return 0;
}

static struct platform_driver arm_spe_pmu_driver = {
	.driver	= {
		.name		= DRVNAME,
		.of_match_table	= of_match_ptr(arm_spe_pmu_of_match),
	},
	.probe	= arm_spe_pmu_device_dt_probe,
	.remove	= arm_spe_pmu_device_remove,
};

static int __init arm_spe_pmu_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN, DRVNAME,
				      arm_spe_pmu_cpu_startup,
				      arm_spe_pmu_cpu_teardown);
	if (ret < 0)
		return ret;
	arm_spe_pmu_online = ret;

	ret = platform_driver_register(&arm_spe_pmu_driver);
	if (ret)
		cpuhp_remove_multi_state(arm_spe_pmu_online);

	return ret;
}

static void __exit arm_spe_pmu_exit(void)
{
	platform_driver_unregister(&arm_spe_pmu_driver);
	cpuhp_remove_multi_state(arm_spe_pmu_online);
}

module_init(arm_spe_pmu_init);
module_exit(arm_spe_pmu_exit);

MODULE_DESCRIPTION("Perf driver for the ARMv8.2 Statistical Profiling Extension");
MODULE_AUTHOR("Will Deacon <will.deacon@arm.com>");
MODULE_LICENSE("GPL v2");
