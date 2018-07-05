// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(C) 2015 Linaro Limited. All rights reserved.
 * Author: Mathieu Poirier <mathieu.poirier@linaro.org>
 */

#include <linux/coresight.h>
#include <linux/coresight-pmu.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/parser.h>
#include <linux/perf_event.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "coresight-etm-perf.h"
#include "coresight-priv.h"

static struct pmu etm_pmu;
static bool etm_perf_up;

#define CORESIGHT_DEVICE_MAX_NAME_LEN	256

/**
 * struct etm_event_data - Coresight specifics associated to an event
 * @work:		Handle to free allocated memory outside IRQ context.
 * @mask:		Hold the CPU(s) this event was set for.
 * @snk_config:		The sink configuration.
 * @path:		An array of path, each slot for one CPU.
 */
struct etm_event_data {
	struct work_struct work;
	cpumask_t mask;
	void *snk_config;
	struct list_head **path;
};

static DEFINE_PER_CPU(struct perf_output_handle, ctx_handle);
static DEFINE_PER_CPU(struct coresight_device *, csdev_src);

/* ETMv3.5/PTM's ETMCR is 'config' */
PMU_FORMAT_ATTR(cycacc,		"config:" __stringify(ETM_OPT_CYCACC));
PMU_FORMAT_ATTR(timestamp,	"config:" __stringify(ETM_OPT_TS));
PMU_FORMAT_ATTR(retstack,	"config:" __stringify(ETM_OPT_RETSTK));

static struct attribute *etm_config_formats_attr[] = {
	&format_attr_cycacc.attr,
	&format_attr_timestamp.attr,
	&format_attr_retstack.attr,
	NULL,
};

static const struct attribute_group etm_pmu_format_group = {
	.name   = "format",
	.attrs  = etm_config_formats_attr,
};

static const struct attribute_group *etm_pmu_attr_groups[] = {
	&etm_pmu_format_group,
	NULL,
};

static void etm_event_read(struct perf_event *event) {}

static int etm_addr_filters_alloc(struct perf_event *event)
{
	struct etm_filters *filters;
	int node = event->cpu == -1 ? -1 : cpu_to_node(event->cpu);

	filters = kzalloc_node(sizeof(struct etm_filters), GFP_KERNEL, node);
	if (!filters)
		return -ENOMEM;

	if (event->parent)
		memcpy(filters, event->parent->hw.addr_filters,
		       sizeof(*filters));

	event->hw.addr_filters = filters;

	return 0;
}

static void etm_event_destroy(struct perf_event *event)
{
	kfree(event->hw.addr_filters);
	event->hw.addr_filters = NULL;
}

static int etm_event_init(struct perf_event *event)
{
	int ret = 0;

	if (event->attr.type != etm_pmu.type) {
		ret = -ENOENT;
		goto out;
	}

	ret = etm_addr_filters_alloc(event);
	if (ret)
		goto out;

	event->destroy = etm_event_destroy;
out:
	return ret;
}

static void free_event_data(struct work_struct *work)
{
	int cpu;
	cpumask_t *mask;
	struct etm_event_data *event_data;
	struct coresight_device *sink;

	event_data = container_of(work, struct etm_event_data, work);
	mask = &event_data->mask;
	/*
	 * First deal with the sink configuration.  See comment in
	 * etm_setup_aux() about why we take the first available path.
	 */
	if (event_data->snk_config) {
		cpu = cpumask_first(mask);
		sink = coresight_get_sink(event_data->path[cpu]);
		if (sink_ops(sink)->free_buffer)
			sink_ops(sink)->free_buffer(event_data->snk_config);
	}

	for_each_cpu(cpu, mask) {
		if (!(IS_ERR_OR_NULL(event_data->path[cpu])))
			coresight_release_path(event_data->path[cpu]);
	}

	kfree(event_data->path);
	kfree(event_data);
}

static void *alloc_event_data(int cpu)
{
	int size;
	cpumask_t *mask;
	struct etm_event_data *event_data;

	/* First get memory for the session's data */
	event_data = kzalloc(sizeof(struct etm_event_data), GFP_KERNEL);
	if (!event_data)
		return NULL;

	/* Make sure nothing disappears under us */
	get_online_cpus();
	size = num_online_cpus();

	mask = &event_data->mask;
	if (cpu != -1)
		cpumask_set_cpu(cpu, mask);
	else
		cpumask_copy(mask, cpu_online_mask);
	put_online_cpus();

	/*
	 * Each CPU has a single path between source and destination.  As such
	 * allocate an array using CPU numbers as indexes.  That way a path
	 * for any CPU can easily be accessed at any given time.  We proceed
	 * the same way for sessions involving a single CPU.  The cost of
	 * unused memory when dealing with single CPU trace scenarios is small
	 * compared to the cost of searching through an optimized array.
	 */
	event_data->path = kcalloc(size,
				   sizeof(struct list_head *), GFP_KERNEL);
	if (!event_data->path) {
		kfree(event_data);
		return NULL;
	}

	return event_data;
}

static void etm_free_aux(void *data)
{
	struct etm_event_data *event_data = data;

	schedule_work(&event_data->work);
}

static char *etm_drv_config_sync(struct perf_event *event)
{
	char *sink;
	int node = event->cpu == -1 ? -1 : cpu_to_node(event->cpu);
	struct pmu_drv_config *drv_config = perf_event_get_drv_config(event);

	sink = kmalloc_node(CORESIGHT_DEVICE_MAX_NAME_LEN, GFP_KERNEL, node);
	if (!sink)
		return NULL;

	/*
	 * Make sure we don't race with perf_drv_config_replace() in
	 * kernel/events/core.c.
	 */
	raw_spin_lock(&drv_config->lock);
	memcpy(sink, drv_config->config, CORESIGHT_DEVICE_MAX_NAME_LEN);
	raw_spin_unlock(&drv_config->lock);

	return sink;
}

static struct coresight_device *etm_event_get_sink(struct perf_event *event)
{
	struct pmu_drv_config *drv_config = perf_event_get_drv_config(event);

	/*
	 * Try the preferred method first, i.e getting the sink information
	 * using the ioctl() method.
	 */
	if (drv_config->config) {
		char *drv_config;
		struct device *dev;
		struct coresight_device *sink;

		/*
		 * Get sink from event->hw.drv_config.config - see
		 * _perf_ioctl() _SET_DRV_CONFIG.
		 */
		drv_config = etm_drv_config_sync(event);
		if (!drv_config)
			goto out;

		/* Look for the device of that name on the CS bus. */
		dev = bus_find_device_by_name(&coresight_bustype, NULL,
					      drv_config);
		kfree(drv_config);

		if (dev) {
			sink = to_coresight_device(dev);
			/* Put reference from 'bus_find_device()' */
			put_device(dev);
			return sink;
		}
	}

	/*
	 * No luck with the above method, so we are working with an older user
	 * space.  See if a sink has been set using sysFS.  If this is the case
	 * CPU-wide session will only be able to use a single sink.
	 *
	 * When operated from sysFS users are responsible to enable the sink
	 * while from perf, the perf tools will do it based on the choice made
	 * on the cmd line.  As such the "enable_sink" flag in sysFS is reset.
	 */
out:
	return coresight_get_enabled_sink(true);
}

static void *etm_setup_aux(struct perf_event *event, void **pages,
			   int nr_pages, bool overwrite)
{
	int cpu = event->cpu;
	cpumask_t *mask;
	struct coresight_device *sink;
	struct etm_event_data *event_data = NULL;

	event_data = alloc_event_data(cpu);
	if (!event_data)
		return NULL;
	INIT_WORK(&event_data->work, free_event_data);

	/* First get the sink to use for this event */
	sink = etm_event_get_sink(event);
	if (!sink)
		goto err;

	mask = &event_data->mask;

	/* Setup the path for each CPU in a trace session */
	for_each_cpu(cpu, mask) {
		struct coresight_device *csdev;

		csdev = per_cpu(csdev_src, cpu);
		if (!csdev)
			goto err;

		/*
		 * Building a path doesn't enable it, it simply builds a
		 * list of devices from source to sink that can be
		 * referenced later when the path is actually needed.
		 */
		event_data->path[cpu] = coresight_build_path(csdev, sink);
		if (IS_ERR(event_data->path[cpu]))
			goto err;
	}

	if (!sink_ops(sink)->alloc_buffer)
		goto err;

	cpu = cpumask_first(mask);
	/* Get the AUX specific data from the sink buffer */
	event_data->snk_config =
			sink_ops(sink)->alloc_buffer(sink, cpu, pages,
						     nr_pages, overwrite);
	if (!event_data->snk_config)
		goto err;

out:
	return event_data;

err:
	etm_free_aux(event_data);
	event_data = NULL;
	goto out;
}

static void etm_event_start(struct perf_event *event, int flags)
{
	int cpu = smp_processor_id();
	struct etm_event_data *event_data;
	struct perf_output_handle *handle = this_cpu_ptr(&ctx_handle);
	struct coresight_device *sink, *csdev = per_cpu(csdev_src, cpu);

	if (!csdev)
		goto fail;

	/*
	 * Deal with the ring buffer API and get a handle on the
	 * session's information.
	 */
	event_data = perf_aux_output_begin(handle, event);
	if (!event_data)
		goto fail;

	/* We need a sink, no need to continue without one */
	sink = coresight_get_sink(event_data->path[cpu]);
	if (WARN_ON_ONCE(!sink || !sink_ops(sink)->set_buffer))
		goto fail_end_stop;

	/* Configure the sink */
	if (sink_ops(sink)->set_buffer(sink, handle,
				       event_data->snk_config))
		goto fail_end_stop;

	/* Nothing will happen without a path */
	if (coresight_enable_path(event_data->path[cpu], CS_MODE_PERF))
		goto fail_end_stop;

	/* Tell the perf core the event is alive */
	event->hw.state = 0;

	/* Finally enable the tracer */
	if (source_ops(csdev)->enable(csdev, event, CS_MODE_PERF))
		goto fail_end_stop;

out:
	return;

fail_end_stop:
	perf_aux_output_flag(handle, PERF_AUX_FLAG_TRUNCATED);
	perf_aux_output_end(handle, 0);
fail:
	event->hw.state = PERF_HES_STOPPED;
	goto out;
}

static void etm_event_stop(struct perf_event *event, int mode)
{
	int cpu = smp_processor_id();
	unsigned long size;
	struct coresight_device *sink, *csdev = per_cpu(csdev_src, cpu);
	struct perf_output_handle *handle = this_cpu_ptr(&ctx_handle);
	struct etm_event_data *event_data = perf_get_aux(handle);

	if (event->hw.state == PERF_HES_STOPPED)
		return;

	if (!csdev)
		return;

	sink = coresight_get_sink(event_data->path[cpu]);
	if (!sink)
		return;

	/* stop tracer */
	source_ops(csdev)->disable(csdev, event);

	/* tell the core */
	event->hw.state = PERF_HES_STOPPED;

	if (mode & PERF_EF_UPDATE) {
		if (WARN_ON_ONCE(handle->event != event))
			return;

		/* update trace information */
		if (!sink_ops(sink)->update_buffer)
			return;

		sink_ops(sink)->update_buffer(sink, handle,
					      event_data->snk_config);

		if (!sink_ops(sink)->reset_buffer)
			return;

		size = sink_ops(sink)->reset_buffer(sink, handle,
						    event_data->snk_config);

		perf_aux_output_end(handle, size);
	}

	/* Disabling the path make its elements available to other sessions */
	coresight_disable_path(event_data->path[cpu]);
}

static int etm_event_add(struct perf_event *event, int mode)
{
	int ret = 0;
	struct hw_perf_event *hwc = &event->hw;

	if (mode & PERF_EF_START) {
		etm_event_start(event, 0);
		if (hwc->state & PERF_HES_STOPPED)
			ret = -EINVAL;
	} else {
		hwc->state = PERF_HES_STOPPED;
	}

	return ret;
}

static void etm_event_del(struct perf_event *event, int mode)
{
	etm_event_stop(event, PERF_EF_UPDATE);
}

static int etm_addr_filters_validate(struct list_head *filters)
{
	bool range = false, address = false;
	int index = 0;
	struct perf_addr_filter *filter;

	list_for_each_entry(filter, filters, entry) {
		/*
		 * No need to go further if there's no more
		 * room for filters.
		 */
		if (++index > ETM_ADDR_CMP_MAX)
			return -EOPNOTSUPP;

		/* filter::size==0 means single address trigger */
		if (filter->size) {
			/*
			 * The existing code relies on START/STOP filters
			 * being address filters.
			 */
			if (filter->action == PERF_ADDR_FILTER_ACTION_START ||
			    filter->action == PERF_ADDR_FILTER_ACTION_STOP)
				return -EOPNOTSUPP;

			range = true;
		} else
			address = true;

		/*
		 * At this time we don't allow range and start/stop filtering
		 * to cohabitate, they have to be mutually exclusive.
		 */
		if (range && address)
			return -EOPNOTSUPP;
	}

	return 0;
}

static void etm_addr_filters_sync(struct perf_event *event)
{
	struct perf_addr_filters_head *head = perf_event_addr_filters(event);
	unsigned long start, stop, *offs = event->addr_filters_offs;
	struct etm_filters *filters = event->hw.addr_filters;
	struct etm_filter *etm_filter;
	struct perf_addr_filter *filter;
	int i = 0;

	list_for_each_entry(filter, &head->list, entry) {
		start = filter->offset + offs[i];
		stop = start + filter->size;
		etm_filter = &filters->etm_filter[i];

		switch (filter->action) {
		case PERF_ADDR_FILTER_ACTION_FILTER:
			etm_filter->start_addr = start;
			etm_filter->stop_addr = stop;
			etm_filter->type = ETM_ADDR_TYPE_RANGE;
			break;
		case PERF_ADDR_FILTER_ACTION_START:
			etm_filter->start_addr = start;
			etm_filter->type = ETM_ADDR_TYPE_START;
			break;
		case PERF_ADDR_FILTER_ACTION_STOP:
			etm_filter->stop_addr = stop;
			etm_filter->type = ETM_ADDR_TYPE_STOP;
			break;
		}
		i++;
	}

	filters->nr_filters = i;
}

static const match_table_t config_tokens = {
	{ ETM_CFG_SINK,		"%u.%s" },
	{ ETM_CFG_NONE,		NULL },
};

static void *etm_drv_config_validate(struct perf_event *event, char *cstr)
{
	char *str, *to_parse, *sink = NULL;
	int token, ret = -EINVAL;
	substring_t args[MAX_OPT_ARGS];

	to_parse = kstrdup(cstr, GFP_KERNEL);
	if (!to_parse)
		return ERR_PTR(-ENOMEM);

	while ((str = strsep(&to_parse, " ,\n")) != NULL) {
		if (!*str)
			continue;

		token = match_token(str, config_tokens, args);
		switch (token) {
		case ETM_CFG_SINK:
			sink = kstrdup(str, GFP_KERNEL);
			if (!sink) {
				ret = -ENOMEM;
				goto out;
			}
			break;
		default:
			goto out;
		}
	}

out:
	kfree(to_parse);
	return sink ? sink : ERR_PTR(ret);
}

static void etm_drv_config_free(void *drv_data)
{
	kfree(drv_data);
}

int etm_perf_symlink(struct coresight_device *csdev, bool link)
{
	char entry[sizeof("cpu9999999")];
	int ret = 0, cpu = source_ops(csdev)->cpu_id(csdev);
	struct device *pmu_dev = etm_pmu.dev;
	struct device *cs_dev = &csdev->dev;

	sprintf(entry, "cpu%d", cpu);

	if (!etm_perf_up)
		return -EPROBE_DEFER;

	if (link) {
		ret = sysfs_create_link(&pmu_dev->kobj, &cs_dev->kobj, entry);
		if (ret)
			return ret;
		per_cpu(csdev_src, cpu) = csdev;
	} else {
		sysfs_remove_link(&pmu_dev->kobj, entry);
		per_cpu(csdev_src, cpu) = NULL;
	}

	return 0;
}

static int __init etm_perf_init(void)
{
	int ret;

	etm_pmu.capabilities		= PERF_PMU_CAP_EXCLUSIVE;

	etm_pmu.attr_groups		= etm_pmu_attr_groups;
	etm_pmu.task_ctx_nr		= perf_sw_context;
	etm_pmu.read			= etm_event_read;
	etm_pmu.event_init		= etm_event_init;
	etm_pmu.setup_aux		= etm_setup_aux;
	etm_pmu.free_aux		= etm_free_aux;
	etm_pmu.start			= etm_event_start;
	etm_pmu.stop			= etm_event_stop;
	etm_pmu.add			= etm_event_add;
	etm_pmu.del			= etm_event_del;
	etm_pmu.addr_filters_sync	= etm_addr_filters_sync;
	etm_pmu.addr_filters_validate	= etm_addr_filters_validate;
	etm_pmu.nr_addr_filters		= ETM_ADDR_CMP_MAX;
	etm_pmu.drv_config_validate	= etm_drv_config_validate;
	etm_pmu.drv_config_free		= etm_drv_config_free;

	ret = perf_pmu_register(&etm_pmu, CORESIGHT_ETM_PMU_NAME, -1);
	if (ret == 0)
		etm_perf_up = true;

	return ret;
}
device_initcall(etm_perf_init);
