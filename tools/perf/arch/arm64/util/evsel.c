#include <string.h>

#include <linux/perf_event.h>
#include <linux/err.h>

#include "../../util/evsel.h"

#include "evsel.h"

static int ccn_strerror(struct perf_evsel *evsel,
			struct target *target __maybe_unused,
			int err, char *msg, size_t size)
{
	const char *evname = perf_evsel__name(evsel);
	struct perf_event_attr *attr = &evsel->attr;

	switch (err) {
#if 1 /* generic handles instead */
	case EOPNOTSUPP:
#if 0 /* generic handles instead */
		if (attr->sample_period)
			return scnprintf(msg, size, "%s: MAKEMEGENERIC: Sampling not supported, try 'perf stat'\n", evname);
#endif
#if 1 /* driver version (cpu < 0) doesn't occur IRL anymore (since systemwide -a by default commit) */
		//if (target__has_task(target))
	//	if (!target__has_cpu(target))
			return scnprintf(msg, size, 
	"%s: UNCONDITIONALEOPNOTSUPP: MAKEMEGENERIC: Can't provide per-task data!\n"
	"%s: MAKEMEGENERIC: target: pid %p tid %p cpu_list %p uid_str %p system_wide %d uses_mmap %d default_per_cpu %d per_thread %d\n"
	"%s: MAKEMEGENERIC: target: has_task %d  has_cpu %d  none %d  uses_dummy_map %d\n"
, evname,
evname,
target->pid, target->tid, target->cpu_list, target->uid_str, target->system_wide, target->uses_mmap, target->default_per_cpu, target->per_thread,
evname,
target__has_task(target), target__has_cpu(target), target__none(target)
);
#endif
		break;
#endif
	case EINVAL:
		if ((attr->sample_type & PERF_SAMPLE_BRANCH_STACK) ||
		    attr->exclude_user || attr->exclude_kernel ||
		    attr->exclude_hv || attr->exclude_idle ||
		    attr->exclude_host || attr->exclude_guest)
			return scnprintf(msg, size, "%s: TRYANDMAKEMEGENERIC: Can't exclude execution levels!\n"
	"%s: MAKEMEGENERIC: target: pid %p tid %p cpu_list %p uid_str %p system_wide %d uses_mmap %d default_per_cpu %d per_thread %d\n"
	"%s: MAKEMEGENERIC: target: has_task %d  has_cpu %d  none %d  uses_dummy_map %d\n"
, evname,
evname,
target->pid, target->tid, target->cpu_list, target->uid_str, target->system_wide, target->uses_mmap, target->default_per_cpu, target->per_thread,
evname,
target__has_task(target), target__has_cpu(target), target__none(target)
);

		return scnprintf(msg, size,
	"%s: Invalid MN / XP / node ID, or node type, or node/XP port / vc or event, or mixed PMU group. See dmesg for details\n"
	"%s: MAKEMEGENERIC: target: pid %p tid %p cpu_list %p uid_str %p system_wide %d uses_mmap %d default_per_cpu %d per_thread %d\n"
	"%s: MAKEMEGENERIC: target: has_task %d  has_cpu %d  none %d  uses_dummy_map %d\n"
, evname,
evname,
target->pid, target->tid, target->cpu_list, target->uid_str, target->system_wide, target->uses_mmap, target->default_per_cpu, target->per_thread,
evname,
target__has_task(target), target__has_cpu(target), target__none(target)
);
		break;
	default:
		break;
	}

	return 0;
}

int perf_evsel__open_strerror_arch(struct perf_evsel *evsel,
				   struct target *target,
				   int err, char *msg, size_t size)
{

	const char *evname = perf_evsel__name(evsel);

	if (strstarts(evname, "ccn"))
		return ccn_strerror(evsel, target, err, msg, size);

	return 0;
}
