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
	case EOPNOTSUPP:
		if (attr->sample_period)
			return scnprintf(msg, size, "%s: Sampling not supported, try 'perf stat'\n", evname);
		if (target__has_task(target)) //target->cpu < 0)
			return scnprintf(msg, size, "%s: Can't provide per-task data!\n", evname);
		break;
	case EINVAL:
		/* we never see the below because the fallback gets called on the exclude_guest being set, and if that didn't work, we just get:


perf/perf stat -e ccn/rni_rdata_beats_p0,node=3/ sleep 1

 Performance counter stats for 'system wide':

   <not supported>      ccn/rni_rdata_beats_p0,node=3/                                   

       1.003762498 seconds time elapsed

show how doc example fails:

invalid or unsupported event: 'ccn/cycles/,ccn/xp_valid_flit,xp=1,port=0,vc=1,dir=1/'

*/
		if ((attr->sample_type & PERF_SAMPLE_BRANCH_STACK) ||
			attr->exclude_user ||
			attr->exclude_kernel || attr->exclude_hv ||
			attr->exclude_idle || attr->exclude_host ||
			attr->exclude_guest)
			return scnprintf(msg, size, "%s: Can't exclude execution levels!\n", evname);
		/* we never see the below */
		return scnprintf(msg, size,
	"%s: Invalid MN / XP / node ID, or node type, or node/XP port / vc or event, or mixed PMU group. See dmesg for details\n", evname);
		break;
	default:
		break;
	}

	return 0;
}

int perf_evsel__suppl_strerror(struct perf_evsel *evsel,
			       struct target *target __maybe_unused,
			       int err, char *msg, size_t size)
{

	const char *evname = perf_evsel__name(evsel);

	if (strstarts(evname, "ccn"))
		return ccn_strerror(evsel, target, err, msg, size);

	return 0;
}
