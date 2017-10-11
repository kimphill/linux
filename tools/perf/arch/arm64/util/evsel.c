#include <string.h>

#include <linux/perf_event.h>
#include <linux/err.h>

#include "../../util/evsel.h"

#include "evsel.h"

#if 0 //def AUXTRACE??
+               if (!strncmp(perf_evsel__name(evsel), "arm_spe", sizeof("arm_spe"))) {
+                       if (evsel->attr.sample_period != 0)
+                               return scnprintf(msg, size, "required sample period missing.  Use -c <n>");
+                       else
+                               return scnprintf(msg, size,
+       "Bad sample period %d.  SPE requires one of: 256, 512, 768, 1024, 1536, 2048, 3072, 4096.\n",
+                                               evsel->attr.sample_period);
#endif


int ccn_strerror(struct perf_evsel *evsel,
		 struct target *target __maybe_unused,
		 int err, char *msg, size_t size)
{
	struct perf_event_attr *attr = &evsel->attr;

	switch (err) {
	case EOPNOTSUPP:
		if (attr->sample_period)
			return scnprintf(msg, size, "Sampling not supported!\n");
		if (target->per_thread)
			return scnprintf(msg, size, "Can't provide per-task data!\n");
		break;
	case EINVAL:
		if (//(attr->sample_type & PERF_SAMPLE_BRANCH_STACK) ||
			attr->exclude_user ||
			attr->exclude_kernel || attr->exclude_hv ||
			attr->exclude_idle || attr->exclude_host ||
			attr->exclude_guest)
			return scnprintf(msg, size, "Can't exclude execution levels!\n");
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

	if (strstarts(evname, "ccn/"))
		return ccn_strerror(evsel, target, err, msg, size);

	return 0;
}
