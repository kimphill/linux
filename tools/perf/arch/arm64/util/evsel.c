#include <string.h>

#include <linux/perf_event.h>
#include <linux/err.h>

#include "../../util/evsel.h"

#include "evsel.h"

static int ccn_strerror(struct perf_evsel *evsel,
			struct target *target __maybe_unused,
			int err, char *msg, size_t size)
{
	struct perf_event_attr *attr = &evsel->attr;

	switch (err) {
	case EOPNOTSUPP:
		if (attr->sample_period)
			return scnprintf(msg, size, "Sampling not supported, try 'perf stat'");
		if (target->per_thread)
			return scnprintf(msg, size, "Can't provide per-task data!\n");
		return scnprintf(msg, size, "*FILL ME IN*\n");
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

#ifdef HAVE_AUXTRACE_SUPPORT
static int arm_spe_strerror(struct perf_evsel *evsel,
			    struct target *target __maybe_unused,
			    int err, char *msg, size_t size)
{
	struct perf_event_attr *attr = &evsel->attr;

	switch (err) {
	case EOPNOTSUPP:
#if 0
	if (!event->hw.sample_period ||
+	    event->hw.sample_period < spe_pmu->min_period) {
+		errorf("%s: no sample period, or less than minimum (%d)\n",
+		       devname, spe_pmu->min_period);
+		return -EOPNOTSUPP;
+	
#endif
#if 0 //def AUXTRACE??
+               if (!strncmp(perf_evsel__name(evsel), "arm_spe", sizeof("arm_spe"))) {
+                       if (evsel->attr.sample_period != 0)
+                               return scnprintf(msg, size, "required sample period missing.  Use -c <n>");
+                       else if sample period not one of the ones supported
+                               return scnprintf(msg, size,
+       "Bad sample period %d.  SPE requires one of: 256, 512, 768, 1024, 1536, 2048, 3072, 4096.\n",
+                                               evsel->attr.sample_period);
#endif


		if (attr->exclude_idle)
			return scnprintf(msg, size, "Cannot exclude profiling when idle, try without //I\n");
		return scnprintf(msg, size, "*FILL ME IN*\n");
		break;
	case EACCES:
		//if (attr->config)
		return scnprintf(msg, size, "pa_enable, pct_enable and cx_enable require admin privileges\n");
	case EINVAL:
		if (!attr->sample_period)
			return scnprintf(msg, size, "required sample period missing.  Use '--count='\n");
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
#endif

int perf_evsel__suppl_strerror(struct perf_evsel *evsel,
			       struct target *target __maybe_unused,
			       int err, char *msg, size_t size)
{

	const char *evname = perf_evsel__name(evsel);

	if (strstarts(evname, "ccn/"))
		return ccn_strerror(evsel, target, err, msg, size);

#ifdef HAVE_AUXTRACE_SUPPORT
	if (strstarts(evname, "arm_spe"))
		return arm_spe_strerror(evsel, target, err, msg, size);
#endif

	return 0;
}
