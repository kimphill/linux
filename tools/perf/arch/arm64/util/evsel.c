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

#ifdef HAVE_AUXTRACE_SUPPORT
static int arm_spe_strerror(struct perf_evsel *evsel,
			    struct target *target __maybe_unused,
			    int err, char *msg, size_t size)
{
	const char *evname = perf_evsel__name(evsel);
	struct perf_event_attr *attr = &evsel->attr;

	pr_warning("%s %d: entered with err %d\n", __func__, __LINE__, err);

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
			return scnprintf(msg, size,
	"%s: Cannot exclude profiling when idle, try without //I\n", evname);
		return scnprintf(msg, size, "%s: unsupported error code:\n"
	"EITHER this driver may not support a possibly h/w-implementation\n"
	"\tdefined event filter bit that has been set in the PMSEVFR register\n"
	"OR h/w doesn't support filtering by one or more of: latency,\n"
	"\toperation type, or events\n", evname);
		break;
	case EACCES:
		if (strstr(evname, "pa_enable") || strstr(evname, "pct_enable"))
			return scnprintf(msg, size,
	"%s: physical address and time, and EL1 context ID data collection\n"
	"\trequire admin privileges\n", evname);
		break;
	case EINVAL:
	pr_err("%s %d: err %d attr->sample_period %llu\n", __func__, __LINE__, err, attr->sample_period);
		if (attr->freq || !attr->sample_period)
			return scnprintf(msg, size,
	"required sample period missing.  Use '--count='\n");
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

	pr_err("%s %d: \n", __func__, __LINE__);
	if (strstarts(evname, "ccn"))
		return ccn_strerror(evsel, target, err, msg, size);

#ifdef HAVE_AUXTRACE_SUPPORT
	if (strstarts(evname, "arm_spe"))
		return arm_spe_strerror(evsel, target, err, msg, size);
#endif

	return 0;
}
