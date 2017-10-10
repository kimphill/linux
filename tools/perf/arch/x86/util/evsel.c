#include <string.h>

#include <linux/perf_event.h>
#include <linux/err.h>

#include "../../util/evsel.h"

int perf_evsel__suppl_strerror(struct perf_evsel *evsel,
			       struct target *target __maybe_unused,
			       int err, char *msg, size_t size)
{
	switch (err) {
	case EOPNOTSUPP:
		if (evsel->attr.type == PERF_TYPE_HARDWARE)
			return scnprintf(msg, size, "%s",
	"No hardware sampling interrupt available.\n"
	"No APIC? If so then you can boot the kernel with the \"lapic\" boot parameter to force-enable it.");
		break;
	default:
		break;
	}

	return 0;
}
