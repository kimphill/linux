/*
 * Copyright(C) 2015 Linaro Limited. All rights reserved.
 * Author: Mathieu Poirier <mathieu.poirier@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdio.h>
#include <linux/coresight-pmu.h>

#include "../../util/auxtrace.h"
#include "../../util/evlist.h"
#include "../../util/pmu.h"
#include "cs-etm.h"
#include "arm-spe.h"

struct auxtrace_record
*auxtrace_record__init(struct perf_evlist *evlist, int *err)
{
	struct perf_pmu	*cs_etm_pmu, *arm_spe_pmu;
	struct perf_evsel *evsel;
	bool found_etm = false, found_spe = false;
	char arm_spe_pmu_name[sizeof(ARM_SPE_PMU_NAME) + 5 /* dec width of MAX_NR_CPUS + term. */];
	int nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	pr_err("%s %d: nr_cpus %d\n", __func__, __LINE__, nr_cpus);
	//fprintf(stderr, "%s %d: \n", __func__, __LINE__);

	cs_etm_pmu = perf_pmu__find(CORESIGHT_ETM_PMU_NAME);

	do {
		*err = sprintf(arm_spe_pmu_name, "%s_%d", ARM_SPE_PMU_NAME, nr_cpus);
		if (*err < 0) {
			pr_err("sprintf failed\n");
			*err = -ENOMEM;
			return NULL;
		}

		arm_spe_pmu = perf_pmu__find(arm_spe_pmu_name);
		if (arm_spe_pmu)
			break;
	} while (nr_cpus--);

	if (!arm_spe_pmu) {
		pr_err("%s %d: spe NOT found, searched nr_cpus arm_spe_X instances\n", __func__, __LINE__);
//		arm_spe_pmu = perf_pmu__find(ARM_SPE_PMU_NAME);
		*err = 0;
		return NULL;
	}

	pr_err("%s %d: arm_spe_pmu %p  type 0x%x\n", __func__, __LINE__,
		arm_spe_pmu, arm_spe_pmu ? arm_spe_pmu->type : 0xdeadbeef);

	if (evlist) {
		evlist__for_each_entry(evlist, evsel) {
			const char *evname = perf_evsel__name(evsel);

			pr_err("%s %d: evname %s   evsel->attr.type %d arm_spe_pmu %p ?->type %d\n",
				 __func__, __LINE__, evname, evsel->attr.type, arm_spe_pmu, arm_spe_pmu ? arm_spe_pmu->type : 0);
			if (cs_etm_pmu &&
			    evsel->attr.type == cs_etm_pmu->type)
				found_etm = true;
			if (arm_spe_pmu &&
			    evsel->attr.type == arm_spe_pmu->type)
				found_spe = true;
		}
	}

	if (found_etm && found_spe) {
		pr_err("Concurrent ARM Coresight ETM and SPE operation not currently supported\n");
		*err = -EOPNOTSUPP;
		return NULL;
	}

	if (found_etm)
		return cs_etm_record_init(err);

	if (found_spe) {
		pr_err("%s %d: spe found, arm_spe_pmu_name %s\n", __func__, __LINE__, arm_spe_pmu_name);
		return arm_spe_recording_init(err, arm_spe_pmu);
	} else
		pr_err("%s %d: spe NOT found, darn it!\n", __func__, __LINE__);

	/*
	 * Clear 'err' even if we haven't found an event - that way perf
	 * record can still be used even if tracers aren't present.  The NULL
	 * return value will take care of telling the infrastructure HW tracing
	 * isn't available.
	 */
	*err = 0;
	return NULL;
}
