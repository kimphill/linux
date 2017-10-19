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

//is_arm_spe(

struct auxtrace_record
*auxtrace_record__init(struct perf_evlist *evlist, int *err)
{
	struct perf_pmu	*cs_etm_pmu; //, *arm_spe_pmu;
	static struct perf_pmu **arm_spe_pmus;
	struct perf_evsel *evsel;
	const char *evname;
	bool found_etm = false;
	bool found_spe = false;
	char arm_spe_pmu_name[sizeof(ARM_SPE_PMU_NAME) + 5 /* dec width of MAX_NR_CPUS + term. */];
	int i, nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	static int nr_spes = 0;

	pr_err("%s %d: nr_cpus %d\n", __func__, __LINE__, nr_cpus);
	//fprintf(stderr, "%s %d: \n", __func__, __LINE__);

	cs_etm_pmu = perf_pmu__find(CORESIGHT_ETM_PMU_NAME);
	if (!arm_spe_pmus) {
		arm_spe_pmus = zalloc(sizeof(struct perf_pmu *) * nr_cpus);
		if (!arm_spe_pmus) {
			pr_err("spes alloc failed\n");
			*err = -ENOMEM;
			return NULL;
		}

		for (i = 0; i < nr_cpus; i++) {
			*err = sprintf(arm_spe_pmu_name, "%s_%d", ARM_SPE_PMU_NAME, i);
			if (*err < 0) {
				pr_err("sprintf failed\n");
				*err = -ENOMEM;
				return NULL;
			}

			arm_spe_pmus[nr_spes] = perf_pmu__find(arm_spe_pmu_name);
// zalloc(sizeof(struct perf_pmu) * nr_cpus);
//			arm_spe_pmu = perf_pmu__find(arm_spe_pmu_name);


			if (arm_spe_pmus[nr_spes]) {
				pr_err("%s %d: arm_spe_pmu %d type %d name %s\n",
					 __func__, __LINE__, nr_spes,
					 arm_spe_pmus[nr_spes]->type,
					 arm_spe_pmus[nr_spes]->name);
				nr_spes++;
			}
		}
	}

#if 0 // perf_pmu__find(ARM_SPE_PMU_NAME); will never return nonzero pmu, since driver registers first spe as arm_spe_0, so we have to go and look for spe instances
	if (!arm_spe_pmu) {
		pr_err("%s %d: spe NOT found, searched nr_cpus arm_spe_X instances\n", __func__, __LINE__);
//		arm_spe_pmu = perf_pmu__find(ARM_SPE_PMU_NAME);
		*err = 0;
		return NULL;
	}

	pr_err("%s %d: arm_spe_pmu %p  type 0x%x\n", __func__, __LINE__,
		arm_spe_pmu, arm_spe_pmu ? arm_spe_pmu->type : 0xdeadbeef);
#endif
	pr_err("%s %d: nr_spes %d\n", __func__, __LINE__, nr_spes);

	if (evlist) {
		evlist__for_each_entry(evlist, evsel) {
			evname = perf_evsel__name(evsel);

			if (cs_etm_pmu &&
			    evsel->attr.type == cs_etm_pmu->type)
				found_etm = true;

			if (nr_spes)
				for (i = 0; i < nr_spes; i++) {
					pr_err("%s %d: evname %s   evsel->attr.type %d arm_spe_pmu %p ?->type %d  ?->name %s\n",
						 __func__, __LINE__, evname, evsel->attr.type, arm_spe_pmus[i],
						 arm_spe_pmus ? arm_spe_pmus[i]->type : 0,
						 arm_spe_pmus ? arm_spe_pmus[i]->name : "nil");
			    		if (evsel->attr.type == arm_spe_pmus[i]->type) {
						found_spe = true;
						pr_err("%s %d: found_spe %d\n", __func__, __LINE__, found_spe);   
						break;
					}
				}
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
		pr_err("%s %d: spe found, arm_spe_pmu %d\n", __func__, __LINE__, i);
		return arm_spe_recording_init(err, arm_spe_pmus[i]);
	} else
		pr_err("%s %d: spe NOT found for evname %s (nr_spes %d, found_spe %d)\n", __func__, __LINE__, evname, nr_spes, found_spe);

	/*
	 * Clear 'err' even if we haven't found an event - that way perf
	 * record can still be used even if tracers aren't present.  The NULL
	 * return value will take care of telling the infrastructure HW tracing
	 * isn't available.
	 */
	*err = 0;
	return NULL;
}
