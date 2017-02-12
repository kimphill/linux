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

	pr_err("%s %d: \n", __func__, __LINE__);
	
	cs_etm_pmu = perf_pmu__find(CORESIGHT_ETM_PMU_NAME);
	arm_spe_pmu = perf_pmu__find(ARM_SPE_PMU_NAME);

	pr_err("%s %d: cs_etm_pmu %p\n", __func__, __LINE__, cs_etm_pmu);
	pr_err("%s %d: arm_spe_pmu %p\n", __func__, __LINE__, arm_spe_pmu);
	if (evlist) {
		evlist__for_each_entry(evlist, evsel) {
			pr_err("%s %d: \n", __func__, __LINE__);
			if (cs_etm_pmu &&
			    evsel->attr.type == cs_etm_pmu->type)
				found_etm = true;
			if (arm_spe_pmu &&
			    evsel->attr.type == arm_spe_pmu->type)
				found_spe = true;
		}
	}


	pr_err("%s %d: \n", __func__, __LINE__);
	if (found_etm && found_spe) {
		pr_err("ARM Coresight ETM and SPE may not be used together\n");
		*err = -EINVAL;
		return NULL;
	}

	pr_err("%s %d: \n", __func__, __LINE__);
	if (found_etm)
		return cs_etm_record_init(err);

	pr_err("%s %d: \n", __func__, __LINE__);
	if (found_spe)
		return arm_spe_recording_init(err);

	pr_err("%s %d: \n", __func__, __LINE__);
	/*
	 * Clear 'err' even if we haven't found a cs_etm event - that way perf
	 * record can still be used even if tracers aren't present.  The NULL
	 * return value will take care of telling the infrastructure HW tracing
	 * isn't available.
	 */
	*err = 0;
	return NULL;
}
