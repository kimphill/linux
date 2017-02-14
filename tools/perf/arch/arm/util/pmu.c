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

#include <string.h>
#include <linux/coresight-pmu.h>
#include <linux/perf_event.h>

#include "cs-etm.h"
#include "../../util/pmu.h"
#include "../../util/arm-spe.h"

int arm_spe_set_drv_config(struct perf_evsel_config_term *term __maybe_unused);

int arm_spe_set_drv_config(struct perf_evsel_config_term *term __maybe_unused)
{
	fprintf(stderr, "%s %d: not implemented\n", __func__, __LINE__);

	return 0;
}

struct perf_event_attr
*perf_pmu__get_default_config(struct perf_pmu *pmu __maybe_unused)
{
#ifdef HAVE_AUXTRACE_SUPPORT
	if (!strcmp(pmu->name, CORESIGHT_ETM_PMU_NAME)) {
		/* add ETM default config here */
		pmu->selectable = true;
		pmu->set_drv_config = cs_etm_set_drv_config;
	}
	if (!strcmp(pmu->name, ARM_SPE_PMU_NAME)) {
		/* add SPE default config here */
		pmu->selectable = true;
		pmu->set_drv_config = arm_spe_set_drv_config;
	}
#endif
	return NULL;
}
