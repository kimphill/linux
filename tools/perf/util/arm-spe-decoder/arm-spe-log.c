/*
 * arm_spe_log.c: Intel Processor Trace support
 * Copyright (c) 2013-2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include "arm-spe-log.h"
#include "arm-spe-insn-decoder.h"

#include "arm-spe-pkt-decoder.h"

#define MAX_LOG_NAME 256

static FILE *f;
static char log_name[MAX_LOG_NAME];
bool arm_spe_enable_logging;

void arm_spe_log_enable(void)
{
	arm_spe_enable_logging = true;
}

void arm_spe_log_disable(void)
{
	if (f)
		fflush(f);
	arm_spe_enable_logging = false;
}

void arm_spe_log_set_name(const char *name)
{
	strncpy(log_name, name, MAX_LOG_NAME - 5);
	strcat(log_name, ".log");
}

static void arm_spe_print_data(const unsigned char *buf, int len, uint64_t pos,
				int indent)
{
	int i;

	for (i = 0; i < indent; i++)
		fprintf(f, " ");

	fprintf(f, "  %08" PRIx64 ": ", pos);
	for (i = 0; i < len; i++)
		fprintf(f, " %02x", buf[i]);
	for (; i < 16; i++)
		fprintf(f, "   ");
	fprintf(f, " ");
}

static void arm_spe_print_no_data(uint64_t pos, int indent)
{
	int i;

	for (i = 0; i < indent; i++)
		fprintf(f, " ");

	fprintf(f, "  %08" PRIx64 ": ", pos);
	for (i = 0; i < 16; i++)
		fprintf(f, "   ");
	fprintf(f, " ");
}

static int arm_spe_log_open(void)
{
	if (!arm_spe_enable_logging)
		return -1;

	if (f)
		return 0;

	if (!log_name[0])
		return -1;

	f = fopen(log_name, "w+");
	if (!f) {
		arm_spe_enable_logging = false;
		return -1;
	}

	return 0;
}

void __arm_spe_log_packet(const struct arm_spe_pkt *packet, int pkt_len,
			   uint64_t pos, const unsigned char *buf)
{
	char desc[ARM_SPE_PKT_DESC_MAX];

	if (arm_spe_log_open())
		return;

	arm_spe_print_data(buf, pkt_len, pos, 0);
	arm_spe_pkt_desc(packet, desc, ARM_SPE_PKT_DESC_MAX);
	fprintf(f, "%s\n", desc);
}

void __arm_spe_log_insn(struct arm_spe_insn *arm_spe_insn, uint64_t ip)
{
	//char desc[ARM_SPE_INSN_DESC_MAX];
	size_t len = arm_spe_insn->length;

	if (arm_spe_log_open())
		return;

	if (len > ARM_SPE_INSN_DBG_BUF_SZ)
		len = ARM_SPE_INSN_DBG_BUF_SZ;
	arm_spe_print_data(arm_spe_insn->buf, len, ip, 8);
#if 0
	if (arm_spe_insn_desc(arm_spe_insn, desc, ARM_SPE_INSN_DESC_MAX) > 0)
		fprintf(f, "%s\n", desc);
	else
#endif
	fprintf(f, "Bad instruction, or arm insn descriptions need to be written!\n");
}

void __arm_spe_log_insn_no_data(struct arm_spe_insn *arm_spe_insn,
				 uint64_t ip)
{
	//char desc[ARM_SPE_INSN_DESC_MAX];

	if (arm_spe_log_open())
		return;

	arm_spe_print_no_data(ip, 8);
#if 0
	if (arm_spe_insn_desc(arm_spe_insn, desc, ARM_SPE_INSN_DESC_MAX) > 0)
		fprintf(f, "%s\n", desc);
	else
		fprintf(f, "Bad instruction!\n");
#endif
	fprintf(f, "Bad instruction, or arm insn descriptions need to be written! %p\n",
		       	arm_spe_insn);
}

void __arm_spe_log(const char *fmt, ...)
{
	va_list args;

	if (arm_spe_log_open())
		return;

	va_start(args, fmt);
	vfprintf(f, fmt, args);
	va_end(args);
}
