/*
 * arm_spe_log.h: Intel Processor Trace support
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

#ifndef INCLUDE__ARM_SPE_LOG_H__
#define INCLUDE__ARM_SPE_LOG_H__

#include <stdint.h>
#include <inttypes.h>

struct arm_spe_pkt;

void arm_spe_log_enable(void);
void arm_spe_log_disable(void);
void arm_spe_log_set_name(const char *name);

void __arm_spe_log_packet(const struct arm_spe_pkt *packet, int pkt_len,
			   uint64_t pos, const unsigned char *buf);

struct arm_spe_insn;

void __arm_spe_log_insn(struct arm_spe_insn *arm_spe_insn, uint64_t ip);
void __arm_spe_log_insn_no_data(struct arm_spe_insn *arm_spe_insn,
				 uint64_t ip);

__attribute__((format(printf, 1, 2)))
void __arm_spe_log(const char *fmt, ...);

#define arm_spe_log(fmt, ...) \
	do { \
		if (arm_spe_enable_logging) \
			__arm_spe_log(fmt, ##__VA_ARGS__); \
	} while (0)

#define arm_spe_log_packet(arg, ...) \
	do { \
		if (arm_spe_enable_logging) \
			__arm_spe_log_packet(arg, ##__VA_ARGS__); \
	} while (0)

#define arm_spe_log_insn(arg, ...) \
	do { \
		if (arm_spe_enable_logging) \
			__arm_spe_log_insn(arg, ##__VA_ARGS__); \
	} while (0)

#define arm_spe_log_insn_no_data(arg, ...) \
	do { \
		if (arm_spe_enable_logging) \
			__arm_spe_log_insn_no_data(arg, ##__VA_ARGS__); \
	} while (0)

#define x64_fmt "0x%" PRIx64

extern bool arm_spe_enable_logging;

static inline void arm_spe_log_at(const char *msg, uint64_t u)
{
	arm_spe_log("%s at " x64_fmt "\n", msg, u);
}

static inline void arm_spe_log_to(const char *msg, uint64_t u)
{
	arm_spe_log("%s to " x64_fmt "\n", msg, u);
}

#endif
