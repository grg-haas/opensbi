/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Ventana Micro Systems Inc.
 *
 * Authors:
 *   Himanshu Chauhan <hchauhan@ventanamicro.com>
 */

#ifndef __FDT_RAS_H__
#define __FDT_RAS_H__

#include <sbi/sbi_types.h>

#ifdef CONFIG_FDT_RAS

struct fdt_ras {
	const struct fdt_match *match_table;
	int (*cold_init)(const void *fdt, int nodeoff, const struct fdt_match *match);
	int (*warm_init)(void);
	void (*exit)(void);
};

void fdt_ras_exit(void);

int fdt_ras_init(bool cold_boot);

#else

static inline void fdt_ras_exit(void) { }
static inline int fdt_ras_init(bool cold_boot) { return 0; }

#endif

#endif
