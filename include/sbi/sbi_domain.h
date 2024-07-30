/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#ifndef __SBI_DOMAIN_H__
#define __SBI_DOMAIN_H__

#include <sbi/riscv_locks.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_domain_context.h>
#include <sbi/sbi_memregion.h>

struct sbi_scratch;

/** Maximum number of domains */
#define SBI_DOMAIN_MAX_INDEX			32

/** Representation of OpenSBI domain */
struct sbi_domain {
	/**
	 * Logical index of this domain
	 * Note: This set by sbi_domain_finalize() in the coldboot path
	 */
	u32 index;
	/**
	 * HARTs assigned to this domain
	 * Note: This set by sbi_domain_init() and sbi_domain_finalize()
	 * in the coldboot path
	 */
	struct sbi_hartmask assigned_harts;
	/** Spinlock for accessing assigned_harts */
	spinlock_t assigned_harts_lock;
	/** Name of this domain */
	char name[64];
	/** Possible HARTs in this domain */
	const struct sbi_hartmask *possible_harts;
	/** Contexts for possible HARTs indexed by hartindex */
	struct sbi_context *hartindex_to_context_table[SBI_HARTMASK_MAX_BITS];
	/** Array of memory regions terminated by a region with order zero */
	struct sbi_memregion *regions;
	/** HART id of the HART booting this domain */
	u32 boot_hartid;
	/** Arg1 (or 'a1' register) of next booting stage for this domain */
	unsigned long next_arg1;
	/** Address of next booting stage for this domain */
	unsigned long next_addr;
	/** Privilege mode of next booting stage for this domain */
	unsigned long next_mode;
	/** Is domain allowed to reset the system */
	bool system_reset_allowed;
	/** Is domain allowed to suspend the system */
	bool system_suspend_allowed;
	/** Identifies whether to include the firmware region */
	bool fw_region_inited;
};

/** The root domain instance */
extern struct sbi_domain root;

/** Get pointer to sbi_domain from HART index */
struct sbi_domain *sbi_hartindex_to_domain(u32 hartindex);

/** Update HART local pointer to point to specified domain */
void sbi_update_hartindex_to_domain(u32 hartindex, struct sbi_domain *dom);

/** Get pointer to sbi_domain for current HART */
#define sbi_domain_thishart_ptr() \
	sbi_hartindex_to_domain(sbi_hartid_to_hartindex(current_hartid()))

/** Index to domain table */
extern struct sbi_domain *domidx_to_domain_table[];

/** Get pointer to sbi_domain from index */
#define sbi_index_to_domain(__index) \
	domidx_to_domain_table[__index]

/** Iterate over each domain */
#define sbi_domain_for_each(__i, __d) \
	for ((__i) = 0; ((__d) = sbi_index_to_domain(__i)); (__i)++)

/** Iterate over each memory region of a domain */
#define sbi_domain_for_each_memregion(__d, __r) \
	for ((__r) = (__d)->regions; (__r)->order; (__r)++)

/**
 * Check whether given HART is assigned to specified domain
 * @param dom pointer to domain
 * @param hartid the HART ID
 * @return true if HART is assigned to domain otherwise false
 */
bool sbi_domain_is_assigned_hart(const struct sbi_domain *dom, u32 hartid);

/**
 * Get ulong assigned HART mask for given domain and HART base ID
 * @param dom pointer to domain
 * @param hbase the HART base ID
 * @return ulong possible HART mask
 * Note: the return ulong mask will be set to zero on failure.
 */
ulong sbi_domain_get_assigned_hartmask(const struct sbi_domain *dom,
				       ulong hbase);

/** Dump domain details on the console */
void sbi_domain_dump(const struct sbi_domain *dom, const char *suffix);

/** Dump all domain details on the console */
void sbi_domain_dump_all(const char *suffix);

/**
 * Register a new domain
 * @param dom pointer to domain
 * @param assign_mask pointer to HART mask of HARTs assigned to the domain
 *
 * @return 0 on success and negative error code on failure
 */
int sbi_domain_register(struct sbi_domain *dom,
			const struct sbi_hartmask *assign_mask);

/**
 * Add a memory region to the root domain
 * @param reg pointer to the memory region to be added
 *
 * @return 0 on success
 * @return SBI_EALREADY if memory region conflicts with the existing one
 * @return SBI_EINVAL otherwise
 */
int sbi_domain_root_add_memregion(const struct sbi_memregion *reg);

/**
 * Add a memory range with its flags to the root domain
 * @param addr start physical address of memory range
 * @param size physical size of memory range
 * @param align alignment of memory region
 * @param region_flags memory range flags
 *
 * @return 0 on success
 * @return SBI_EALREADY if memory region conflicts with the existing one
 * @return SBI_EINVAL otherwise
 */
int sbi_domain_root_add_memrange(unsigned long addr, unsigned long size,
			   unsigned long align, unsigned long region_flags);

/** Finalize domain tables and startup non-root domains */
int sbi_domain_finalize(struct sbi_scratch *scratch, u32 cold_hartid);

/** Initialize domains */
int sbi_domain_init(struct sbi_scratch *scratch, u32 cold_hartid);

#endif
