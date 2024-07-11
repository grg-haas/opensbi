#include <sbi/sbi_smmtt.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_heap.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <libfdt.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_math.h>

#include "smmtt_defs.h"

/* Globals */

static struct sbi_heap_control *smmtt_hpctrl = NULL;
static uint64_t smmtt_table_base, smmtt_table_size;

/* Definitions */

#if __riscv_xlen == 32
#define IS_RW_MODE(mode) (mode == SMMTT_34_rw)
#else
#define IS_RW_MODE(mode) ((mode == SMMTT_46_rw) || (mode == SMMTT_56_rw))
#endif

#if __riscv_xlen == 32

#define SMMTT_DEFAULT_MODE (SMMTT_34)
#define MTTL2_SIZE (0x4 * 0x400)

#else

#define SMMTT_DEFAULT_MODE (SMMTT_46)
#define MTTL3_SIZE (0x8 * 0x400)
#define MTTL2_SIZE (0x10 * 0x400 * 0x400)

#endif

// Getters and setters for mttl2 fields, depending on rw
#define MTTL2_FIELD_GET(entry, rw, field) \
	((rw) ? (entry->mttl2_rw.field) : (entry->mttl2.field))

#define MTTL2_FIELD_SET(entry, rw, field, val) \
	if (rw)                                \
		entry->mttl2_rw.field = val;   \
	else                                   \
		entry->mttl2.field = val;

// Helper for getting an SMMTT type depending on rw
#define MTTL2_TYPE(rw, type) \
	((rw) ? (SMMTT_TYPE_RW_##type) : (SMMTT_TYPE_##type))

// Macro for ensuring we don't overwrite a preset field with a new value
#define MTTL2_FIELD_ENSURE_EQUAL(entry, rw, field, val)          \
	if (MTTL2_FIELD_GET(entry, rw, field) == 0) {            \
		MTTL2_FIELD_SET(entry, rw, field, val)           \
	} else if (MTTL2_FIELD_GET(entry, rw, field) != (val)) { \
		return SBI_EINVAL;                               \
	}

#define ENSURE_ZERO(expr)          \
	if ((expr) != 0) {         \
		return SBI_EINVAL; \
	}

/* MTTP handling */

unsigned int mttp_get_sdidlen()
{
	smmtt_mode_t mode;
	unsigned int sdid, sdidlen;
	uintptr_t ppn;

	// Save current values in mttp
	mttp_get(&mode, &sdid, &ppn);

	// Write all ones to SDID and get values back
	mttp_set(SMMTT_BARE, (unsigned int)-1, 0);
	mttp_get(NULL, &sdidlen, NULL);

	// Reset back old values
	mttp_set(mode, sdid, ppn);

	if (sdidlen == 0) {
		return 0;
	} else {
		return sbi_fls(sdidlen) + 1;
	}
}

void mttp_set(smmtt_mode_t mode, unsigned int sdid, uintptr_t ppn)
{
	uintptr_t mttp = INSERT_FIELD(0, MTTP_PPN, ppn);
	mttp	       = INSERT_FIELD(mttp, MTTP_SDID, sdid);
	mttp	       = INSERT_FIELD(mttp, MTTP_MODE, mode);
	csr_write(CSR_MTTP, mttp);
}

void mttp_get(smmtt_mode_t *mode, unsigned int *sdid, uintptr_t *ppn)
{
	uintptr_t mttp = csr_read(CSR_MTTP);
	if (mode) {
		*mode = EXTRACT_FIELD(mttp, MTTP_MODE);
	}

	if (sdid) {
		*sdid = EXTRACT_FIELD(mttp, MTTP_SDID);
	}

	if (ppn) {
		*ppn = EXTRACT_FIELD(mttp, MTTP_PPN);
	}
}

/* Internal decoding helpers */

static int get_smmtt_mode_info(smmtt_mode_t mode, int *levels, bool *rw)
{
	int olevels = -1;
	bool orw    = false;

	switch (mode) {
	case SMMTT_BARE:
		olevels = -1;
		break;

		// Determine if rw
#if __riscv_xlen == 32
	case SMMTT_34_rw:
#elif __riscv_xlen == 64
	case SMMTT_46_rw:
#endif
		orw = true;
#if __riscv_xlen == 32
	// fall through
	case SMMTT_34:
#elif __riscv_xlen == 64
	// fall through
	case SMMTT_46:
#endif
		olevels = 2;
		break;

#if __riscv_xlen == 64
	case SMMTT_56_rw:
		orw = true;
	// fall through
	case SMMTT_56:
		olevels = 3;
		break;
#endif
	default:
		return SBI_EINVAL;
	}

	if (levels) {
		*levels = olevels;
	}

	if (rw) {
		*rw = orw;
	}

	return SBI_OK;
}

/* SMMTT Updates */

static inline mttl1_entry_t *mttl1_from_mttl2(mttl2_entry_t *entry, bool rw)
{
	unsigned long mttl1_ppn;
	mttl1_entry_t *mttl1 = NULL;

	// Make sure this entry is the correct type to have an mttl1
	if (MTTL2_FIELD_GET(entry, rw, type) != MTTL2_TYPE(rw, MTT_L1_DIR)) {
		return NULL;
	}

	if (MTTL2_FIELD_GET(entry, rw, info)) {
		// mttl1 already allocated, extract from mttl2
		mttl1_ppn = MTTL2_FIELD_GET(entry, rw, info);
		mttl1	  = (mttl1_entry_t *)(mttl1_ppn << PAGE_SHIFT);
	} else {
		// Allocate new mttl1
		mttl1 = sbi_aligned_alloc_from(smmtt_hpctrl, PAGE_SIZE, PAGE_SIZE);
		if (!mttl1) {
			return NULL;
		}

		// Link to mttl2
		MTTL2_FIELD_SET(entry, rw, info,
				((uintptr_t)mttl1) >> PAGE_SHIFT);

		// Ensure zero field is zero
		MTTL2_FIELD_SET(entry, rw, zero, 0);
	}

	return mttl1;
}

static inline uint64_t mttl1_perms_from_flags(unsigned long flags, bool rw)
{
	if (rw) {
		if (flags & SBI_MEMREGION_SU_RX) {
			if (flags & SBI_MEMREGION_SU_WRITABLE) {
				return SMMTT_PERMS_MTT_L1_DIR_RW_READ_WRITE;
			} else {
				return SMMTT_PERMS_MTT_L1_DIR_RW_READ;
			}
		} else {
			return SMMTT_PERMS_MTT_L1_DIR_RW_DISALLOWED;
		}
	} else {
		if (flags & SBI_MEMREGION_SU_RWX) {
			return SMMTT_PERMS_MTT_L1_DIR_ALLOWED;
		} else {
			return SMMTT_PERMS_MTT_L1_DIR_DISALLOWED;
		}
	}
}

static int smmtt_add_region_mttl1(mttl2_entry_t *entry, unsigned long addr,
				  unsigned long flags, bool rw)
{
	uintptr_t idx, offset;
	uint64_t perms, field;
	mttl1_entry_t *mttl1;

	// Ensure we're not trying to change the type of this mttl2 entry
	MTTL2_FIELD_ENSURE_EQUAL(entry, rw, type, MTTL2_TYPE(rw, MTT_L1_DIR));

	// Allocate or get an existing mttl1 table
	mttl1 = mttl1_from_mttl2(entry, rw);
	if (!mttl1) {
		// Failed to allocate, reset entry
		MTTL2_FIELD_SET(entry, rw, info, 0);
		MTTL2_FIELD_SET(entry, rw, type, 0);
		MTTL2_FIELD_SET(entry, rw, zero, 0);
		return SBI_ENOMEM;
	}

	// Determine index and offset in mttl1 that this address belongs to
	idx    = EXTRACT_FIELD(addr, rw ? MTTL1_RW : MTTL1);
	offset = EXTRACT_FIELD(addr, rw ? MTTL1_RW_OFFS : MTTL1_OFFS);

	// Generate the bitfield for the permissions and ensure it is not set
	field = MTT_PERM_FIELD(1, rw, L1_DIR, offset);
	ENSURE_ZERO(EXTRACT_FIELD(mttl1[idx], field));

	// Set the new permissions
	perms	   = mttl1_perms_from_flags(flags, rw);
	mttl1[idx] = INSERT_FIELD(mttl1[idx], field, perms);
	return SBI_OK;
}

static inline uint64_t mttl2_2m_perms_from_flags(unsigned long flags, bool rw)
{
	if (rw) {
		if (flags & SBI_MEMREGION_SU_RX) {
			if (flags & SBI_MEMREGION_SU_WRITABLE) {
				return SMMTT_PERMS_2M_PAGES_RW_READ_WRITE;
			} else {
				return SMMTT_PERMS_2M_PAGES_RW_READ;
			}
		} else {
			return SMMTT_PERMS_2M_PAGES_RW_DISALLOWED;
		}
	} else {
		if (flags & SBI_MEMREGION_SU_RWX) {
			return SMMTT_PERMS_2M_PAGES_ALLOWED;
		} else {
			return SMMTT_PERMS_2M_PAGES_DISALLOWED;
		}
	}
}

static int smmtt_add_region_mttl2_2m(mttl2_entry_t *entry, unsigned long addr,
				     unsigned long flags, bool rw)
{
	uintptr_t offset;
	uint32_t info, perms, field;

	// Ensure we're not trying to change the type of this mttl2 entry
	MTTL2_FIELD_ENSURE_EQUAL(entry, rw, type, MTTL2_TYPE(rw, 2M_PAGES));

	// Determine offset in mttl2 entry that this address belongs to
	offset = EXTRACT_FIELD(addr, rw ? MTTL2_RW_OFFS : MTTL2_OFFS);

	// Generate the bitfield for the permissions and ensure it is not set
	field = MTT_PERM_FIELD(2, rw, 2M_PAGES, offset);
	info  = MTTL2_FIELD_GET(entry, rw, info);
	ENSURE_ZERO(EXTRACT_FIELD(info, field));

	// Set the new permissions
	perms = mttl2_2m_perms_from_flags(flags, rw);
	info  = INSERT_FIELD(info, field, perms);
	MTTL2_FIELD_SET(entry, rw, info, info)

	// Ensure zero field is zero
	MTTL2_FIELD_SET(entry, rw, zero, 0);
	return SBI_OK;
}

static inline uint64_t mttl2_1g_type_from_flags(unsigned long flags, bool rw)
{
	if (rw) {
		if (flags & SBI_MEMREGION_SU_RX) {
			if (flags & SBI_MEMREGION_SU_WRITABLE) {
				return SMMTT_TYPE_RW_1G_ALLOW_RW;
			} else {
				return SMMTT_TYPE_RW_1G_ALLOW_R;
			}
		} else {
			return SMMTT_TYPE_RW_1G_DISALLOW;
		}
	} else {
		if (flags & SBI_MEMREGION_SU_RWX) {
			return SMMTT_TYPE_1G_ALLOW;
		} else {
			return SMMTT_TYPE_1G_DISALLOW;
		}
	}
}

static int smmtt_add_region_mttl2_1g(mttl2_entry_t *entry, unsigned long flags,
				     bool rw)
{
	// Ensure we're not trying to change the type of this mttl2 entry
	uint64_t type = mttl2_1g_type_from_flags(flags, rw);
	MTTL2_FIELD_ENSURE_EQUAL(entry, rw, type, type);

	// Ensure info and zero fields are set to zero
	MTTL2_FIELD_SET(entry, rw, info, 0);
	MTTL2_FIELD_SET(entry, rw, zero, 0);
	return SBI_OK;
}

#define FITS(base, size, region) \
	(((size) >= (region)) && (!((base) % (region))))

#define MiB (1UL << 20)
#define GiB (1ULL << 30)

static int smmtt_add_region_mttl2(mttl2_entry_t *mttl2, unsigned long base,
				  unsigned long size, unsigned long flags,
				  bool rw)
{
	int rc, i;
	uintptr_t idx;
	mttl2_entry_t *entry;

	unsigned long long mask = rw ? MTTL2_RW : MTTL2;

	while (size != 0) {
		idx		     = EXTRACT_FIELD(base, mask);
		entry		     = &mttl2[idx];
		entry->mttl2_rw.zero = 0;

		if (FITS(base, size, GiB)) {
			for (i = 0; i < (rw ? 32 : 16); i++) {
				rc = smmtt_add_region_mttl2_1g(&mttl2[idx + i],
							       flags, rw);
				if (rc < 0) {
					return rc;
				}
			}

			size -= GiB;
			base += GiB;
		} else if (FITS(base, size, 2 * MiB)) {
			rc = smmtt_add_region_mttl2_2m(entry, base, flags, rw);
			if (rc < 0) {
				return rc;
			}

			size -= (2 * MiB);
			base += (2 * MiB);
		} else {
			rc = smmtt_add_region_mttl1(entry, base, flags, rw);
			if (rc < 0) {
				return rc;
			}

			size -= PAGE_SIZE;
			base += PAGE_SIZE;
		}
	}

	return SBI_OK;
}

#if __riscv_xlen == 64
static int smmtt_add_region_mttl3(mttl3_entry_t *mttl3, unsigned long base,
				  unsigned long size, unsigned long flags,
				  bool rw)
{
	unsigned long mttl2_ppn;
	mttl2_entry_t *mttl2;
	uintptr_t idx = EXTRACT_FIELD(base, MTTL3);

	if (mttl3[idx].mttl2_ppn == 0) {
		mttl2 = sbi_aligned_alloc_from(smmtt_hpctrl, MTTL2_SIZE, MTTL2_SIZE);
		mttl2_ppn	     = ((uintptr_t)mttl2) >> PAGE_SHIFT;
		mttl3[idx].mttl2_ppn = mttl2_ppn;
		mttl3[idx].zero	     = 0;
	} else {
		mttl2_ppn = mttl3[idx].mttl2_ppn;
		mttl2	  = (mttl2_entry_t *)(mttl2_ppn << PAGE_SHIFT);
	}

	if (!mttl2) {
		return SBI_ENOMEM;
	}

	return smmtt_add_region_mttl2(mttl2, base, size, flags, rw);
}
#endif

/* External interfaces */

static int initialize_mtt(struct sbi_domain *dom, struct sbi_scratch *scratch)
{
	int rc, levels;
	bool rw;

	struct sbi_memregion *reg;

	if (!dom->mtt) {
		// Assign the default SMMTT mode if this domain does not
		// have a specified one yet
		if (dom->smmtt_mode == SMMTT_BARE) {
			dom->smmtt_mode = SMMTT_DEFAULT_MODE;
		}

		if (!sbi_hart_has_smmtt_mode(scratch, dom->smmtt_mode)) {
			return SBI_EINVAL;
		}

		// Allocate an appropriately sized MTT
		rc = get_smmtt_mode_info(dom->smmtt_mode, &levels, &rw);
		if (rc < 0) {
			return rc;
		}

#if __riscv_xlen == 64
		if (levels == 3) {
			dom->mtt = sbi_aligned_alloc_from(smmtt_hpctrl,
							  MTTL3_SIZE, MTTL3_SIZE);
		}
#endif
		if (levels == 2) {
			dom->mtt = sbi_aligned_alloc_from(smmtt_hpctrl,
							  MTTL2_SIZE, MTTL2_SIZE);
		}

		if (!dom->mtt) {
			return SBI_ENOMEM;
		}

		sbi_domain_for_each_memregion(dom, reg)
		{

			if (!(reg->flags & SBI_MEMREGION_SU_RWX)) {
				continue;
			}

#if __riscv_xlen == 64
			if (levels == 3) {
				smmtt_add_region_mttl3(dom->mtt, reg->base,
						       reg->size, reg->flags,
						       rw);
			}
#endif

			if (levels == 2) {
				smmtt_add_region_mttl2(dom->mtt, reg->base,
						       reg->size, reg->flags,
						       rw);
			}
		}
	}

	return SBI_OK;
}

int sbi_hart_smmtt_configure(struct sbi_scratch *scratch)
{
	int rc;
	unsigned int pmp_count;
	struct sbi_domain *dom = sbi_domain_thishart_ptr();

	rc = sbi_memregion_sanitize(dom, SBI_ISOLATION_SMMTT);
	if (rc < 0) {
		return rc;
	}

	/* Ensure table is rendered */
	rc = initialize_mtt(dom, scratch);
	if (rc < 0) {
		return rc;
	}

	/* Install table and PMP */

	// For PMP, we allow access to everything except for the SMMTT
	// tables (disabled by highest priority register).
	pmp_count = sbi_hart_pmp_count(scratch);
	pmp_set(pmp_count - 1, PMP_R | PMP_W | PMP_X, 0, __riscv_xlen);
	pmp_set(0, 0, smmtt_table_base, log2roundup(smmtt_table_size));

	// For SMMTT, we only selectively enable access as specified
	// by the domain configuration
	mttp_set(dom->smmtt_mode, 0, ((uintptr_t)dom->mtt) >> PAGE_SHIFT);

	// Both PMP and SMMTT checks apply for each access, and the final
	// permissions are the logical and of the two checks. Therefore,
	// unprivileged code can definitely never access the SMMTT tables
	// because of the PMP configuration. Unprivileged code can also not
	// access anything besides what SMMTT explicitly enables.

	return 0;
}

static int setup_table_memory()
{
	const void *fdt;
	int namelen, ret;
	int reserved_node, table_node;
	const char *name;

	// Look for the smmtt-tables reserved memory node
	fdt	      = fdt_get_address();
	reserved_node = fdt_path_offset(fdt, "/reserved-memory");
	if (reserved_node < 0) {
		return SBI_ENOMEM;
	}

	fdt_for_each_subnode(table_node, fdt, reserved_node)
	{
		name = fdt_get_name(fdt, table_node, &namelen);
		if (strncmp(name, "smmtt-tables", namelen) == 0) {
			break;
		}
	}

	if (table_node == -FDT_ERR_NOTFOUND) {
		return SBI_ENOMEM;
	}

	// Extract base and size
	ret = fdt_get_node_addr_size(fdt, table_node, 0, &smmtt_table_base,
				     &smmtt_table_size);
	if (ret < 0) {
		return ret;
	}

	// Ensure NAPOT so we can later fit this in a single PMP register
	if ((smmtt_table_size & (smmtt_table_size - 1)) != 0) {
		return SBI_EINVAL;
	}

	if ((smmtt_table_base & (smmtt_table_size - 1)) != 0) {
		return SBI_EINVAL;
	}

	// Initialize the SMMTT table heap
	sbi_heap_alloc_new(&smmtt_hpctrl);
	sbi_heap_init_new(smmtt_hpctrl, smmtt_table_base, smmtt_table_size);

	return SBI_OK;
}

int sbi_smmtt_init(struct sbi_scratch *scratch, bool cold_boot)
{
	int rc;

	if (cold_boot) {
		rc = setup_table_memory();
		if (rc < 0)
			return rc;
	}

	return SBI_OK;
}
