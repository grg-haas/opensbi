#include <sbi/sbi_memregion.h>
#include <sbi/sbi_math.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_string.h>

static void memregion_sanitize_pmp(struct sbi_memregion *reg)
{
	unsigned long base = 0, order;
	unsigned long addr = reg->base, size = reg->size;
	for (order = log2roundup(size) ; order <= __riscv_xlen; order++) {
		if (order < __riscv_xlen) {
			base = addr & ~((1UL << order) - 1UL);
			if ((base <= addr) &&
			    (addr < (base + (1UL << order))) &&
			    (base <= (addr + size - 1UL)) &&
			    ((addr + size - 1UL) < (base + (1UL << order))))
				break;
		} else {
			base = 0;
			break;
		}
	}

	reg->base = base;
	reg->size = (order == __riscv_xlen) ? -1UL : BIT(order);
}

void sbi_memregion_init(unsigned long addr,
			       unsigned long size,
			       unsigned long flags,
			       struct sbi_memregion *reg)
{
	if (reg) {
		reg->base = addr;
		reg->size = size;
		reg->flags = flags;
	}
}

/** Check if regionA is sub-region of regionB */
static bool is_region_subset(const struct sbi_memregion *regA,
			     const struct sbi_memregion *regB)
{
	ulong regA_start = memregion_start(regA);
	ulong regA_end = memregion_end(regA);
	ulong regB_start = memregion_start(regB);
	ulong regB_end = memregion_end(regB);

	if ((regB_start <= regA_start) &&
	    (regA_start < regB_end) &&
	    (regB_start < regA_end) &&
	    (regA_end <= regB_end))
		return true;

	return false;
}

/** Check if regionA can be replaced by regionB */
static bool is_region_compatible(const struct sbi_memregion *regA,
				 const struct sbi_memregion *regB)
{
	if (is_region_subset(regA, regB) && regA->flags == regB->flags)
		return true;

	return false;
}

static bool is_region_valid_pmp(const struct sbi_memregion *reg)
{
	unsigned int order = log2roundup(reg->size);
	if (order < 3 || __riscv_xlen < order)
		return false;

	if (order == __riscv_xlen && reg->base != 0)
		return false;

	if (order < __riscv_xlen && (reg->base & (BIT(order) - 1)))
		return false;

	return true;
}

/* Check if region complies with constraints */
static bool is_region_valid(const struct sbi_memregion *reg,
			    enum sbi_isolation_method type)
{
	switch(type) {
	case SBI_ISOLATION_UNKNOWN:
		break;

	case SBI_ISOLATION_PMP:
	case SBI_ISOLATION_SMEPMP:
		return is_region_valid_pmp(reg);

	default:
		return false;
	}

	return true;
}

/** Check if regionA should be placed before regionB */
static bool is_region_before(const struct sbi_memregion *regA,
			     const struct sbi_memregion *regB)
{
	// Sentinel region always goes last
	if (!regA->size)
		return false;

	if (!regB->size)
		return true;

	if (regA->size < regB->size)
		return true;

	if ((regA->size == regB->size) &&
	    (regA->base < regB->base))
		return true;

	return false;
}


static void swap_region(struct sbi_memregion * reg1,
			struct sbi_memregion * reg2)
{
	struct sbi_memregion treg;

	sbi_memcpy(&treg, reg1, sizeof(treg));
	sbi_memcpy(reg1, reg2, sizeof(treg));
	sbi_memcpy(reg2, &treg, sizeof(treg));
}

static void clear_region(struct sbi_memregion * reg)
{
	sbi_memset(reg, 0x0, sizeof(*reg));
}

static void sort_memregions(struct sbi_domain *dom, int count)
{
	int i, j;
	struct sbi_memregion *reg, *reg1;

	/* Sort the memory regions */
	for (i = 0; i < (count - 1); i++) {
		reg = &dom->regions[i];
		for (j = i + 1; j < count; j++) {
			reg1 = &dom->regions[j];

			if (!is_region_before(reg1, reg))
				continue;

			swap_region(reg, reg1);
		}
	}
}

static void overlap_memregions(struct sbi_domain *dom, int count)
{
	int i = 0, j;
	bool is_covered;
	struct sbi_memregion *reg, *reg1;

	/* Remove covered regions */
	while(i < (count - 1)) {
		is_covered = false;
		reg = &dom->regions[i];

		for (j = i + 1; j < count; j++) {
			reg1 = &dom->regions[j];

			if (is_region_compatible(reg, reg1)) {
				is_covered = true;
				break;
			}
		}

		/* find a region is superset of reg, remove reg */
		if (is_covered) {
			for (j = i; j < (count - 1); j++)
				swap_region(&dom->regions[j],
					    &dom->regions[j + 1]);
			clear_region(&dom->regions[count - 1]);
			count--;
		} else
			i++;
	}
}

static void merge_memregions(struct sbi_domain *dom, int *nmerged)
{
	struct sbi_memregion *reg, *reg1, *reg2;

	/* Merge consecutive memregions with same flags */
	*nmerged = 0;
	sbi_domain_for_each_memregion(dom, reg) {
		reg1 = reg + 1;
		if (!reg1->size)
			continue;

		if ((reg->base + reg->size) == reg1->base &&
		    reg->flags == reg1->flags) {
			reg->size += reg1->size;
			while (reg1->size) {
				reg2 = reg1 + 1;
				sbi_memcpy(reg1, reg2, sizeof(*reg1));
				reg1++;
			}
			(*nmerged)++;
		}
	}
}

static int memregion_sanitize(struct sbi_domain *dom,
			      struct sbi_memregion *reg,
			      enum sbi_isolation_method type)
{
	if (!reg) {
		return SBI_EINVAL;
	}

	switch (type) {
		case SBI_ISOLATION_UNKNOWN:
			break;

		case SBI_ISOLATION_PMP:
		case SBI_ISOLATION_SMEPMP:
			memregion_sanitize_pmp(reg);
			break;

		default:
			return SBI_EINVAL;
	}

	if (!is_region_valid(reg, type)) {
		sbi_printf("%s: %s has invalid region base=0x%lx "
			   "size=0x%lx flags=0x%lx\n", __func__,
			   dom->name, reg->base, reg->size,
			   reg->flags);
		return SBI_EINVAL;
	}

	return SBI_OK;
}

int sbi_memregion_sanitize(struct sbi_domain *dom,
			   enum sbi_isolation_method type)
{
	int count, nmerged;
	struct sbi_memregion *reg;

	/* Check memory regions */
	if (!dom->regions) {
		sbi_printf("%s: %s regions is NULL\n",
			   __func__, dom->name);
		return SBI_EINVAL;
	}

	/* Make sure we're not refinalizing */
	if (type != SBI_ISOLATION_UNKNOWN &&
	    dom->isol_mode != SBI_ISOLATION_UNKNOWN &&
	    type != dom->isol_mode) {
		sbi_printf("%s: %s attempting to resanitize memregions\n",
			   __func__, dom->name);
		return SBI_EINVAL;
	}

	/* Count memory regions */
	count = 0;
	sbi_domain_for_each_memregion(dom, reg) {
		count++;
		if (memregion_sanitize(dom, reg, type) < 0) {
			return SBI_EINVAL;
		}
	}

	/* Check presence of firmware regions */
	if (!dom->fw_region_inited) {
		sbi_printf("%s: %s does not have firmware region\n",
			   __func__, dom->name);
		return SBI_EINVAL;
	}

	do {
		sort_memregions(dom, count);
		overlap_memregions(dom, count);
		merge_memregions(dom, &nmerged);
	} while (nmerged);

	sbi_domain_for_each_memregion(dom, reg) {
		if (!is_region_valid(reg, type)) {
			sbi_printf("%s: %s has invalid region base=0x%lx "
				   "size=0x%lx flags=0x%lx\n", __func__,
				   dom->name, reg->base, reg->size,
				   reg->flags);
			return SBI_EINVAL;
		}
	}

	return SBI_OK;
}


bool sbi_domain_check_addr(const struct sbi_domain *dom,
			   unsigned long addr, unsigned long mode,
			   unsigned long access_flags)
{
	bool rmmio, mmio = false;
	struct sbi_memregion *reg;
	unsigned long rstart, rend, rflags, rwx = 0, rrwx = 0;

	if (!dom)
		return false;

	/*
	 * Use M_{R/W/X} bits because the SU-bits are at the
	 * same relative offsets. If the mode is not M, the SU
	 * bits will fall at same offsets after the shift.
	 */
	if (access_flags & SBI_DOMAIN_READ)
		rwx |= SBI_MEMREGION_M_READABLE;

	if (access_flags & SBI_DOMAIN_WRITE)
		rwx |= SBI_MEMREGION_M_WRITABLE;

	if (access_flags & SBI_DOMAIN_EXECUTE)
		rwx |= SBI_MEMREGION_M_EXECUTABLE;

	if (access_flags & SBI_DOMAIN_MMIO)
		mmio = true;

	sbi_domain_for_each_memregion(dom, reg) {
		rflags = reg->flags;
		rrwx = (mode == PRV_M ?
					(rflags & SBI_MEMREGION_M_ACCESS_MASK) :
					(rflags & SBI_MEMREGION_SU_ACCESS_MASK)
						>> SBI_MEMREGION_SU_ACCESS_SHIFT);

		rstart = memregion_start(reg);
		rend = memregion_end(reg);
		if (rstart <= addr && addr <= rend) {
			rmmio = (rflags & SBI_MEMREGION_MMIO) ? true : false;
			if (mmio != rmmio)
				return false;
			return ((rrwx & rwx) == rwx) ? true : false;
		}
	}

	return (mode == PRV_M) ? true : false;
}

static const struct sbi_memregion *find_region(
	const struct sbi_domain *dom,
	unsigned long addr)
{
	unsigned long rstart, rend;
	struct sbi_memregion *reg;

	sbi_domain_for_each_memregion(dom, reg) {
		rstart = memregion_start(reg);
		rend = memregion_end(reg);
		if (rstart <= addr && addr <= rend)
			return reg;
	}

	return NULL;
}

static const struct sbi_memregion *find_next_subset_region(
	const struct sbi_domain *dom,
	const struct sbi_memregion *reg,
	unsigned long addr)
{
	struct sbi_memregion *sreg, *ret = NULL;

	sbi_domain_for_each_memregion(dom, sreg) {
		if (sreg == reg || (sreg->base <= addr) ||
		    !is_region_subset(sreg, reg))
			continue;

		if (!ret || (sreg->base < ret->base) ||
		    ((sreg->base == ret->base) && (sreg->size < ret->size)))
			ret = sreg;
	}

	return ret;
}

bool sbi_domain_check_addr_range(const struct sbi_domain *dom,
				 unsigned long addr, unsigned long size,
				 unsigned long mode,
				 unsigned long access_flags)
{
	unsigned long max = addr + size;
	const struct sbi_memregion *reg, *sreg;

	if (!dom)
		return false;

	while (addr < max) {
		reg = find_region(dom, addr);
		if (!reg)
			return false;

		if (!sbi_domain_check_addr(dom, addr, mode, access_flags))
			return false;

		sreg = find_next_subset_region(dom, reg, addr);
		if (sreg)
			addr = sreg->base;
		else if (reg->size != -1UL)
			addr = reg->base + reg->size;
		else
			break;
	}

	return true;
}

void sbi_domain_dump_memregions(const struct sbi_domain *dom, const char *suffix)
{
	unsigned long rstart, rend;
	struct sbi_memregion *reg;
	int i = 0, k;

	sbi_domain_for_each_memregion(dom, reg) {
		rstart = memregion_start(reg);
		rend = memregion_end(reg);

		sbi_printf("Domain%d Region%02d    %s: 0x%" PRILX "-0x%" PRILX " ",
			   dom->index, i, suffix, rstart, rend);

		k = 0;

		sbi_printf("M: ");
		if (reg->flags & SBI_MEMREGION_MMIO)
			sbi_printf("%cI", (k++) ? ',' : '(');
		if (reg->flags & SBI_MEMREGION_M_READABLE)
			sbi_printf("%cR", (k++) ? ',' : '(');
		if (reg->flags & SBI_MEMREGION_M_WRITABLE)
			sbi_printf("%cW", (k++) ? ',' : '(');
		if (reg->flags & SBI_MEMREGION_M_EXECUTABLE)
			sbi_printf("%cX", (k++) ? ',' : '(');
		sbi_printf("%s ", (k++) ? ")" : "()");

		k = 0;
		sbi_printf("S/U: ");
		if (reg->flags & SBI_MEMREGION_SU_READABLE)
			sbi_printf("%cR", (k++) ? ',' : '(');
		if (reg->flags & SBI_MEMREGION_SU_WRITABLE)
			sbi_printf("%cW", (k++) ? ',' : '(');
		if (reg->flags & SBI_MEMREGION_SU_EXECUTABLE)
			sbi_printf("%cX", (k++) ? ',' : '(');
		sbi_printf("%s\n", (k++) ? ")" : "()");

		i++;
	}
}
