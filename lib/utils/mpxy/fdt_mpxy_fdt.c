#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi_utils/mpxy/fdt_mpxy.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_string.h>
#include <libfdt.h>
#include <sbi/sbi_console.h>

#define RISCV_MSG_ID_SMM_VERSION		0x1
#define RISCV_MSG_ID_SMM_COMMUNICATE	0x2
#define RISCV_MSG_ID_SMM_EVENT_COMPLETE 0x3
#define RISCV_MSG_SMM_MAX_LEN	16

#define SMM_VERSION_MAJOR        1
#define SMM_VERSION_MAJOR_SHIFT  16
#define SMM_VERSION_MAJOR_MASK   0x7FFF
#define SMM_VERSION_MINOR        0
#define SMM_VERSION_MINOR_SHIFT  0
#define SMM_VERSION_MINOR_MASK   0xFFFF
#define SMM_VERSION_FORM(major, minor) ((major << SMM_VERSION_MAJOR_SHIFT) | \
                                       (minor))
#define SMM_VERSION_COMPILED     SMM_VERSION_FORM(SMM_VERSION_MAJOR, \
                                                SMM_VERSION_MINOR)

struct mpxy_fdt_info {
	struct sbi_domain *dom;
};

static void mpxy_fdt_swap_msg(void *msgbuf, void *respbuf, u32 msg_len, unsigned long *ack_len)
{
	static void *_msgbuf = NULL;
	static void *_respbuf = NULL;
	static unsigned long *_ack_len = NULL;

	if(_msgbuf && msgbuf) {
		sbi_memcpy(_msgbuf, msgbuf, msg_len);
	}
	if(_respbuf && respbuf) {
		sbi_memcpy(_respbuf, respbuf, msg_len);
	}

	if (_ack_len)
		*_ack_len = msg_len;

	_msgbuf = msgbuf;
	_respbuf = respbuf;
	_ack_len = ack_len;
}

static int mpxy_fdt_send_message(struct sbi_mpxy_channel *channel,
				 u32 msg_id, void *msgbuf, u32 msg_len,
				 void *respbuf, u32 resp_max_len,
				 unsigned long *ack_len)
{
	struct mpxy_fdt_info *info = channel->opaque;

	if (RISCV_MSG_ID_SMM_VERSION == msg_id) {
		uint32_t version = SMM_VERSION_COMPILED;
		if(respbuf) {
			sbi_memcpy((void *)respbuf, &version, sizeof(version));
			if (ack_len)
				*ack_len = sizeof(version);
		}
	} else if (RISCV_MSG_ID_SMM_EVENT_COMPLETE == msg_id) {
		mpxy_fdt_swap_msg(msgbuf, respbuf, msg_len, ack_len);
		sbi_domain_context_exit();
	} else if (RISCV_MSG_ID_SMM_COMMUNICATE == msg_id) {
		mpxy_fdt_swap_msg(msgbuf, respbuf, msg_len, ack_len);
		sbi_domain_context_enter(info->dom);
	} else {
		return SBI_EFAIL;
	}

	return SBI_OK;
}

struct fdt_copy_node {
	enum {
		FDT_SUBNODE,
		FDT_STRING,
		FDT_CELL,
		FDT_MEM
	} type;
	const char *path;
	const char *name;

};

static const struct fdt_copy_node copy_nodes[] = {
	{ FDT_STRING, "/", "model" },
	{ FDT_STRING, "/", "compatible" },
	{ FDT_CELL, "/", "#size-cells" },
	{ FDT_CELL, "/", "#address-cells" },

	{ FDT_SUBNODE, "/", "cpus"},
	{ FDT_CELL, "/cpus", "#address-cells" },
	{ FDT_CELL, "/cpus", "#size-cells" },
	{ FDT_CELL, "/cpus", "timebase-frequency" },
	{ FDT_SUBNODE, "/cpus", "cpu-map"},

	{ FDT_SUBNODE, "/", "soc" },
	{ FDT_MEM, "/soc", "ranges" },
	{ FDT_CELL, "/soc", "#address-cells"},
	{ FDT_CELL, "/soc", "#size-cells"},
};

static int init_fdt_from_table(void *new_fdt, const void *base_fdt, int nentries,
			       const struct fdt_copy_node *nodes) {
	int i, rc, len;
	int new_offs, base_offs;
	const void *prop;
	const struct fdt_copy_node *node;

	for (i = 0; i < nentries; i++) {
		node = &nodes[i];
		new_offs = fdt_path_offset(new_fdt, node->path);
		base_offs = fdt_path_offset(base_fdt, node->path);
		prop = fdt_getprop(base_fdt, base_offs, node->name, &len);

		switch (node->type) {
		case FDT_SUBNODE:
			rc = fdt_add_subnode(new_fdt, new_offs, node->name);
			if (rc > 0)
				rc = 0;
			break;

		case FDT_STRING:
			rc = fdt_setprop_string(new_fdt, new_offs, node->name, prop);
			break;

		case FDT_CELL:
			rc = fdt_setprop_cell(new_fdt, new_offs, node->name,
					      cpu_to_fdt32(*(const uint32_t *) prop));
			break;

		case FDT_MEM:
			rc = fdt_setprop(new_fdt, new_offs, node->name,
					 prop, len);
			break;
		}

		if (rc) {
			return rc;
		}
	}

	return SBI_OK;
}

static int copy_all_properties_(void *new_fdt, const void *base_fdt,
				int new_node_to, int base_node_from)
{
	int base_subnode, new_subnode, rc;
	int base_prop, base_prop_len, base_node_len;
	const void *base_prop_val;
	const char *base_prop_name, *base_node_name;

	fdt_for_each_subnode(base_subnode, base_fdt, base_node_from) {
		base_node_name = fdt_get_name(base_fdt, base_subnode, &base_node_len);
		if (!base_node_name) {
			return base_node_len;
		}

		new_subnode = fdt_add_subnode(new_fdt, new_node_to, base_node_name);
		if (new_subnode < 0) {
			return new_subnode;
		}

		rc = copy_all_properties_(new_fdt, base_fdt, new_subnode, base_subnode);
		if (rc) {
			return rc;
		}
	}

	fdt_for_each_property_offset(base_prop, base_fdt, base_node_from) {
		base_prop_val =
			fdt_getprop_by_offset(base_fdt, base_prop,
					      &base_prop_name,
					      &base_prop_len);
		if (!base_prop_val) {
			return base_prop_len;
		}

		rc = fdt_setprop(new_fdt, new_node_to, base_prop_name,
				 base_prop_val, base_prop_len);
		if (rc) {
			return rc;
		}
	}

	return SBI_OK;
}

static int copy_fdt_cpus(void *new_fdt, const void *base_fdt, struct sbi_domain *dom)
{
	int i, rc;
	int base_node, new_node;
	char path[32];

	int new_cpu_offs = fdt_path_offset(new_fdt, "/cpus");
	if (new_cpu_offs < 0) {
		return new_cpu_offs;
	}

	sbi_hartmask_for_each_hartindex(i, dom->possible_harts) {
		sbi_snprintf(path, sizeof(path), "/cpus/cpu@%i", i);
		base_node = fdt_path_offset(base_fdt, path);
		if (base_node < 0) {
			return base_node;
		}

		sbi_snprintf(path, sizeof(path), "cpu@%i", i);
		new_node = fdt_add_subnode(new_fdt, new_cpu_offs, path);
		if (new_node < 0) {
			return new_node;
		}

		rc = copy_all_properties_(new_fdt, base_fdt,
					  new_node, base_node);
		if (rc) {
			return rc;
		}
	}

	return SBI_OK;
}

static int set_fdt_memory(void *new_fdt, struct sbi_domain *dom)
{
	struct sbi_memregion *reg;
	int rc, new_mem_offs;
	uint32_t memory_reg[4];
	char path[32];

	sbi_domain_for_each_memregion(dom, reg) {
		if ((reg->flags & SBI_MEMREGION_SU_RWX) &&
		    !(reg->flags & SBI_MEMREGION_MMIO)) {
			sbi_snprintf(path, sizeof(path), "memory@%lx", reg->base);
			new_mem_offs = fdt_add_subnode(new_fdt, 0, path);
			if (new_mem_offs < 0) {
				rc = new_mem_offs;
				break;
			}

			fdt_setprop_string(new_fdt, new_mem_offs,
					   "device_type", "memory");

			memory_reg[0] = cpu_to_fdt32((uint64_t) reg->base >> 32);
			memory_reg[1] = cpu_to_fdt32(reg->base);
			memory_reg[2] = cpu_to_fdt32((uint64_t) reg->size >> 32);
			memory_reg[3] = cpu_to_fdt32(reg->size);

			rc = fdt_setprop(new_fdt, new_mem_offs, "reg",
					 memory_reg, sizeof(memory_reg));
			if (rc)
				break;
		}
	}

	return rc;
}

static int copy_fdt_devices(void *new_fdt, const void *base_fdt, struct sbi_domain *dom)
{
	int i, j, rc;
	int nregions, ndevices, reg;
	int new_node, base_node;
	const uint32_t *regions, *devices;
	char path[32];
	const char *name;
	int namelen;

	/* FDT domain parse does not save this info, so we have to get it ourselves */
	sbi_snprintf(path, sizeof(path), "/chosen/opensbi-domains/%s", dom->name);

	int base_domain = fdt_path_offset(base_fdt, path);
	if (base_domain < 0) {
		return base_domain;
	}

	regions = fdt_getprop(base_fdt, base_domain, "regions", &nregions);
	if (!regions) {
		return nregions;
	}

	nregions /= sizeof(uint32_t);
	for (i = 0; i < nregions; i += 2) {
		reg = fdt_node_offset_by_phandle(base_fdt,
						 fdt32_to_cpu(regions[i]));
		if (!reg) {
			return reg;
		}

		devices = fdt_getprop(base_fdt, reg, "devices", &ndevices);
		if (!devices) {
			// This region may just not have devices, which
			// is not an error
			continue;
		}

		ndevices /= sizeof(uint32_t);
		for (j = 0; j < ndevices; j++) {
			base_node =
				fdt_node_offset_by_phandle(base_fdt, devices[j]);
			if (!base_node) {
				return base_node;
			}

			name = fdt_get_name(base_fdt, base_node, &namelen);
			if (!name) {
				return namelen;
			}

			new_node = fdt_add_subnode(new_fdt,
						   fdt_path_offset(new_fdt, "/soc"), name);
			if (new_node < 0) {
				return new_node;
			}

			// Copy every property of each of these devices
			rc = copy_all_properties_(new_fdt, base_fdt,
						  new_node, base_node);
			if (rc) {
				return rc;
			}
		}
	}

	return SBI_OK;
}


static int mpxy_fdt_setup_fdt(const void *base_fdt, struct sbi_mpxy_channel *channel)
{
	int rc;
	struct mpxy_fdt_info *info = channel->opaque;
	void *new_fdt = (void *) info->dom->next_arg1;

	/* Create fdt */

	rc = fdt_create_empty_tree(new_fdt, 0x1000);
	if (rc) {
		return rc;
	}

	/* Copy toplevel properties */
	rc = init_fdt_from_table(new_fdt, base_fdt, array_size(copy_nodes),
				 copy_nodes);
	if (rc) {
		return rc;
	}

	/* Copy over assigned CPUs */
	rc = copy_fdt_cpus(new_fdt, base_fdt, info->dom);
	if (rc) {
		return rc;
	}
	
	/* Set available memory */
	rc = set_fdt_memory(new_fdt, info->dom);
	if (rc) {
		return rc;
	}

	/* Copy any attached devices */
	rc = copy_fdt_devices(new_fdt, base_fdt, info->dom);
	if (rc) {
		return rc;
	}

	fdt_pack(new_fdt);
	return SBI_OK;
}

static struct sbi_domain *__get_domain(char* name)
{
	int i;
	struct sbi_domain *dom = NULL;
	sbi_domain_for_each(i, dom)
	{
		if (!sbi_strcmp(dom->name, name)) {
			return dom;
		}
	}
	return NULL;
}


static int mpxy_fdt_parse(const void *fdt, int nodeoff,
			  struct sbi_mpxy_channel *channel)
{
	const u32 *prop_instance, *prop_value;
	char name[64];
	int len, offset;

	struct mpxy_fdt_info *info = channel->opaque;

	/* Domain to communicate with */
	prop_instance = fdt_getprop(fdt, nodeoff, "tdomain-instance", &len);
	if (!prop_instance || len < 4) {
		return SBI_EINVAL;
	}
	offset = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*prop_instance));
	if (offset < 0) {
		return SBI_EINVAL;
	}
	sbi_memset(name, 0, 64);
	strncpy(name, fdt_get_name(fdt, offset, NULL), sizeof(name));
	info->dom = __get_domain(name);
	if (NULL == info->dom)
		return SBI_EINVAL;

	/* Channel ID */
	prop_value = fdt_getprop(fdt, nodeoff, "riscv,sbi-mpxy-channel-id", &len);
	if (!prop_value || len < 4)
		return SBI_EINVAL;
	channel->channel_id = (unsigned int)fdt32_to_cpu(*prop_value);

	return SBI_OK;
}

static int mpxy_fdt_init(const void *fdt, int nodeoff,
                        const struct fdt_match *match)
{
    int rc;
    struct sbi_mpxy_channel *channel = NULL;
    struct mpxy_fdt_info *info = NULL;

    /* Allocate context for MPXY channel */
    channel = sbi_zalloc(sizeof(struct sbi_mpxy_channel));
    if (!channel) {
	    rc = SBI_ENOMEM;
	    goto out;
    }

    info = sbi_zalloc(sizeof(struct mpxy_fdt_info));
    if (!info) {
	    rc = SBI_ENOMEM;
	    goto out;
    }

    /* Parse */
    channel->opaque = info;
    rc = mpxy_fdt_parse(fdt, nodeoff, channel);
    if (rc) {
	    goto out;
    }

    rc = mpxy_fdt_setup_fdt(fdt, channel);
    if (rc) {
	    goto out;
    }

    channel->send_message = mpxy_fdt_send_message;
    rc = sbi_mpxy_register_channel(channel);
    if (rc) {
	    goto out;
    }

out:
    if (info)
	    sbi_free(info);

    if (channel)
	    sbi_free(channel);

    return rc;
}

static const struct fdt_match mpxy_fdt_match[] = {
        { .compatible = "riscv,sbi-mpxy-fdt", .data = NULL},
        {}
};

struct fdt_mpxy fdt_mpxy_fdt = {
        .match_table = mpxy_fdt_match, mpxy_fdt_init
};
