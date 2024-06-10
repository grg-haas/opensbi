/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Intel Corporation. All rights reserved.
 */

#include <sbi/sbi_error.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_mpxy.h>
#include <libfdt.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi_utils/mpxy/fdt_mpxy.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_console.h>
#include <sbi_utils/mailbox/rpmi_msgprot.h>

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

struct mm_cpu_info {
	u64 mpidr;
	u32 linear_id;
	u32 flags;
};

struct mm_boot_info {
	u64 mm_mem_base;
	u64 mm_mem_limit;
	u64 mm_image_base;
	u64 mm_stack_base;
	u64 mm_heap_base;
	u64 mm_ns_comm_buf_base;
	u64 mm_shared_buf_base;
	u64 mm_image_size;
	u64 mm_pcpu_stack_size;
	u64 mm_heap_size;
	u64 mm_ns_comm_buf_size;
	u64 mm_shared_buf_size;
	u32 num_mem_region;
	u32 num_cpus;
	u32 mm_channel_id;
	struct mm_cpu_info *cpu_info;
};

struct mm_boot_args {
	struct mm_boot_info boot_info;
	struct mm_cpu_info cpu_info[SBI_HARTMASK_MAX_BITS];
};

static u32 mm_channel_id = 0;
static struct sbi_domain *tdomain = NULL;

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

static int mpxy_mm_setup_bootinfo(const void *fdt, int nodeoff, const struct fdt_match *match)
{
	const u32 *prop_instance, *prop_value;
	u64 base64, size64;
	char name[64];
	int i, len, offset;

	struct mm_boot_args *boot_args = NULL;
	struct mm_boot_info *boot_info = NULL;

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
	tdomain = __get_domain(name);
	if (NULL == tdomain)
		return SBI_EINVAL;

	boot_args = (void *)tdomain->next_arg1;
	boot_info = &boot_args->boot_info;

	prop_value = fdt_getprop(fdt, nodeoff, "num-regions", &len);
	if (!prop_value || len < 4)
		return SBI_EINVAL;
	boot_info->num_mem_region = (unsigned int)fdt32_to_cpu(*prop_value);

	prop_value = fdt_getprop(fdt, nodeoff, "memory-reg", &len);
	if (!prop_value || len < 16)
		return SBI_EINVAL;
	base64 = fdt32_to_cpu(prop_value[0]);
	base64 = (base64 << 32) | fdt32_to_cpu(prop_value[1]);
	size64 = fdt32_to_cpu(prop_value[2]);
	size64 = (size64 << 32) | fdt32_to_cpu(prop_value[3]);
	boot_info->mm_mem_base	= base64;
	boot_info->mm_mem_limit	= base64 + size64;

	prop_value = fdt_getprop(fdt, nodeoff, "image-reg", &len);
	if (!prop_value || len < 16)
		return SBI_EINVAL;
	base64 = fdt32_to_cpu(prop_value[0]);
	base64 = (base64 << 32) | fdt32_to_cpu(prop_value[1]);
	size64 = fdt32_to_cpu(prop_value[2]);
	size64 = (size64 << 32) | fdt32_to_cpu(prop_value[3]);
	boot_info->mm_image_base	= base64;
	boot_info->mm_image_size	= size64;

	prop_value = fdt_getprop(fdt, nodeoff, "heap-reg", &len);
	if (!prop_value || len < 16)
		return SBI_EINVAL;
	base64 = fdt32_to_cpu(prop_value[0]);
	base64 = (base64 << 32) | fdt32_to_cpu(prop_value[1]);
	size64 = fdt32_to_cpu(prop_value[2]);
	size64 = (size64 << 32) | fdt32_to_cpu(prop_value[3]);
	boot_info->mm_heap_base	= base64;
	boot_info->mm_heap_size	= size64;

	prop_value = fdt_getprop(fdt, nodeoff, "stack-reg", &len);
	if (!prop_value || len < 16)
		return SBI_EINVAL;
	base64 = fdt32_to_cpu(prop_value[0]);
	base64 = (base64 << 32) | fdt32_to_cpu(prop_value[1]);
	size64 = fdt32_to_cpu(prop_value[2]);
	size64 = (size64 << 32) | fdt32_to_cpu(prop_value[3]);
	boot_info->mm_stack_base	= base64 + size64 -1;

	prop_value = fdt_getprop(fdt, nodeoff, "pcpu-stack-size", &len);
	if (!prop_value || len < 4)
		return SBI_EINVAL;
	boot_info->mm_pcpu_stack_size = (unsigned long)fdt32_to_cpu(*prop_value);

	prop_value = fdt_getprop(fdt, nodeoff, "shared-buf", &len);
	if (!prop_value || len < 16)
		return SBI_EINVAL;
	base64 = fdt32_to_cpu(prop_value[0]);
	base64 = (base64 << 32) | fdt32_to_cpu(prop_value[1]);
	size64 = fdt32_to_cpu(prop_value[2]);
	size64 = (size64 << 32) | fdt32_to_cpu(prop_value[3]);
	boot_info->mm_shared_buf_base	= base64;
	boot_info->mm_shared_buf_size	= size64;

	prop_value = fdt_getprop(fdt, nodeoff, "ns-comm-buf", &len);
	if (!prop_value || len < 16)
		return SBI_EINVAL;
	base64 = fdt32_to_cpu(prop_value[0]);
	base64 = (base64 << 32) | fdt32_to_cpu(prop_value[1]);
	size64 = fdt32_to_cpu(prop_value[2]);
	size64 = (size64 << 32) | fdt32_to_cpu(prop_value[3]);
	boot_info->mm_ns_comm_buf_base	= base64;
	boot_info->mm_ns_comm_buf_size	= size64;
	boot_info->num_cpus = 0;
	sbi_hartmask_for_each_hartindex(i, tdomain->possible_harts) {
		boot_args->cpu_info[i].linear_id = sbi_hartindex_to_hartid(i);
		boot_args->cpu_info[i].flags = 0;
		boot_info->num_cpus += 1;
	}
	boot_info->cpu_info = boot_args->cpu_info;

	prop_value = fdt_getprop(fdt, nodeoff, "riscv,sbi-mpxy-channel-id", &len);
	if (!prop_value || len < 4)
		return SBI_EINVAL;
	mm_channel_id = (unsigned int)fdt32_to_cpu(*prop_value);
	boot_info->mm_channel_id = mm_channel_id;

	return 0;
}

static void mpxy_mm_swap_msg(void *msgbuf, void *respbuf, u32 msg_len, unsigned long *ack_len)
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

static int mpxy_mm_send_message(struct sbi_mpxy_channel *channel,
				  u32 msg_id, void *msgbuf, u32 msg_len,
			    void *respbuf, u32 resp_max_len,
			    unsigned long *ack_len)
{
	if (RISCV_MSG_ID_SMM_VERSION == msg_id) {
		uint32_t version = SMM_VERSION_COMPILED;
		if(respbuf) {
			sbi_memcpy((void *)respbuf, &version, sizeof(version));
			if (ack_len)
				*ack_len = sizeof(version);
		}
	} else if (RISCV_MSG_ID_SMM_EVENT_COMPLETE == msg_id) {
		mpxy_mm_swap_msg(msgbuf, respbuf, msg_len, ack_len);
		sbi_domain_context_exit();
	} else if (RISCV_MSG_ID_SMM_COMMUNICATE == msg_id) {
		mpxy_mm_swap_msg(msgbuf, respbuf, msg_len, ack_len);
		sbi_domain_context_enter(tdomain);
	} else {
		return SBI_EFAIL;
	}

	return SBI_OK;
}

static int mpxy_mm_init(const void *fdt, int nodeoff,
			  const struct fdt_match *match)
{
	int rc;
	struct sbi_mpxy_channel *channel;

	/* Allocate context for MPXY channel */
	channel = sbi_zalloc(sizeof(struct sbi_mpxy_channel));
	if (!channel)
		return SBI_ENOMEM;

	/* Setup MM boot envrionment */
	rc = mpxy_mm_setup_bootinfo(fdt, nodeoff, match);
	if (rc) {
		sbi_free(channel);
		return 0;
	}

	channel->channel_id = mm_channel_id;
	channel->send_message = mpxy_mm_send_message;
	channel->attrs.msg_data_maxlen = RISCV_MSG_SMM_MAX_LEN;

	rc = sbi_mpxy_register_channel(channel);
	if (rc) {
		sbi_free(channel);
		return rc;
	}

	return 0;
}

static const struct fdt_match mpxy_mm_match[] = {
	{ .compatible = "riscv,sbi-mpxy-mm", .data = NULL },
	{},
};

struct fdt_mpxy fdt_mpxy_mm = {
	.match_table = mpxy_mm_match,
	.init = mpxy_mm_init,
};
