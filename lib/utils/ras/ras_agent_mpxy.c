/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Ventana Micro Systems, Inc.
 *
 * Author(s):
 *   Himanshu Chauhan <hchauhan@ventanamicro.com>
 */

#include <libfdt.h>
#include <sbi/sbi_error.h>
#include <sbi/riscv_io.h>
#include <sbi/sbi_ras.h>
#include <sbi/sbi_mpxy.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include <sbi_utils/ras/fdt_ras.h>
#include <sbi_utils/ras/ras_agent_mpxy.h>
#include <sbi_utils/ras/riscv_reri_regs.h>
#include <sbi_utils/ras/apei_tables.h>
#include <sbi_utils/ras/ghes.h>
#include <sbi_utils/mailbox/fdt_mailbox.h>
#include <sbi_utils/mailbox/rpmi_mailbox.h>

struct __packed ras_rpmi_resp_hdr {
	u32 status;
	u32 flags;
	u32 remaining;
	u32 returned;
};

static struct sbi_mpxy_channel ra_mpxy_ch;
static int ras_handle_message(struct sbi_mpxy_channel *channel, u32 msg_id,
			      void *msgbuf, u32 msg_len, void *respbuf,
			      u32 resp_max_len, unsigned long *resp_len);

int ras_mpxy_init(const void *fdt, int nodeoff)
{
	int rc, len;
	const fdt32_t *chan_id_p;
	u32 chan_id;
	int mpxy_node_off;

	memset(&ra_mpxy_ch, 0, sizeof(ra_mpxy_ch));

	mpxy_node_off = fdt_node_offset_by_compatible(fdt, -1, "riscv,sbi-mpxy-ras-agent");
	if (mpxy_node_off < 0)
		return SBI_ENOENT;

	chan_id_p = fdt_getprop(fdt, mpxy_node_off, "riscv,sbi-mpxy-channel-id", &len);
	if (!chan_id_p)
		return SBI_ENOENT;

	chan_id = fdt32_to_cpu(*chan_id_p);

	ra_mpxy_ch.channel_id = chan_id;
	ra_mpxy_ch.send_message = ras_handle_message;
	ra_mpxy_ch.get_notification_events = NULL;
	ra_mpxy_ch.switch_eventsstate = NULL;
	ra_mpxy_ch.attrs.msg_data_maxlen = 4096;

	rc = sbi_mpxy_register_channel(&ra_mpxy_ch);
	if (rc != SBI_SUCCESS)
		return rc;

	return SBI_SUCCESS;
}

#define BUF_TO_DATA(_msg_buf)		\
	(((uint8_t *)_msg_buf) + sizeof(struct ras_rpmi_resp_hdr))

static int ras_handle_message(struct sbi_mpxy_channel *channel, u32 msg_id,
			      void *msgbuf, u32 msg_len, void *respbuf,
			      u32 resp_max_len, unsigned long *resp_len)
{
	int rc = SBI_SUCCESS;
	int nr, nes;
	u32 *src_list;
	u32 src_id;
	uint8_t *src_desc;
	struct ras_rpmi_resp_hdr *rhdr = (struct ras_rpmi_resp_hdr *)respbuf;
	u32 *nsrcs;
#define MAX_ID_BUF_SZ (sizeof(u32) * MAX_ERR_SRCS)

	switch(msg_id) {
	case RAS_GET_NUM_ERR_SRCS:
		if (!respbuf)
			return -SBI_EINVAL;

		memset(respbuf, 0, resp_max_len);
		nes = acpi_ghes_get_num_err_srcs();
		rhdr->flags = 0;
		rhdr->status = RPMI_SUCCESS;
		rhdr->remaining = 0;
		rhdr->returned = cpu_to_le32(nes);

		nsrcs = (u32 *)BUF_TO_DATA(respbuf);
		*nsrcs = cpu_to_le32(nes);
		*resp_len = sizeof(*rhdr) + (sizeof(u32));
		rc = SBI_SUCCESS;
		break;

	case RAS_GET_ERR_SRCS_ID_LIST:
		if (!respbuf)
			return -SBI_EINVAL;

		src_list = (u32 *)BUF_TO_DATA(respbuf);

		nr = acpi_ghes_get_err_srcs_list(src_list,
						 resp_max_len/sizeof(u32));

		rhdr->status = RPMI_SUCCESS;
		rhdr->returned = nr;
		rhdr->remaining = 0;
		*resp_len = sizeof(*rhdr) + (sizeof(u32) * nr);
		break;

	case RAS_GET_ERR_SRC_DESC:
		rhdr->flags = 0;
		src_id = *((u32 *)msgbuf);
		src_desc = (uint8_t *)BUF_TO_DATA(respbuf);
		acpi_ghes_get_err_src_desc(src_id, (acpi_ghesv2 *)src_desc);

		rhdr->status = RPMI_SUCCESS;

		rhdr->returned = sizeof(acpi_ghesv2);
		rhdr->remaining = 0;
		*resp_len = sizeof(*rhdr) + sizeof(acpi_ghesv2);
		break;

	default:
		sbi_printf("RAS Agent: Unknown service %u\n", msg_id);
		rc = SBI_ENOENT;
	}

	return rc;
}
