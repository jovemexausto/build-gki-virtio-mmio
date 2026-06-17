// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * tpm_virtio.c - Driver for TPM over virtio
 *
 * Exposes a TPM 2.0 device (/dev/tpm0) backed by a virtio transport.
 * The VMM (libkrun, crosvm, etc.) exposes VIRTIO_ID_TPM (29) with a
 * single virtqueue. The guest submits one descriptor chain per command:
 *
 *   [0] OUT (guest→host): raw TPM command bytes
 *   [1] IN  (host→guest): response buffer (TPM_BUFSIZE bytes)
 *
 * We use TPM_CHIP_FLAG_IRQ so the TPM core calls recv() immediately
 * after send() without polling status(). The virtqueue callback fires
 * when the VMM has written the response, completing the recv() wait.
 *
 * Flow:
 *   tpm_core → send()    : enqueue descriptors, kick virtqueue
 *   VMM                  : process command, write response, notify guest
 *   vtpm_vq_callback()   : virtqueue_get_buf(), stash resp_len, complete()
 *   tpm_core → recv()    : wait_for_completion(), copy response out
 *
 * Copyright (c) 2026 Capivara contributors
 * Based on tpm_ibmvtpm.c and crosvm virtio-tpm device specification.
 */

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/tpm.h>
#include <linux/completion.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include "tpm.h"

/* VIRTIO_ID_TPM = 29; defined in linux/virtio_ids.h on recent kernels.
 * Provide a fallback for kernels that don't have it yet. */
#ifndef VIRTIO_ID_TPM
#define VIRTIO_ID_TPM 29
#endif

/*
 * Maximum TPM command/response size.
 * TCG PC Client spec allows up to 4096; swtpm and crosvm use this value.
 */
#define VTPM_BUFSIZE 4096

struct vtpm_dev {
	struct virtqueue	*vq;
	struct tpm_chip		*chip;

	/*
	 * cmd_buf: holds the outgoing TPM command (populated in send()).
	 * resp_buf: VMM writes the response here via the IN descriptor.
	 * Both are allocated at probe time and reused for every command.
	 * Only one command is in flight at a time (enforced by TPM core).
	 */
	u8			*cmd_buf;
	u8			*resp_buf;

	/*
	 * resp_len is written by vtpm_vq_callback() (softirq context)
	 * and read by vtpm_recv() (process context) after the completion.
	 * The completion provides the necessary memory barrier.
	 */
	unsigned int		 resp_len;

	struct completion	 req_complete;
};

/* -----------------------------------------------------------------------
 * Virtqueue callback — called from softirq when VMM returns a response.
 * ----------------------------------------------------------------------- */
static void vtpm_vq_callback(struct virtqueue *vq)
{
	struct vtpm_dev *vtpm = vq->vdev->priv;
	unsigned int len;
	void *buf;

	/*
	 * Drain all used buffers. In normal operation there is exactly one
	 * (we submit one chain at a time), but drain defensively.
	 */
	while ((buf = virtqueue_get_buf(vq, &len)) != NULL) {
		/*
		 * buf is vtpm->cmd_buf (the token we passed to
		 * virtqueue_add_sgs). We only care about len, which is
		 * the number of bytes the VMM wrote into the IN descriptor
		 * (i.e. resp_buf).
		 */
		vtpm->resp_len = len;
		complete(&vtpm->req_complete);
	}
}

/* -----------------------------------------------------------------------
 * TPM core ops
 * ----------------------------------------------------------------------- */

/*
 * send() — called by the TPM core with the raw command to transmit.
 *
 * We enqueue a two-descriptor chain:
 *   sgs[0] OUT: cmd_buf  (cmd_len bytes, readable by VMM)
 *   sgs[1] IN:  resp_buf (VTPM_BUFSIZE bytes, writable by VMM)
 *
 * We set TPM_CHIP_FLAG_IRQ in probe() so the core calls recv()
 * immediately after send() returns, without any status() polling.
 */
static int vtpm_send(struct tpm_chip *chip, u8 *buf, size_t len)
{
	struct vtpm_dev *vtpm = dev_get_drvdata(&chip->dev);
	struct scatterlist sg_out, sg_in;
	struct scatterlist *sgs[2] = { &sg_out, &sg_in };
	int ret;

	if (len > VTPM_BUFSIZE)
		return -E2BIG;

	memcpy(vtpm->cmd_buf, buf, len);

	sg_init_one(&sg_out, vtpm->cmd_buf, len);
	sg_init_one(&sg_in,  vtpm->resp_buf, VTPM_BUFSIZE);

	reinit_completion(&vtpm->req_complete);

	/*
	 * Token (last arg) identifies this request in the callback.
	 * We use cmd_buf as the token — it's what virtqueue_get_buf
	 * returns as buf in vtpm_vq_callback().
	 */
	ret = virtqueue_add_sgs(vtpm->vq, sgs, 1, 1, vtpm->cmd_buf,
				GFP_KERNEL);
	if (ret) {
		dev_err(&chip->dev, "virtqueue_add_sgs: %d\n", ret);
		return ret;
	}

	virtqueue_kick(vtpm->vq);
	return 0;
}

/*
 * recv() — called by the TPM core after send() to retrieve the response.
 *
 * Blocks until vtpm_vq_callback() signals completion (i.e. the VMM has
 * written the response into resp_buf).
 */
static int vtpm_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
	struct vtpm_dev *vtpm = dev_get_drvdata(&chip->dev);
	unsigned int resp_len;

	if (!wait_for_completion_timeout(&vtpm->req_complete,
					 msecs_to_jiffies(120000))) {
		dev_err(&chip->dev, "TPM command timed out (120s)\n");
		return -ETIMEDOUT;
	}

	/*
	 * resp_len was set by vtpm_vq_callback(). The completion ensures
	 * this read happens after the callback's write (memory barrier).
	 */
	resp_len = vtpm->resp_len;

	if (resp_len > count) {
		dev_err(&chip->dev,
			"response too large: %u > %zu\n", resp_len, count);
		return -EIO;
	}

	memcpy(buf, vtpm->resp_buf, resp_len);
	return resp_len;
}

/*
 * cancel() — virtio has no cancellation; the VMM will complete the
 * in-flight command normally. The completion will fire and be ignored
 * by the TPM core after it has given up.
 */
static void vtpm_cancel(struct tpm_chip *chip)
{
	/* no-op */
}

/*
 * status() — not used because we set TPM_CHIP_FLAG_IRQ, but must be
 * provided. Return 0 (no status bits set).
 */
static u8 vtpm_status(struct tpm_chip *chip)
{
	return 0;
}

static bool vtpm_req_canceled(struct tpm_chip *chip, u8 status)
{
	return false;
}

static const struct tpm_class_ops vtpm_ops = {
	/*
	 * TPM_OPS_AUTO_STARTUP: let the TPM core run tpm2_auto_startup()
	 * (TPM2_SelfTest, TPM2_GetCapability, etc.) during chip_register.
	 *
	 * TPM_CHIP_FLAG_IRQ is set dynamically in vtpm_probe() on the chip,
	 * not here — it's a chip flag, not an ops flag.
	 */
	.flags		  = TPM_OPS_AUTO_STARTUP,
	.send		  = vtpm_send,
	.recv		  = vtpm_recv,
	.cancel		  = vtpm_cancel,
	.status		  = vtpm_status,
	.req_canceled	  = vtpm_req_canceled,
};

/* -----------------------------------------------------------------------
 * Probe / remove
 * ----------------------------------------------------------------------- */

static int vtpm_probe(struct virtio_device *vdev)
{
	struct vtpm_dev *vtpm;
	int ret;

	vtpm = kzalloc(sizeof(*vtpm), GFP_KERNEL);
	if (!vtpm)
		return -ENOMEM;

	vtpm->cmd_buf = kzalloc(VTPM_BUFSIZE, GFP_KERNEL);
	vtpm->resp_buf = kzalloc(VTPM_BUFSIZE, GFP_KERNEL);
	if (!vtpm->cmd_buf || !vtpm->resp_buf) {
		ret = -ENOMEM;
		goto err_free_bufs;
	}

	init_completion(&vtpm->req_complete);

	vtpm->vq = virtio_find_single_vq(vdev, vtpm_vq_callback, "vtpmq");
	if (IS_ERR(vtpm->vq)) {
		ret = PTR_ERR(vtpm->vq);
		dev_err(&vdev->dev, "failed to find virtqueue: %d\n", ret);
		goto err_free_bufs;
	}

	vdev->priv = vtpm;
	virtio_device_ready(vdev);

	/*
	 * tpmm_chip_alloc uses devm; the chip is freed automatically when
	 * the device is removed. Sets up /dev/tpm<N> but does not register
	 * with the TPM bus yet.
	 */
	vtpm->chip = tpmm_chip_alloc(&vdev->dev, &vtpm_ops);
	if (IS_ERR(vtpm->chip)) {
		ret = PTR_ERR(vtpm->chip);
		dev_err(&vdev->dev, "tpmm_chip_alloc: %d\n", ret);
		goto err_del_vqs;
	}

	dev_set_drvdata(&vtpm->chip->dev, vtpm);

	/*
	 * TPM_CHIP_FLAG_IRQ: tells tpm_try_transmit() to skip status()
	 * polling and call recv() immediately after send() returns.
	 * This is the correct model for virtio: the callback fires when
	 * the VMM is done, recv() waits on the completion.
	 */
	vtpm->chip->flags |= TPM_CHIP_FLAG_IRQ | TPM_CHIP_FLAG_TPM2;

	/*
	 * tpm_chip_register() runs TPM_OPS_AUTO_STARTUP (tpm2_auto_startup),
	 * creates sysfs entries, and makes /dev/tpmN available.
	 */
	ret = tpm_chip_register(vtpm->chip);
	if (ret) {
		dev_err(&vdev->dev, "tpm_chip_register: %d\n", ret);
		goto err_del_vqs;
	}

	dev_info(&vdev->dev, "virtio TPM registered as /dev/tpm%d\n",
		 vtpm->chip->dev_num);
	return 0;

err_del_vqs:
	vdev->config->del_vqs(vdev);
err_free_bufs:
	kfree(vtpm->resp_buf);
	kfree(vtpm->cmd_buf);
	kfree(vtpm);
	return ret;
}

static void vtpm_remove(struct virtio_device *vdev)
{
	struct vtpm_dev *vtpm = vdev->priv;

	tpm_chip_unregister(vtpm->chip);
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);
	kfree(vtpm->resp_buf);
	kfree(vtpm->cmd_buf);
	kfree(vtpm);
}

static const struct virtio_device_id vtpm_id_table[] = {
	{ VIRTIO_ID_TPM, VIRTIO_DEV_ANY_ID },
	{ 0 },
};
MODULE_DEVICE_TABLE(virtio, vtpm_id_table);

static struct virtio_driver vtpm_driver = {
	.driver.name	= "tpm_virtio",
	.id_table	= vtpm_id_table,
	.probe		= vtpm_probe,
	.remove		= vtpm_remove,
};
module_virtio_driver(vtpm_driver);

MODULE_AUTHOR("Capivara contributors");
MODULE_DESCRIPTION("TPM 2.0 driver over virtio transport");
MODULE_LICENSE("GPL");