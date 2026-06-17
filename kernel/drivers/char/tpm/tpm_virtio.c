// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * tpm_virtio.c - Driver for TPM over virtio
 *
 * Provides a TPM device backed by a virtio transport.
 * The VMM (e.g. libkrun, crosvm) exposes a virtio device with
 * VIRTIO_ID_TPM (29) and a single virtqueue. TPM commands are sent
 * as OUT buffers and responses received as IN buffers in the same
 * descriptor chain.
 *
 * Based on the virtio driver documentation and the crosvm virtio-tpm
 * device specification. Protocol:
 *   - Single virtqueue ("vtpmq")
 *   - Command: guest → host (OUT scatter, up to TPM_BUFSIZE bytes)
 *   - Response: host → guest (IN scatter, up to TPM_BUFSIZE bytes)
 *   - Synchronous: one command in flight at a time
 *
 * Copyright (c) 2026 Capivara contributors
 */

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/tpm.h>
#include <linux/completion.h>
#include <linux/scatterlist.h>

/* virtio device ID for TPM — matches crosvm and libkrun VMM side */
#ifndef VIRTIO_ID_TPM
#define VIRTIO_ID_TPM 29
#endif

/* Maximum TPM command/response size (TCG spec: 4096 is typical max) */
#define TPM_BUFSIZE 4096

struct vtpm_dev {
	struct virtqueue *vq;
	struct tpm_chip *chip;
	struct completion req_complete;

	/* Buffers for command and response — single in-flight request */
	u8 *cmd_buf;
	u8 *resp_buf;
	unsigned int resp_len;
};

static void vtpm_recv_done(struct virtqueue *vq)
{
	struct vtpm_dev *vtpm = vq->vdev->priv;
	unsigned int len;
	void *buf;

	buf = virtqueue_get_buf(vq, &len);
	if (!buf)
		return;

	vtpm->resp_len = len;
	complete(&vtpm->req_complete);
}

/*
 * Send a TPM command via virtqueue and wait for the response.
 *
 * The descriptor chain has two entries:
 *   [0] OUT: command buffer (cmd_len bytes)
 *   [1] IN:  response buffer (TPM_BUFSIZE bytes, host fills actual response)
 */
static int vtpm_send_recv(struct vtpm_dev *vtpm,
			  const u8 *cmd, size_t cmd_len,
			  u8 *resp, size_t resp_len)
{
	struct scatterlist sg_out, sg_in;
	struct scatterlist *sgs[2] = { &sg_out, &sg_in };
	int ret;

	if (cmd_len > TPM_BUFSIZE || resp_len > TPM_BUFSIZE)
		return -EINVAL;

	/* Copy command to DMA-safe buffer */
	memcpy(vtpm->cmd_buf, cmd, cmd_len);

	sg_init_one(&sg_out, vtpm->cmd_buf, cmd_len);
	sg_init_one(&sg_in, vtpm->resp_buf, resp_len);

	reinit_completion(&vtpm->req_complete);

	ret = virtqueue_add_sgs(vtpm->vq, sgs, 1, 1, vtpm->cmd_buf, GFP_KERNEL);
	if (ret) {
		dev_err(&vtpm->vq->vdev->dev,
			"virtqueue_add_sgs failed: %d\n", ret);
		return ret;
	}

	virtqueue_kick(vtpm->vq);

	/* Wait for VMM to process and return response */
	if (!wait_for_completion_timeout(&vtpm->req_complete,
					 msecs_to_jiffies(60000))) {
		dev_err(&vtpm->vq->vdev->dev,
			"TPM command timed out after 60s\n");
		return -ETIMEDOUT;
	}

	/* Copy response to caller buffer */
	if (vtpm->resp_len > resp_len)
		vtpm->resp_len = resp_len;

	memcpy(resp, vtpm->resp_buf, vtpm->resp_len);
	return vtpm->resp_len;
}

/*
 * TPM subsystem ops — called by the kernel TPM core.
 */

static int vtpm_tpm_op_send(struct tpm_chip *chip, u8 *buf, size_t len)
{
	/* The TPM core calls send() then recv() separately.
	 * We store the command and send it in recv().
	 * This follows the pattern of other TPM drivers. */
	struct vtpm_dev *vtpm = dev_get_drvdata(&chip->dev);

	if (len > TPM_BUFSIZE)
		return -E2BIG;

	memcpy(vtpm->cmd_buf, buf, len);
	vtpm->resp_len = len; /* stash cmd length for recv */
	return 0;
}

static int vtpm_tpm_op_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
	struct vtpm_dev *vtpm = dev_get_drvdata(&chip->dev);
	size_t cmd_len = vtpm->resp_len; /* was stashed by send() */
	int ret;

	ret = vtpm_send_recv(vtpm, vtpm->cmd_buf, cmd_len, buf, count);
	return ret;
}

static void vtpm_tpm_op_cancel(struct tpm_chip *chip)
{
	/* virtio has no cancellation mechanism — noop */
}

static u8 vtpm_tpm_op_status(struct tpm_chip *chip)
{
	return 0;
}

static bool vtpm_tpm_op_req_canceled(struct tpm_chip *chip, u8 status)
{
	return false;
}

static const struct tpm_class_ops vtpm_tpm_ops = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.send = vtpm_tpm_op_send,
	.recv = vtpm_tpm_op_recv,
	.cancel = vtpm_tpm_op_cancel,
	.status = vtpm_tpm_op_status,
	.req_canceled = vtpm_tpm_op_req_canceled,
};

static int vtpm_probe(struct virtio_device *vdev)
{
	struct vtpm_dev *vtpm;
	int ret;

	vtpm = kzalloc(sizeof(*vtpm), GFP_KERNEL);
	if (!vtpm)
		return -ENOMEM;

	/* Allocate DMA-safe buffers */
	vtpm->cmd_buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	vtpm->resp_buf = kzalloc(TPM_BUFSIZE, GFP_KERNEL);
	if (!vtpm->cmd_buf || !vtpm->resp_buf) {
		ret = -ENOMEM;
		goto err_free;
	}

	init_completion(&vtpm->req_complete);

	/* Find the single virtqueue */
	vtpm->vq = virtio_find_single_vq(vdev, vtpm_recv_done, "vtpmq");
	if (IS_ERR(vtpm->vq)) {
		ret = PTR_ERR(vtpm->vq);
		dev_err(&vdev->dev, "failed to find virtqueue: %d\n", ret);
		goto err_free;
	}

	vdev->priv = vtpm;

	virtio_device_ready(vdev);

	/* Allocate and register TPM chip */
	vtpm->chip = tpmm_chip_alloc(&vdev->dev, &vtpm_tpm_ops);
	if (IS_ERR(vtpm->chip)) {
		ret = PTR_ERR(vtpm->chip);
		dev_err(&vdev->dev, "tpmm_chip_alloc failed: %d\n", ret);
		goto err_vq;
	}

	dev_set_drvdata(&vtpm->chip->dev, vtpm);

	ret = tpm_chip_register(vtpm->chip);
	if (ret) {
		dev_err(&vdev->dev, "tpm_chip_register failed: %d\n", ret);
		goto err_vq;
	}

	dev_info(&vdev->dev, "virtio TPM registered as /dev/tpm%d\n",
		 vtpm->chip->dev_num);
	return 0;

err_vq:
	vdev->config->del_vqs(vdev);
err_free:
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
	.driver.name = "tpm_virtio",
	.id_table = vtpm_id_table,
	.probe = vtpm_probe,
	.remove = vtpm_remove,
};

module_virtio_driver(vtpm_driver);

MODULE_AUTHOR("Capivara contributors");
MODULE_DESCRIPTION("TPM driver over virtio transport");
MODULE_LICENSE("GPL");