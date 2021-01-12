/* Copyright (c) 2015-2018 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */

/**
 * nss_cryptoapi_ablk.c
 * 	Interface to communicate Native Linux crypto framework specific data
 * 	to Crypto core specific data
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <asm/cmpxchg.h>
#include <linux/delay.h>
#include <linux/crypto.h>
#include <linux/debugfs.h>

#include <crypto/ctr.h>
#include <crypto/des.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/skcipher.h>

#include <nss_api_if.h>
#include <nss_crypto_if.h>
#include <nss_cfi_if.h>
#include <nss_cryptoapi.h>
#include "nss_cryptoapi_private.h"

extern struct nss_cryptoapi gbl_ctx;

struct nss_cryptoapi_ablk_info {
	void *iv;
	struct nss_crypto_params *params;
	nss_crypto_comp_t cb_fn;
};

/*
 * nss_cryptoapi_skcipher_ctx2session()
 *	Cryptoapi function to get the session ID for an skcipher
 */
int nss_cryptoapi_skcipher_ctx2session(struct crypto_skcipher *sk, uint32_t *sid)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(sk);
	struct crypto_ablkcipher **actx, *ablk;
	struct ablkcipher_tfm *ablk_tfm;
	struct nss_cryptoapi_ctx *ctx;

	if (strncmp("nss-", crypto_tfm_alg_driver_name(tfm), 4))
		return -EINVAL;

	/* Get the ablkcipher from the skcipher */
	actx = crypto_skcipher_ctx(sk);
	if (!actx || !(*actx))
		return -EINVAL;

	/*
	 * The ablkcipher now obtained is a wrapper around the actual
	 * ablkcipher that is created when the skcipher is created.
	 * Hence we derive the required ablkcipher through ablkcipher_tfm.
	 */
	ablk_tfm = crypto_ablkcipher_crt(*actx);
	if (!ablk_tfm)
		return -EINVAL;

	ablk = ablk_tfm->base;
	if (!ablk)
		return -EINVAL;

	/* Get the nss_cryptoapi context stored in the ablkcipher */
	ctx = crypto_ablkcipher_ctx(ablk);

	nss_cfi_assert(ctx);
	nss_cryptoapi_verify_magic(ctx);

	*sid = ctx->sid;
	return 0;
}
EXPORT_SYMBOL(nss_cryptoapi_skcipher_ctx2session);

/*
 * nss_cryptoapi_free_sg_copy()
 * 	Free scatterlist copy.
 */
inline void nss_cryptoapi_free_sg_copy(const int len, struct scatterlist **sg)
{
	if (!*sg || !len)
		return;

	free_pages((unsigned long)sg_virt(*sg), get_order(len));
	kfree(*sg);
	*sg = NULL;
}
/*
 * nss_cryptoapi_free_sg_copy()
 * 	Make scatterlist copy.
 */
inline int nss_cryptoapi_make_sg_copy(struct scatterlist *src,
		struct scatterlist **dst, int len, const bool copy)
{
	void *pages;

	*dst = kmalloc(sizeof(**dst), GFP_KERNEL);
	if (!*dst) {
		nss_cfi_err("No memory to make a copy of scatterlist\n");
		return -ENOMEM;
	}

	pages = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA,
					get_order(len));

	if (!pages) {
		kfree(*dst);
		*dst = NULL;
		nss_cfi_err("no free pages\n");
		return -ENOMEM;
	}

	sg_init_table(*dst, 1);
	sg_set_buf(*dst, pages, len);

	if (copy)
		sg_copy_to_buffer(src, sg_nents(src), pages, len);

	return 0;
}
/*
 * nss_cryptoapi_is_sg_aligned()
 * 	Verify if scatterlist is blocksize aligned.
 */
inline bool nss_cryptoapi_is_sg_aligned(struct scatterlist *sg,
					u32 len, const int blksz)
{
	int nents;

	for (nents = 0; sg; sg = sg_next(sg), ++nents) {
		if (!IS_ALIGNED(sg->offset, 4))
			return false;

		if (len <= sg->length) {
			if (!IS_ALIGNED(len, blksz))
				return false;

			return true;
		}

		if (!IS_ALIGNED(sg->length, blksz))
			return false;

		len -= sg->length;
	}
	return false;
}

/*
 * nss_cryptoapi_skcipher_init()
 * 	Cryptoapi skcipher init function.
 */
int nss_cryptoapi_skcipher_init(struct crypto_tfm *tfm)
{
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_skcipher *skcipher = __crypto_skcipher_cast(tfm);

	nss_cfi_assert(ctx);

	ctx->session_allocated = false;
	ctx->sid = NSS_CRYPTO_MAX_IDXS;
	ctx->queued = 0;
	ctx->completed = 0;
	ctx->queue_failed = 0;
	ctx->fallback_req = false;
	ctx->sw_tfm = NULL;
	ctx->is_rfc3686 = false;
	ctx->cb_fn = nss_cryptoapi_skcipher_done;
	atomic_set(&ctx->refcnt, 1);

	nss_cryptoapi_set_magic(ctx);

	/* Alloc fallback transform for future use */

	if ((tfm->__crt_alg->cra_flags) & CRYPTO_ALG_NEED_FALLBACK) {
		skcipher = crypto_alloc_skcipher(crypto_tfm_alg_name(tfm),
		 				0, CRYPTO_ALG_NEED_FALLBACK);
		ctx->sw_tfm = crypto_skcipher_tfm(skcipher);
		if (IS_ERR(ctx->sw_tfm)) {
			nss_cfi_err("unable to alloc software crypto for %s\n",
						crypto_tfm_alg_name(tfm));
			ctx->sw_tfm = NULL;
			return -EINVAL;
		}
	}

	if (ctx->sw_tfm)
		crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
					sizeof(struct nss_cryptoapi_sctx) +
					crypto_skcipher_reqsize(skcipher));
	else
		crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
			offsetof(struct nss_cryptoapi_sctx, fallback_req));

	return 0;
}

/*
 * nss_cryptoapi_skcipher_exit()
 * 	Cryptoapi skcipher exit function.
 */
void nss_cryptoapi_skcipher_exit(struct crypto_tfm *tfm)
{
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(tfm);
	nss_crypto_status_t status;

	nss_cfi_assert(ctx);

	if (!atomic_dec_and_test(&ctx->refcnt)) {
		nss_cfi_err("Process done is not completed, while exit is called\n");
		nss_cfi_assert(false);
	}

	if (ctx->sw_tfm) {
		crypto_free_skcipher(__crypto_skcipher_cast(ctx->sw_tfm));
		ctx->sw_tfm = NULL;
	}

	if (ctx->session_allocated) {
		nss_cryptoapi_debugfs_del_session(ctx);
		status = nss_crypto_send_session_update(ctx->sid,
				NSS_CRYPTO_SESSION_STATE_FREE,
				NSS_CRYPTO_CIPHER_NULL);

		if (status != NSS_CRYPTO_STATUS_OK) {
			nss_cfi_err("unable to free session: idx %d\n", ctx->sid);
		}
		ctx->session_allocated = false;
	}

	nss_cryptoapi_clear_magic(ctx);
}

/*
 * nss_cryptoapi_skcipher_setkey()
 * 	Cryptoapi setkey routine.
 */
int nss_cryptoapi_skcipher_setkey(struct crypto_skcipher *cipher, const u8 *key, unsigned int keylen)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(cipher);
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(tfm);
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_crypto_key cip;
	struct crypto_aes_ctx aes;
	uint32_t flag = CRYPTO_TFM_RES_BAD_KEY_LEN;
	nss_crypto_status_t status;
	int ret;

	/*
	 * validate magic number - init should be called before setkey
	 */
	nss_cryptoapi_verify_magic(ctx);
	ctx->blksize = crypto_tfm_alg_blocksize(tfm);

	/*
	 * set cipher key
	 */
	cip.key = (uint8_t *)key;
	cip.key_len = keylen;

	/*
	 * check for the algorithm
	 */
	if (!strncmp("nss-rfc3686-ctr-aes", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_AES_CTR;
		ctx->is_rfc3686 = true;
		ctx->blksize = AES_BLOCK_SIZE;

		/*
		 * For RFC3686 CTR mode we construct the IV such that
		 * - First word is key nonce
		 * - Second & third word set to the IV provided by seqiv
		 * - Last word set to counter '1'
		 */
		if (cip.key_len < CTR_RFC3686_NONCE_SIZE)
			goto fail;

		cip.key_len = cip.key_len - CTR_RFC3686_NONCE_SIZE;
		ctx->nonce = *(uint32_t *)(cip.key + cip.key_len);
	} else if (!strncmp("nss-cbc-aes", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_AES_CBC;
	} else if (!strncmp("nss-ctr-aes", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_AES_CTR;
		ctx->is_rfc3686 = false;
		ctx->blksize = AES_BLOCK_SIZE;
	} else if (!strncmp("nss-ecb-aes", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_AES_ECB;
	} else if (!strncmp("nss-cbc-3des", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_DES;
	} else
		goto fail;

	ctx->cip_alg = cip.algo;

	/*
	 * Validate cipher key length
	 */
	switch (ctx->cip_alg) {
	case NSS_CRYPTO_CIPHER_AES_ECB:
	case NSS_CRYPTO_CIPHER_AES_CBC:
	case NSS_CRYPTO_CIPHER_AES_CTR:
		ret = aes_expandkey(&aes, cip.key, cip.key_len);
		break;
	case NSS_CRYPTO_CIPHER_DES:
		ret = verify_skcipher_des3_key(cipher, cip.key);
		if (ret)
			goto fail;
		ctx->fallback_req = false;
		goto skip_fallback;
	default:
		ret = -EINVAL;
	}
	if (ret)
		goto fail;

	switch (cip.key_len) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_256:
		/* success */
		ctx->fallback_req = false;
		break;
	case AES_KEYSIZE_192:
		/*
		 * AES192 is not supported by hardware, falling back to software
		 * crypto.
		 */
		ctx->fallback_req = true;
		break;
	default:
		nss_cfi_err("Bad Cipher key_len(%d)\n", cip.key_len);
		goto fail;
	}

	if ((ctx->fallback_req) && (!ctx->sw_tfm))
			goto fail;

	if (ctx->sw_tfm) {
		 /* Set key to the fallback tfm */
		ret = crypto_skcipher_setkey(__crypto_skcipher_cast(ctx->sw_tfm), key, keylen);
		if (ret)
			nss_cfi_err("Failed to set key to the sw crypto");

		if (ctx->fallback_req)
			return ret;
	}

skip_fallback:
	if (!ctx->session_allocated)
		status = nss_crypto_session_alloc(sc->crypto, &cip, NULL, &ctx->sid);
	else
		status = nss_crypto_session_key_update(sc->crypto, &cip, NULL, ctx->sid);

	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("nss_crypto_session_alloc failed - status: %d\n", status);
		ctx->sid = NSS_CRYPTO_MAX_IDXS;
		flag = CRYPTO_TFM_RES_BAD_FLAGS;
		goto fail;
	}

	if (!ctx->session_allocated) {
		nss_cryptoapi_debugfs_add_session(sc, ctx);
		nss_cfi_info("session id created: %d\n", ctx->sid);
	}

	ctx->session_allocated = true;

	return 0;

fail:
	crypto_skcipher_set_flags(cipher, flag);
	return -EINVAL;
}

/*
 * nss_cryptoapi_skcipher_done()
 * 	Cipher operation completion callback function
 */
void nss_cryptoapi_skcipher_done(struct nss_crypto_buf *buf)
{
	struct nss_cryptoapi_ctx *ctx;
	struct skcipher_request *req;
	struct nss_cryptoapi_sctx *rctx;
	struct nss_cryptoapi_bufctx *bufctx;
	bool complete;
	int err = 0;

	nss_cfi_assert(buf);

	bufctx = (struct nss_cryptoapi_bufctx *)nss_crypto_get_cb_ctx(buf);
	complete = bufctx->complete;
	buf->ctx_0 = bufctx->original_ctx0;

	req = (struct skcipher_request *)bufctx->req;
	rctx = skcipher_request_ctx(req);

	/*
	 * check cryptoapi context magic number.
	 */
	ctx = crypto_tfm_ctx(req->base.tfm);
	nss_cryptoapi_verify_magic(ctx);

	/*
	 * Free Crypto buffer.
	 */
	nss_crypto_buf_free(gbl_ctx.crypto, buf);
	kfree(bufctx);

	if (!complete)
		return;

	/* Store IV for next round (CBC mode only) */
	if ((ctx->cip_alg == NSS_CRYPTO_CIPHER_AES_CBC) ||
			(ctx->cip_alg == NSS_CRYPTO_CIPHER_DES)) {
		if (ctx->op == NSS_CRYPTO_REQ_TYPE_ENCRYPT)
			memcpy(req->iv, bufctx->iv_addr, rctx->iv_size);
	}
	if (rctx->sg_src != req->src)
		nss_cryptoapi_free_sg_cpy(req->cryptlen, &rctx->sg_src);

	if (rctx->sg_dst != req->dst) {
		sg_copy_from_buffer(req->dst, sg_nents(req->dst),
				sg_virt(rctx->sg_dst), req->cryptlen);
		nss_cryptoapi_free_sg_cpy(req->cryptlen, &rctx->sg_dst);
	}

	nss_cfi_dbg("after transformation\n");
	nss_cfi_dbg_data(sg_virt(req->dst), req->cryptlen, ' ');

	nss_cfi_assert(atomic_read(&ctx->refcnt));
	atomic_dec(&ctx->refcnt);

	/*
	 * Passing always pass in case of encrypt.
	 * Perhaps whenever core crypto invloke callback routine, it is always pass.
	 */

	req->base.complete(&req->base, err);

	ctx->completed++;
}

/*
 * nss_cryptoapi_ablk_checkaddr()
 * 	Cryptoapi: obtain sg to virtual address mapping.
 * 	Check for multiple sg in src and dst
 */
int nss_cryptoapi_ablk_checkaddr(struct ablkcipher_request *req)
{
	/*
	 * Currently only single sg is supported
	 * 	return error, if caller send multiple sg for any of src and dst.
	 */
	if (nss_cryptoapi_sg_has_frags(req->src)) {
		nss_cfi_err("Only single sg supported: src invalid\n");
		return -EINVAL;
	}

	if (nss_cryptoapi_sg_has_frags(req->dst)) {
		nss_cfi_err("Only single sg supported: dst invalid\n");
		return -EINVAL;
	}

	/*
	 * If the size of data is more than 65K reject transformation
	 */
	if (req->nbytes > NSS_CRYPTOAPI_MAX_DATA_LEN) {
		nss_cfi_err("Buffer length exceeded limit\n");
		return -EINVAL;
	}

	return 0;
}

/*
 * nss_cryptoapi_ablk_transform()
 * 	Crytoapi common routine for encryption and decryption operations.
 */
struct nss_crypto_buf *nss_cryptoapi_ablk_transform(struct ablkcipher_request *req, struct nss_cryptoapi_ablk_info *info)
{
	struct crypto_ablkcipher *cipher = crypto_ablkcipher_reqtfm(req);
	struct nss_cryptoapi_ctx *ctx = crypto_ablkcipher_ctx(cipher);
	struct nss_crypto_buf *buf;
	struct nss_cryptoapi *sc = &gbl_ctx;
	nss_crypto_status_t status;
	uint16_t iv_size;
	uint16_t cipher_len = 0, auth_len = 0;
	uint8_t *iv_addr;

	nss_cfi_assert(ctx);

	nss_cfi_dbg("src_vaddr: 0x%p, dst_vaddr: 0x%p, iv: 0x%p\n",
			sg_virt(req->src), sg_virt(req->dst), req->info);

	info->params->cipher_skip = 0;
	info->params->auth_skip = 0;

	if (nss_cryptoapi_ablk_checkaddr(req)) {
		nss_cfi_err("Invalid address!!\n");
		return NULL;
	}

	/*
	 * Update the crypto session data
	 */
	status = nss_crypto_session_update(sc->crypto, ctx->sid, info->params);
	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("Invalid crypto session parameters\n");
		return NULL;
	}

	/*
	 * Allocate crypto buf
	 */
	buf = nss_crypto_buf_alloc(sc->crypto);
	if (!buf) {
		nss_cfi_err("not able to allocate crypto buffer\n");
		return NULL;
	}

	/*
	 * set crypto buffer callback
	 */
	nss_crypto_set_cb(buf, info->cb_fn, req);
	nss_crypto_set_session_idx(buf, ctx->sid);

	/*
	 * Get IV location and memcpy the IV
	 */
	iv_size = crypto_ablkcipher_ivsize(cipher);
	iv_addr = nss_crypto_get_ivaddr(buf);

	switch (ctx->cip_alg) {
	case NSS_CRYPTO_CIPHER_AES_CBC:
	case NSS_CRYPTO_CIPHER_DES:
		memcpy(iv_addr, req->info, iv_size);
		break;

	case NSS_CRYPTO_CIPHER_AES_CTR:
		((uint32_t *)iv_addr)[0] = ctx->ctx_iv[0];
		((uint32_t *)iv_addr)[1] = ((uint32_t *)req->info)[0];
		((uint32_t *)iv_addr)[2] = ((uint32_t *)req->info)[1];
		((uint32_t *)iv_addr)[3] = ctx->ctx_iv[3];
		break;

	default:
		/*
		 * Should never happen
		 */
		nss_cfi_err("Invalid cipher algo: %d\n", ctx->cip_alg);
		nss_cfi_assert(false);
	}

	/*
	 * Fill Cipher and Auth len
	 */
	cipher_len = req->nbytes;
	auth_len = 0;

	nss_crypto_set_data(buf, sg_virt(req->src), sg_virt(req->dst), cipher_len);
	nss_crypto_set_transform_len(buf, cipher_len, auth_len);

	nss_cfi_dbg("cipher_len: %d, iv_len: %d, auth_len: %d"
			"cipher_skip: %d, auth_skip: %d\n",
			buf->cipher_len, iv_size, buf->auth_len,
			info->params->cipher_skip, info->params->auth_skip);
	nss_cfi_dbg("before transformation\n");
	nss_cfi_dbg_data(sg_virt(req->src), cipher_len, ' ');

	return buf;
}

/*
 * nss_cryptoapi_skcipher_fallback()
 *	Cryptoapi fallback for skcipher algorithm.
 */
int nss_cryptoapi_skcipher_fallback(struct nss_cryptoapi_ctx *ctx,
					struct skcipher_request *req)
{
	struct nss_cryptoapi_sctx *rctx = skcipher_request_ctx(req);
	int err;

	if (!ctx->sw_tfm) {
		return -EINVAL;
	}

	/* Set new fallback tfm to the request */
	skcipher_request_set_tfm(&rctx->fallback_req,
					__crypto_skcipher_cast(ctx->sw_tfm));
	skcipher_request_set_callback(&rctx->fallback_req,
					req->base.flags,
					req->base.complete,
					req->base.data);
	skcipher_request_set_crypt(&rctx->fallback_req, req->src,
					req->dst, req->cryptlen, req->iv);

	switch (ctx->op) {
	case NSS_CRYPTO_REQ_TYPE_ENCRYPT:
		err = crypto_skcipher_encrypt(&rctx->fallback_req);
		break;
	case NSS_CRYPTO_REQ_TYPE_DECRYPT:
		err = crypto_skcipher_decrypt(&rctx->fallback_req);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static bool nss_cryptoapi_check_ctr(uint32_t iv, uint32_t cryptlen)
{
	uint32_t start, end, ctr, blocks;

	/* Compute data length. */
	blocks = DIV_ROUND_UP(cryptlen, AES_BLOCK_SIZE);
	ctr = ntohl((iv));
	/* Check 32bit counter overflow. */
	start = ctr;
	end = start + blocks - 1;
	if (end < start)
		return true;

	return false;
}

/*
 * nss_cryptoapi_skcipher_crypt()
 * Crytoapi common code for skcipher algorithms.
 */
int nss_cryptoapi_skcipher_crypt(struct skcipher_request *req, struct nss_cryptoapi_ablk_info *info)
{
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_cryptoapi_sctx *rctx = skcipher_request_ctx(req);
	struct crypto_skcipher *skcipher = crypto_skcipher_reqtfm(req);
	bool overflow = false;
	int err;

	if (!req->cryptlen)
		return 0;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	/*
	 * Edge case when 32 bit counter overflows in case of CTR we use software
	 */
	if ((ctx->cip_alg == NSS_CRYPTO_CIPHER_AES_CTR) && (!ctx->is_rfc3686))
		overflow = nss_cryptoapi_check_ctr(*(uint32_t *)(req->iv + 12),
						req->cryptlen);

	if (!(ctx->cip_alg == NSS_CRYPTO_CIPHER_AES_CTR))
		if (!IS_ALIGNED(req->cryptlen, ctx->blksize))
			return -EINVAL;

	if ((ctx->fallback_req) || overflow)
		return nss_cryptoapi_skcipher_fallback(ctx, req);

	rctx->iv_size = crypto_skcipher_ivsize(skcipher);

	err = nss_cryptoapi_send_req(req, info);
	if (!(err == -EINPROGRESS))
		return err;

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_skcipher_encrypt()
 * Crytoapi encrypt for des/aes-ecb/cbc/rfc3686/ctr) algorithms.
 */
int nss_cryptoapi_skcipher_encrypt(struct skcipher_request *req)
{
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_cryptoapi_ablk_info info = {.cb_fn = nss_cryptoapi_skcipher_done,
						.params = &params};
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);

	ctx->op = NSS_CRYPTO_REQ_TYPE_ENCRYPT;

	return nss_cryptoapi_skcipher_crypt(req, &info);
}

/*
 * nss_cryptoapi_ablk_aes_decrypt()
 * 	Crytoapi decrypt for des/aes-ecb/cbc/rfc3686/ctr) algorithms.
 */
int nss_cryptoapi_skcipher_decrypt(struct skcipher_request *req)
{
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_DECRYPT };
	struct nss_cryptoapi_ablk_info info = {.cb_fn = nss_cryptoapi_skcipher_done,
						.params = &params};
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);

	ctx->op = NSS_CRYPTO_REQ_TYPE_DECRYPT;

	return nss_cryptoapi_skcipher_crypt(req, &info);
}
