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
 * nss_cryptoapi_aead.c
 * 	Interface to communicate Native Linux crypto framework specific data
 * 	to Crypto core specific data
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/random.h>
#include <crypto/internal/aead.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <asm/cmpxchg.h>
#include <linux/delay.h>
#include <linux/crypto.h>
#include <linux/rtnetlink.h>
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

struct nss_cryptoapi_aead_info {
	void *iv;
	struct nss_crypto_params *params;
	nss_crypto_comp_t cb_fn;
	uint16_t cip_len;
	uint16_t auth_len;
};

/*
 * nss_cryptoapi_aead_ctx2session()
 *	Cryptoapi function to get the session ID for an AEAD
 */
int nss_cryptoapi_aead_ctx2session(struct crypto_aead *aead, uint32_t *sid)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(aead);
	struct nss_cryptoapi_ctx *ctx;

	if (strncmp("nss-", crypto_tfm_alg_driver_name(tfm), 4))
		return -EINVAL;

	ctx = crypto_aead_ctx(aead);
	*sid = ctx->sid;

	return 0;
}
EXPORT_SYMBOL(nss_cryptoapi_aead_ctx2session);

/*
 * nss_cryptoapi_aead_init()
 * 	Cryptoapi aead init function.
 */
 int nss_cryptoapi_aead_init(struct crypto_aead *aead)
 {
 	struct crypto_tfm *tfm = crypto_aead_tfm(aead);
 	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(tfm);

 	nss_cfi_assert(ctx);

 	ctx->session_allocated = false;
 	ctx->sid = NSS_CRYPTO_MAX_IDXS;
 	ctx->queued = 0;
 	ctx->completed = 0;
 	ctx->queue_failed = 0;
 	ctx->fallback_req = 0;
 	ctx->sw_tfm = NULL;
 	atomic_set(&ctx->refcnt, 1);

 	nss_cryptoapi_set_magic(ctx);

 	if ((tfm->__crt_alg->cra_flags) & CRYPTO_ALG_NEED_FALLBACK) {
 		aead = crypto_alloc_aead(crypto_tfm_alg_name(tfm), 0,
 				CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK);
 		ctx->sw_tfm = crypto_aead_tfm(aead);
 		if (IS_ERR(ctx->sw_tfm)) {
 			nss_cfi_err("Unable to allocate fallback for aead:%s\n",
			 		crypto_tfm_alg_name(tfm));
 			return -EINVAL;
 		}
 	}

 	if (ctx->sw_tfm)
 		crypto_aead_set_reqsize(__crypto_aead_cast(tfm),
 				sizeof(struct nss_cryptoapi_actx) +
 					crypto_aead_reqsize(aead));
 	else
 		crypto_aead_set_reqsize(__crypto_aead_cast(tfm),
 			offsetof(struct nss_cryptoapi_actx, fallback_req));

 	return 0;
 }

 /*
  * nss_cryptoapi_aead_exit()
  * 	Cryptoapi aead exit function.
  */
 void nss_cryptoapi_aead_exit(struct crypto_aead *aead)
 {
 	struct crypto_tfm *tfm = crypto_aead_tfm(aead);
 	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(tfm);

 	nss_crypto_status_t status;

 	nss_cfi_assert(ctx);

 	if (!atomic_dec_and_test(&ctx->refcnt)) {
 		nss_cfi_err("Process done is not completed, while exit is called\n");
 		nss_cfi_assert(false);
 	}

 	if (ctx->sw_tfm) {
 		crypto_free_aead(__crypto_aead_cast(ctx->sw_tfm));
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
 * nss_cryptoapi_aead_setkey()
 * 	Cryptoapi setkey routine for aead algorithms.
 */
int nss_cryptoapi_aead_setkey(struct crypto_aead *aead, const u8 *key, unsigned int keylen)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(aead);
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(tfm);
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_crypto_key cip;
	struct nss_crypto_key auth;
	uint32_t flag = CRYPTO_TFM_RES_BAD_KEY_LEN;
	nss_crypto_status_t status;
	struct crypto_authenc_keys keys;
	struct crypto_aes_ctx aes;
	unsigned ret = 0;

	/*
	 * validate magic number - init should be called before setkey
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (crypto_authenc_extractkeys(&keys, key, keylen)) {
		ret = -EINVAL;
		goto fail;
	}

	/*
	 * check for the algorithm
	 */
	if (!strncmp("nss-hmac-sha256-rfc3686-ctr-aes", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_AES_CTR;
		auth.algo = NSS_CRYPTO_AUTH_SHA256_HMAC;
		ctx->is_rfc3686 = true;
	} else if (!strncmp("nss-hmac-sha1-rfc3686-ctr-aes", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_AES_CTR;
		auth.algo = NSS_CRYPTO_AUTH_SHA1_HMAC;
		ctx->is_rfc3686 = true;
	} else if (!strncmp("nss-hmac-sha256-cbc-aes", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_AES_CBC;
		auth.algo = NSS_CRYPTO_AUTH_SHA256_HMAC;
	} else if (!strncmp("nss-hmac-sha1-cbc-aes", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_AES_CBC;
		auth.algo = NSS_CRYPTO_AUTH_SHA1_HMAC;
	} else if (!strncmp("nss-hmac-sha1-cbc-3des", crypto_tfm_alg_driver_name(tfm), CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_DES;
		auth.algo = NSS_CRYPTO_AUTH_SHA1_HMAC;
	} else if (!strncmp("nss-hmac-sha256-cbc-3des", crypto_tfm_alg_driver_name(tfm),CRYPTO_MAX_ALG_NAME)) {
		cip.algo = NSS_CRYPTO_CIPHER_DES;
		auth.algo = NSS_CRYPTO_AUTH_SHA256_HMAC;

	} else {
		goto fail;
	}

	ctx->cip_alg = cip.algo;
	ctx->auth_alg = auth.algo;
	ctx->blksize = crypto_tfm_alg_blocksize(tfm);
	cip.key = (uint8_t *)keys.enckey;
	cip.key_len = keys.enckeylen;

	if (ctx->is_rfc3686) {
		if (keys.enckeylen < CTR_RFC3686_NONCE_SIZE)
			goto fail;

		cip.key_len = cip.key_len - CTR_RFC3686_NONCE_SIZE;
		ctx->nonce = *(uint32_t *)(cip.key + cip.key_len);
	}

	switch (ctx->cip_alg) {
	case NSS_CRYPTO_CIPHER_AES_CBC:
	case NSS_CRYPTO_CIPHER_AES_CTR:
		ret = aes_expandkey(&aes, cip.key, cip.key_len);
		break;
	case NSS_CRYPTO_CIPHER_DES:
		ret = verify_aead_des3_key(aead, cip.key, cip.key_len);
		if (ret)
			goto fail;
		goto no_fallback;
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
		/* We don't support AES192, fallback to software crypto */
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
		ret = crypto_aead_setkey(__crypto_aead_cast(ctx->sw_tfm), key, keylen);
		if (ret)
			nss_cfi_err("Failed to set key to the sw crypto");

		if (ctx->fallback_req)
			return ret;
	}

no_fallback:
	auth.key = (uint8_t *)keys.authkey;
	auth.key_len = keys.authkeylen;

	if (!ctx->session_allocated)
		status = nss_crypto_session_alloc(sc->crypto, &cip, &auth, &ctx->sid);
	else
		status = nss_crypto_session_key_update(sc->crypto, &cip, &auth, ctx->sid);

	if (status != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_err("nss_crypto_session_alloc failed - status: %d\n", status);
		ctx->sid = NSS_CRYPTO_MAX_IDXS;
		flag = CRYPTO_TFM_RES_BAD_FLAGS;
		goto fail;
	}

	if (!ctx->session_allocated) {
		nss_cryptoapi_debugfs_add_session(sc, ctx);
		nss_cfi_info("session id created: %d\n", ctx->sid);
		ctx->session_allocated = true;
	}

	return 0;

fail:
	crypto_aead_set_flags(aead, flag);
	return ret;
}

/*
 * nss_cryptoapi_aead_setauthsize()
 * 	Cryptoapi set authsize funtion.
 */
int nss_cryptoapi_aead_setauthsize(struct crypto_aead *authenc, unsigned int authsize)
{
	/*
	 * Store the authsize.
	 */
	struct nss_cryptoapi_ctx *ctx = crypto_aead_ctx(authenc);

	ctx->authsize = (uint16_t)authsize;

	if (ctx->sw_tfm) {
		crypto_aead_setauthsize(__crypto_aead_cast(ctx->sw_tfm), authsize);
	}

	return 0;
}

/*
 * nss_cryptoapi_aead_decrypt_done()
 * 	Cipher/Auth decrypt request completion callback function
 */
void nss_cryptoapi_aead_decrypt_done(struct nss_crypto_buf *buf)
{
	struct nss_cryptoapi_ctx *ctx;
	struct aead_request *req;
	struct crypto_aead *aead;
	uint8_t *data_hmac;
	uint8_t *hw_hmac;
	uint32_t hmac_sz;
	uint16_t tot_len;
	int err = 0;
	uint8_t *data;

	nss_cfi_assert(buf);

	req = (struct aead_request *)nss_crypto_get_cb_ctx(buf);
	aead = crypto_aead_reqtfm(req);

	/*
	 * check cryptoapi context magic number.
	 */
	ctx = crypto_aead_ctx(aead);
	nss_cryptoapi_verify_magic(ctx);

	data = sg_virt(req->src);
	tot_len = req->assoclen + req->cryptlen;

	hmac_sz = crypto_aead_authsize(aead);
	hw_hmac = nss_crypto_get_hash_addr(buf);
	data_hmac = data + tot_len - hmac_sz;

	if (memcmp(hw_hmac, data_hmac, hmac_sz)) {
		err = -EBADMSG;
		nss_cfi_err("HMAC comparison failed\n");
	}

	nss_crypto_buf_free(gbl_ctx.crypto, buf);
	aead_request_complete(req, err);

	nss_cfi_assert(atomic_read(&ctx->refcnt));
	atomic_dec(&ctx->refcnt);
	ctx->completed++;
}

/*
 * nss_cryptoapi_aead_encrypt_done()
 * 	Cipher/Auth encrypt request completion callback function
 */
void nss_cryptoapi_aead_encrypt_done(struct nss_crypto_buf *buf)
{
	struct nss_cryptoapi_ctx *ctx;
	struct aead_request *req;
	struct crypto_aead *aead;
	uint8_t *hw_hmac;
	uint16_t tot_len;
	int err = 0;
	uint8_t *data;

	nss_cfi_assert(buf);

	req = (struct aead_request *)nss_crypto_get_cb_ctx(buf);
	aead = crypto_aead_reqtfm(req);

	/*
	 * check cryptoapi context magic number.
	 */
	ctx = crypto_aead_ctx(aead);
	nss_cryptoapi_verify_magic(ctx);

	data = sg_virt(req->src);
	tot_len = req->assoclen + req->cryptlen;

	hw_hmac = nss_crypto_get_hash_addr(buf);
	memcpy(data + tot_len, hw_hmac, crypto_aead_authsize(aead));

	nss_crypto_buf_free(gbl_ctx.crypto, buf);

	/*
	 * Passing always pass in case of encrypt.
	 * Perhaps whenever core crypto invokes callback routine, it is always pass.
	 */
	aead_request_complete(req, err);

	nss_cfi_assert(atomic_read(&ctx->refcnt));
	atomic_dec(&ctx->refcnt);
	ctx->completed++;
}

/*
 * nss_cryptoapi_validate_addr()
 * 	Cipher/Auth operation valiate virtual addresses of sg's
 */
int nss_cryptoapi_validate_addr(struct nss_cryptoapi_addr *sg_addr)
{
	/*
	 * Currently only in-place transformation is supported.
	 */
	if (sg_addr->src != sg_addr->dst) {
		nss_cfi_err("src!=dst src: 0x%p, dst: 0x%p\n", sg_addr->src, sg_addr->dst);
		return -EINVAL;
	}

	/*
	 * Assoc should include IV, should be before cipher.
	 */
	if (sg_addr->src < sg_addr->start) {
		nss_cfi_err("Invalid src: 0x%p\n", sg_addr->src);
		return -EINVAL;
	}

	return 0;
}

/*
 * nss_cryptoapi_checknget_addr()
 * 	Cryptoapi: obtain sg to virtual address mapping.
 *
 * 	Note: Check for multiple sg in src and dst sg_list to validate virtual address layout
 */
int nss_cryptoapi_checknget_addr(struct aead_request *req, struct nss_cryptoapi_addr *sg_addr)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	uint32_t data_len;

	/*
	 * Currently only single sg is supported. We will error out in the other cases
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
	 * cryptlen = cipherlen + ivlen
	 */
	data_len = req->cryptlen;
	data_len += req->assoclen + crypto_aead_authsize(aead);
	if (data_len > NSS_CRYPTOAPI_MAX_DATA_LEN) {
		nss_cfi_err("Buffer length exceeded limit\n");
		return -EINVAL;
	}

	/*
	 * check start of buffer.
	 * Either of assoc or cipher can be start of the data
	 */
	sg_addr->src = sg_virt(req->src);
	sg_addr->dst = sg_virt(req->dst);
	sg_addr->start = sg_addr->src;

	nss_cfi_assert(sg_addr->src);
	nss_cfi_assert(sg_addr->dst);
	nss_cfi_assert(sg_addr->start);

	if (nss_cryptoapi_validate_addr(sg_addr)) {
		nss_cfi_err("Invalid addresses\n");
		return -EINVAL;
	}

	return 0;
}

/*
 * nss_cryptoapi_aead_transform()
 * 	Crytoapi common routine for encryption and decryption operations.
 */
struct nss_crypto_buf *nss_cryptoapi_aead_transform(struct aead_request *req, struct nss_cryptoapi_aead_info *info)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct nss_cryptoapi_ctx *ctx = crypto_aead_ctx(aead);
	struct nss_crypto_buf *buf;
	struct nss_cryptoapi_addr sg_addr = {0};
	struct nss_cryptoapi *sc = &gbl_ctx;
	nss_crypto_status_t status;
	int tot_buf_len;
	uint32_t iv_size;
	uint16_t cipher_len = 0, auth_len = 0;
	uint8_t *iv_addr;

	nss_cfi_assert(ctx);

	/*
	 * According to RFC3686, AES-CTR algo need not be padded if the
	 * plaintext or ciphertext is unaligned to block size boundary.
	 */
	if ((info->cip_len & (crypto_aead_blocksize(aead) - 1)) && (ctx->cip_alg != NSS_CRYPTO_CIPHER_AES_CTR)) {
		nss_cfi_dbg("Invalid cipher len - Not aligned to algo blocksize\n");
		crypto_aead_set_flags(aead, CRYPTO_TFM_RES_BAD_BLOCK_LEN);
		return NULL;
	}

	/*
	 * Map sg to corresponding virtual addesses.
	 * validate if addresses are valid as expected and sg has single fragment.
	 */
	if (nss_cryptoapi_checknget_addr(req, &sg_addr)) {
		nss_cfi_err("Invalid address!!\n");
		return NULL;
	}

	nss_cfi_dbg("src_vaddr: 0x%p, dst_vaddr: 0x%p, iv: 0x%p\n",
			sg_addr.src, sg_addr.dst, req->iv);

	iv_size = crypto_aead_ivsize(aead);

	/*
	 * The new AEAD interface starts from the point where the data is be authenticated.
	 */
	info->params->auth_skip = 0;
	info->params->cipher_skip = iv_size + req->assoclen;

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
	 * Get IV location and memcpy the IV.
	 * For all AES algos, copy IV of size AES_BLOCK_SIZE.
	 */
	iv_addr = nss_crypto_get_ivaddr(buf);

	switch (ctx->cip_alg) {
	case NSS_CRYPTO_CIPHER_AES_CBC:
	case NSS_CRYPTO_CIPHER_DES:
		memcpy(iv_addr, req->iv, iv_size);
		break;

	case NSS_CRYPTO_CIPHER_AES_CTR:
		((uint32_t *)iv_addr)[0] = ctx->ctx_iv[0];
		((uint32_t *)iv_addr)[1] = ((uint32_t *)req->iv)[0];
		((uint32_t *)iv_addr)[2] = ((uint32_t *)req->iv)[1];
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
	 * Ideally this is true only for ESP/XFRM case.
	 * Need to introduce a check here to if it's an esp packet atleast for the first packet on session.
	 */
	tot_buf_len = req->assoclen + req->cryptlen;

	/*
	 * Fill Cipher and Auth len
	 */
	cipher_len = info->cip_len;
	auth_len = info->auth_len;

	/*
	 * The physical buffer data length provided to crypto will include
	 * space for authentication hash
	 */
	nss_crypto_set_data(buf, sg_addr.start, sg_addr.start, tot_buf_len);
	nss_crypto_set_transform_len(buf, cipher_len, auth_len);

	nss_cfi_dbg("cipher_len: %d, iv_len: %d, auth_len: %d"
			"tot_buf_len: %d, sha: %d, cipher_skip: %d, auth_skip: %d\n",
			buf->cipher_len, iv_size, buf->auth_len,
			tot_buf_len, crypto_aead_authsize(aead), info->params->cipher_skip, info->params->auth_skip);
	nss_cfi_dbg("before transformation\n");
	nss_cfi_dbg_data(sg_addr.start, tot_buf_len, ' ');

	return buf;
}

/*
 * nss_cryptoapi_aead_fallback()
 *	Cryptoapi fallback for aes algorithm.
 */
int nss_cryptoapi_aead_fallback(struct nss_cryptoapi_ctx *ctx, struct aead_request *req)
{
	struct nss_cryptoapi_actx *rctx = aead_request_ctx(req);
	int err;

	if (!ctx->sw_tfm) {
		return -EINVAL;
	}

	/* Set new fallback tfm to the request */
	aead_request_set_tfm(&rctx->fallback_req, __crypto_aead_cast(ctx->sw_tfm));
	aead_request_set_callback(&rctx->fallback_req,
					req->base.flags,
					req->base.complete,
					req->base.data);

	aead_request_set_crypt(&rctx->fallback_req, req->src,
					req->dst, req->cryptlen, req->iv);
	aead_request_set_ad(&rctx->fallback_req, req->assoclen);

	switch (ctx->op) {
	case NSS_CRYPTO_REQ_TYPE_ENCRYPT:
		err = crypto_aead_encrypt(&rctx->fallback_req);
		break;
	case NSS_CRYPTO_REQ_TYPE_DECRYPT:
		err = crypto_aead_decrypt(&rctx->fallback_req);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

/*
 * nss_cryptoapi_aead_crypt()
 * 	Crytoapi common crypt for aead algorithms.
 */
int nss_cryptoapi_aead_crypt(struct aead_request *req, struct nss_cryptoapi_aead_info *info)
{
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct nss_cryptoapi *sc = &gbl_ctx;
	struct nss_crypto_buf *buf;

	/*
	 * check cryptoapi context magic number.
	 */
	nss_cryptoapi_verify_magic(ctx);

	if (ctx->fallback_req)
		return nss_cryptoapi_aead_fallback(ctx, req);

	/*
	 * Check if previous call to setkey couldn't allocate session with core crypto.
	 */
	if (ctx->sid >= NSS_CRYPTO_MAX_IDXS) {
		nss_cfi_err("Invalid session\n");
		return -EINVAL;
	}

	if (nss_crypto_get_cipher(ctx->sid) != ctx->cip_alg) {
		nss_cfi_err("Invalid Cipher Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	if (nss_crypto_get_auth(ctx->sid) != ctx->auth_alg) {
		nss_cfi_err("Invalid Auth Algo for session id: %d\n", ctx->sid);
		return -EINVAL;
	}

	buf = nss_cryptoapi_aead_transform(req, info);
	if (!buf) {
		nss_cfi_err("Invalid parameters\n");
		return -EINVAL;
	}

	/*
	 *  Send the buffer to CORE layer for processing
	 */
	if (nss_crypto_transform_payload(sc->crypto, buf) != NSS_CRYPTO_STATUS_OK) {
		nss_cfi_info("Not enough resources with driver\n");
		nss_crypto_buf_free(sc->crypto, buf);
		ctx->queue_failed++;
		return -EINVAL;
	}

	ctx->queued++;
	atomic_inc(&ctx->refcnt);

	return -EINPROGRESS;
}

/*
 * nss_cryptoapi_aead_aes_encrypt()
 * 	Crytoapi common encrypt for aead algorithms.
 */
int nss_cryptoapi_aead_encrypt(struct aead_request *req)
{
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_ENCRYPT };
	struct nss_cryptoapi_aead_info info = {.cb_fn = nss_cryptoapi_aead_done,
						.params = &params};
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);

	info.cip_len = req->cryptlen;
	info.auth_len = req->assoclen + req->cryptlen;
	ctx->op = NSS_CRYPTO_REQ_TYPE_ENCRYPT;

	return nss_cryptoapi_aead_crypt(req, &info);
}

/*
 * nss_cryptoapi_aead_aes_decrypt()
 * 	Crytoapi common decrypt for aead algorithms.
 */
int nss_cryptoapi_aead_decrypt(struct aead_request *req)
{
	struct nss_crypto_params params = { .req_type = NSS_CRYPTO_REQ_TYPE_AUTH |
							NSS_CRYPTO_REQ_TYPE_DECRYPT };
	struct nss_cryptoapi_aead_info info = {.cb_fn = nss_cryptoapi_aead_done,
						.params = &params};
	struct nss_cryptoapi_ctx *ctx = crypto_tfm_ctx(req->base.tfm);

	info.cip_len = req->cryptlen - ctx->authsize;
	info.auth_len = req->assoclen + req->cryptlen - ctx->authsize;
	ctx->op = NSS_CRYPTO_REQ_TYPE_DECRYPT;

	return nss_cryptoapi_aead_crypt(req, &info);
}
