/* Copyright (c) 2015-2018, The Linux Foundation. All rights reserved.
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

#ifndef __NSS_CRYPTOAPI_PRIVATE_H
#define __NSS_CRYPTOAPI_PRIVATE_H

/**
 * nss_cryptoapi.h
 *	Cryptoapi (Linux Crypto API framework) specific nss cfi header file
 */

#define NSS_CRYPTOAPI_MAX_DATA_LEN	((uint16_t) -1)
#define nss_cryptoapi_sg_has_frags(s)	sg_next(s)

#define NSS_CRYPTOAPI_DEBUGFS_NAME_SZ	64
#define NSS_CRYPTOAPI_MAGIC		0x7FED

/*
 * Cryptoapi sg virtual addresses used during Encryption/Decryption operations
 */
struct nss_cryptoapi_addr {
	uint8_t *src;
	uint8_t *dst;
	uint8_t *iv;
	uint8_t *start;
};

/*
 * Framework specific handle this will be used to communicate framework
 * specific data to Core specific data
 */
struct nss_cryptoapi {
	nss_crypto_handle_t crypto;		/* crypto handle */
	struct dentry *root_dentry;
	struct dentry *stats_dentry;
	atomic_t registered;			/* Registration flag */
};

struct nss_cryptoapi_ctx {
	uint64_t queued;
	uint64_t completed;
	uint64_t queue_failed;
	struct dentry *session_dentry;
	struct crypto_tfm *sw_tfm;
	uint32_t sid;
	atomic_t refcnt;
	uint16_t authsize;
	uint16_t blksize;
	uint16_t magic;
	uint32_t nonce;
	bool fallback_req;
	enum nss_crypto_cipher cip_alg;
	enum nss_crypto_auth auth_alg;
	enum nss_crypto_req_type op;
	bool is_rfc3686;
	bool fake_seqiv;
	bool session_allocated;
	nss_crypto_comp_t cb_fn;	/**< completion callback function */
};

struct nss_cryptoapi_sctx {
	uint32_t			iv_size;
	struct scatterlist		*sg_src;
	struct scatterlist		*sg_dst;
	/* request fallback, keep at the end */
	struct skcipher_request fallback_req;
};

struct nss_cryptoapi_actx {
	uint32_t			iv_size;
	struct scatterlist		*sg_src;
	struct scatterlist		*sg_dst;
	/* request fallback, keep at the end */
	struct aead_request fallback_req;
};

struct nss_cryptoapi_bufctx {
	bool		complete;
	struct skcipher_request	*req;
	uint8_t		*iv_addr;
	uint32_t	original_ctx0;
};

static inline void nss_cryptoapi_verify_magic(struct nss_cryptoapi_ctx *ctx)
{
	BUG_ON(unlikely(ctx->magic != NSS_CRYPTOAPI_MAGIC));
}

static inline void nss_cryptoapi_set_magic(struct nss_cryptoapi_ctx *ctx)
{
	ctx->magic = NSS_CRYPTOAPI_MAGIC;
}

static inline void nss_cryptoapi_clear_magic(struct nss_cryptoapi_ctx *ctx)
{
	ctx->magic = 0;
}

static inline bool nss_cryptoapi_is_decrypt(struct nss_cryptoapi_ctx *ctx)
{
	return ctx->op & NSS_CRYPTO_REQ_TYPE_DECRYPT;
}

/*
 * nss_cryptoapi_check_unalign()
 *	Cryptoapi verify if length is aligned to boundary.
 */
static inline bool nss_cryptoapi_check_unalign(uint32_t len, uint32_t boundary)
{
	return !!(len & (boundary - 1));
}

/*
 * function prototypes
 */

/* Debug fs */
void nss_cryptoapi_debugfs_add_stats(struct dentry *parent, struct nss_cryptoapi_ctx *session_ctx);
void nss_cryptoapi_debugfs_add_session(struct nss_cryptoapi *gbl_ctx, struct nss_cryptoapi_ctx *session_ctx);
void nss_cryptoapi_debugfs_del_session(struct nss_cryptoapi_ctx *session_ctx);
void nss_cryptoapi_debugfs_init(struct nss_cryptoapi *gbl_ctx);
void nss_cryptoapi_debugfs_exit(struct nss_cryptoapi *gbl_ctx);

/* AEAD */
int nss_cryptoapi_aead_init(struct crypto_aead *aead);
void nss_cryptoapi_aead_exit(struct crypto_aead *aead);
int nss_cryptoapi_aead_setkey(struct crypto_aead *aead, const u8 *key, unsigned int keylen);

int nss_cryptoapi_aead_setauthsize(struct crypto_aead *authenc, unsigned int authsize);
int nss_cryptoapi_aead_encrypt(struct aead_request *req);
int nss_cryptoapi_aead_decrypt(struct aead_request *req);

/* SKCIPHER */
int nss_cryptoapi_skcipher_init(struct crypto_tfm *tfm);
void nss_cryptoapi_skcipher_exit(struct crypto_tfm *tfm);
int nss_cryptoapi_skcipher_setkey(struct crypto_skcipher *cipher, const u8 *key, unsigned int len);

int nss_cryptoapi_skcipher_encrypt(struct skcipher_request *req);
int nss_cryptoapi_skcipher_decrypt(struct skcipher_request *req);

/* Helper functions */
inline void nss_cryptoapi_free_sg_copy(const int len, struct scatterlist **sg);
inline int nss_cryptoapi_make_sg_copy(struct scatterlist *src,
		struct scatterlist **dst, int len, const bool copy);
inline bool nss_cryptoapi_is_sg_aligned(struct scatterlist *sg, u32 len, const int blksz);

#endif /* __NSS_CRYPTOAPI_PRIVATE_H */
