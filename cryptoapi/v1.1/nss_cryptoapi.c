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
 * nss_cryptoapi.c
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
#include "nss_cryptoapi_private.h"

struct nss_cryptoapi gbl_ctx;

/*
 * crypto_alg structure initialization
 */

/*
 * AEAD (Cipher and Authentication)
 */
 struct aead_alg cryptoapi_aead_algs[] = {
 	{
 		.init       = nss_cryptoapi_aead_init,
 		.exit       = nss_cryptoapi_aead_exit,
 		.setkey = nss_cryptoapi_aead_setkey,
 		.setauthsize = nss_cryptoapi_aead_setauthsize,
 		.encrypt = nss_cryptoapi_aead_encrypt,
 		.decrypt = nss_cryptoapi_aead_decrypt,
 		.ivsize         = DES3_EDE_BLOCK_SIZE,
 		.maxauthsize    = SHA1_DIGEST_SIZE,
 		.base = {
 			.cra_name       = "authenc(hmac(sha1),cbc(des3_ede))",
 			.cra_driver_name = "nss-hmac-sha1-cbc-3des",
 			.cra_priority   = 300,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
  						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = DES3_EDE_BLOCK_SIZE,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0,
 			.cra_module     = THIS_MODULE,
 		},
 	},
 	{
 		.init       = nss_cryptoapi_aead_init,
 		.exit       = nss_cryptoapi_aead_exit,
 		.setkey = nss_cryptoapi_aead_setkey,
 		.setauthsize = nss_cryptoapi_aead_setauthsize,
 		.encrypt = nss_cryptoapi_aead_encrypt,
 		.decrypt = nss_cryptoapi_aead_decrypt,
 		.ivsize         = DES3_EDE_BLOCK_SIZE,
 		.maxauthsize    = SHA256_DIGEST_SIZE,
 		.base  = {
 			.cra_name       = "authenc(hmac(sha256),cbc(des3_ede))",
 			.cra_driver_name = "nss-hmac-sha256-cbc-3des",
 			.cra_priority   = 300,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
  						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = DES3_EDE_BLOCK_SIZE,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0,
 			.cra_module     = THIS_MODULE,
 		},
 	},
 	{
 		.init       = nss_cryptoapi_aead_init,
 		.exit       = nss_cryptoapi_aead_exit,
 		.setkey = nss_cryptoapi_aead_setkey,
 		.setauthsize = nss_cryptoapi_aead_setauthsize,
 		.encrypt = nss_cryptoapi_aead_encrypt,
 		.decrypt = nss_cryptoapi_aead_decrypt,
 		.ivsize         = AES_BLOCK_SIZE,
 		.maxauthsize    = SHA1_DIGEST_SIZE,
 		.base = {
 			.cra_name       = "authenc(hmac(sha1),cbc(aes))",
 			.cra_driver_name = "nss-hmac-sha1-cbc-aes",
 			.cra_priority   = 10000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
  						CRYPTO_ALG_NEED_FALLBACK |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = AES_BLOCK_SIZE,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0,
 			.cra_module     = THIS_MODULE,
 		},
 	},
 	{
 		.init	= nss_cryptoapi_aead_init,
 		.exit	= nss_cryptoapi_aead_exit,
 		.setkey = nss_cryptoapi_aead_setkey,
 		.setauthsize = nss_cryptoapi_aead_setauthsize,
 		.encrypt = nss_cryptoapi_aead_encrypt,
 		.decrypt = nss_cryptoapi_aead_decrypt,
 		.ivsize         = AES_BLOCK_SIZE,
 		.maxauthsize    = SHA256_DIGEST_SIZE,
 		.base = {
 			.cra_name       = "authenc(hmac(sha256),cbc(aes))",
 			.cra_driver_name = "nss-hmac-sha256-cbc-aes",
 			.cra_priority   = 10000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
  						CRYPTO_ALG_NEED_FALLBACK |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = AES_BLOCK_SIZE,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0,
 			.cra_module     = THIS_MODULE,
 		},
 	},
 	{
 		.init	= nss_cryptoapi_aead_init,
 		.exit	= nss_cryptoapi_aead_exit,
 		.setkey = nss_cryptoapi_aead_setkey,
 		.encrypt = nss_cryptoapi_aead_encrypt,
 		.decrypt = nss_cryptoapi_aead_decrypt,
 		.ivsize = CTR_RFC3686_IV_SIZE,
 		.setauthsize = nss_cryptoapi_aead_setauthsize,
 		.maxauthsize = SHA1_DIGEST_SIZE,
 		.base = {
 			.cra_name       = "authenc(hmac(sha1),rfc3686(ctr(aes)))",
 			.cra_driver_name = "nss-hmac-sha1-rfc3686-ctr-aes",
 			.cra_priority   = 10000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = 1,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0,
 			.cra_module     = THIS_MODULE,
 		},
 	},
 	{
 		.init	= nss_cryptoapi_aead_init,
 		.exit	= nss_cryptoapi_aead_exit,
 		.setkey = nss_cryptoapi_aead_setkey,
 		.setauthsize = nss_cryptoapi_aead_setauthsize,
 		.encrypt = nss_cryptoapi_aead_encrypt,
 		.decrypt = nss_cryptoapi_aead_decrypt,
 		.ivsize         = CTR_RFC3686_IV_SIZE,
 		.maxauthsize    = SHA256_DIGEST_SIZE,
 		.base = {
 			.cra_name       = "authenc(hmac(sha256),rfc3686(ctr(aes)))",
 			.cra_driver_name = "nss-hmac-sha256-rfc3686-ctr-aes",
 			.cra_priority   = 10000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
  						CRYPTO_ALG_NEED_FALLBACK |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = 1,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0,
 			.cra_module     = THIS_MODULE,
 		},
 	},
 };

 /*
  *   skcipher cipher algorithms
  */

 static struct skcipher_alg cryptoapi_skcipher_algs[] = {
 	{
 		.setkey         = nss_cryptoapi_skcipher_setkey,
 		.encrypt        = nss_cryptoapi_skcipher_encrypt,
 		.decrypt        = nss_cryptoapi_skcipher_decrypt,
 		.ivsize         = DES3_EDE_BLOCK_SIZE,
 		.min_keysize    = DES3_EDE_KEY_SIZE,
 		.max_keysize    = DES3_EDE_KEY_SIZE,
 		.base = {
 			.cra_name       = "cbc(des3_ede)",
 			.cra_driver_name = "nss-cbc-3des",
 			.cra_priority   = 1000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = DES3_EDE_BLOCK_SIZE,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0,
 			.cra_module     = THIS_MODULE,
 			.cra_init       = nss_cryptoapi_skcipher_init,
 			.cra_exit       = nss_cryptoapi_skcipher_exit,
 		},
 	},
 	{
 		.setkey         = nss_cryptoapi_skcipher_setkey,
 		.encrypt        = nss_cryptoapi_skcipher_encrypt,
 		.decrypt        = nss_cryptoapi_skcipher_decrypt,
 		.min_keysize    = AES_MIN_KEY_SIZE,
 		.max_keysize    = AES_MAX_KEY_SIZE,
 		.ivsize         = AES_BLOCK_SIZE,
 		.base = {
 			.cra_name       = "cbc(aes)",
 			.cra_driver_name = "nss-cbc-aes",
 			.cra_priority   = 10000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
 						CRYPTO_ALG_NEED_FALLBACK |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = AES_BLOCK_SIZE,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0xf,
 			.cra_module     = THIS_MODULE,
 			.cra_init       = nss_cryptoapi_skcipher_init,
 			.cra_exit       = nss_cryptoapi_skcipher_exit,

 		},
 	},
 	{
 		.setkey         = nss_cryptoapi_skcipher_setkey,
 		.encrypt        = nss_cryptoapi_skcipher_encrypt,
 		.decrypt        = nss_cryptoapi_skcipher_decrypt,
 		.min_keysize    = AES_MIN_KEY_SIZE,
 		.max_keysize    = AES_MAX_KEY_SIZE,
 		.ivsize         = 0,
 		.base = {
 			.cra_name       = "ecb(aes)",
 			.cra_driver_name = "nss-ecb-aes",
 			.cra_priority   = 10000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
 						CRYPTO_ALG_NEED_FALLBACK |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = AES_BLOCK_SIZE,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0xf,
 			.cra_module     = THIS_MODULE,
 			.cra_init       = nss_cryptoapi_skcipher_init,
 			.cra_exit       = nss_cryptoapi_skcipher_exit,

 		},
 	},
 	{
 		.setkey         = nss_cryptoapi_skcipher_setkey,
 		.encrypt        = nss_cryptoapi_skcipher_encrypt,
 		.decrypt        = nss_cryptoapi_skcipher_decrypt,
 		.ivsize         = AES_BLOCK_SIZE,
 		.min_keysize    = AES_MIN_KEY_SIZE,
 		.max_keysize    = AES_MAX_KEY_SIZE,
 		.base = {
 			.cra_name       = "ctr(aes)",
 			.cra_driver_name = "nss-ctr-aes",
 			.cra_priority   = 10000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
 						CRYPTO_ALG_NEED_FALLBACK |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = 1,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0xf,
 			.cra_module     = THIS_MODULE,
 			.cra_init           = nss_cryptoapi_skcipher_init,
 			.cra_exit           = nss_cryptoapi_skcipher_exit,
 		},
 	},
 	{
 		.setkey         = nss_cryptoapi_skcipher_setkey,
 		.encrypt        = nss_cryptoapi_skcipher_encrypt,
 		.decrypt        = nss_cryptoapi_skcipher_decrypt,
 		.ivsize         = CTR_RFC3686_IV_SIZE,
 		.min_keysize    = AES_MIN_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
 		.max_keysize    = AES_MAX_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
 		.base = {
 			.cra_name       = "rfc3686(ctr(aes))",
 			.cra_driver_name = "nss-rfc3686-ctr-aes",
 			.cra_priority   = 30000,
 			.cra_flags      = CRYPTO_ALG_ASYNC |
 						CRYPTO_ALG_NEED_FALLBACK |
 						CRYPTO_ALG_KERN_DRIVER_ONLY,
 			.cra_blocksize  = 1,
 			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
 			.cra_alignmask  = 0xf,
 			.cra_module     = THIS_MODULE,
 			.cra_init       = nss_cryptoapi_skcipher_init,
 			.cra_exit       = nss_cryptoapi_skcipher_exit,
 		},
 	},
 };

/*
 *   skcipher cipher algorithms
 */

static struct skcipher_alg cryptoapi_skcipher_algs[] = {
	{
		.setkey         = nss_cryptoapi_skcipher_setkey,
		.encrypt        = nss_cryptoapi_skcipher_encrypt,
		.decrypt        = nss_cryptoapi_skcipher_decrypt,
		.min_keysize    = AES_MIN_KEY_SIZE,
		.max_keysize    = AES_MAX_KEY_SIZE,
		.ivsize         = AES_BLOCK_SIZE,
		.base = {
			.cra_name       = "cbc(aes)",
			.cra_driver_name = "nss-cbc-aes",
			.cra_priority   = 10000,
			.cra_flags      = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_NEED_FALLBACK |
						CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize  = AES_BLOCK_SIZE,
			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
			.cra_alignmask  = 0xf,
			.cra_module     = THIS_MODULE,
			.cra_init       = nss_cryptoapi_skcipher_init,
			.cra_exit       = nss_cryptoapi_skcipher_exit,

		},
	},
	{
		.setkey         = nss_cryptoapi_skcipher_setkey,
		.encrypt        = nss_cryptoapi_skcipher_encrypt,
		.decrypt        = nss_cryptoapi_skcipher_decrypt,
		.ivsize         = CTR_RFC3686_IV_SIZE,
		.min_keysize    = AES_MIN_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.max_keysize    = AES_MAX_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.base = {
			.cra_name       = "rfc3686(ctr(aes))",
			.cra_driver_name = "nss-rfc3686-ctr-aes",
			.cra_priority   = 30000,
			.cra_flags      = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_NEED_FALLBACK |
						CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize  = 1,
			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
			.cra_alignmask  = 0xf,
			.cra_module     = THIS_MODULE,
			.cra_init       = nss_cryptoapi_skcipher_init,
			.cra_exit       = nss_cryptoapi_skcipher_exit,
		},
	},
	{
		.setkey         = nss_cryptoapi_skcipher_setkey,
		.encrypt        = nss_cryptoapi_skcipher_encrypt,
		.decrypt        = nss_cryptoapi_skcipher_decrypt,
		.ivsize         = DES3_EDE_BLOCK_SIZE,
		.min_keysize    = DES3_EDE_KEY_SIZE,
		.max_keysize    = DES3_EDE_KEY_SIZE,
		.base = {
			.cra_name       = "cbc(des3_ede)",
			.cra_driver_name = "nss-cbc-3des",
			.cra_priority   = 1000,
			.cra_flags      = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize  = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
			.cra_alignmask  = 0,
			.cra_module     = THIS_MODULE,
			.cra_init       = nss_cryptoapi_skcipher_init,
			.cra_exit       = nss_cryptoapi_skcipher_exit,
		},
	},
	{
		.setkey         = nss_cryptoapi_skcipher_setkey,
		.encrypt        = nss_cryptoapi_skcipher_encrypt,
		.decrypt        = nss_cryptoapi_skcipher_decrypt,
		.ivsize         = AES_BLOCK_SIZE,
		.min_keysize    = AES_MIN_KEY_SIZE,
		.max_keysize    = AES_MAX_KEY_SIZE,
		.base = {
			.cra_name       = "ctr(aes)",
			.cra_driver_name = "nss-ctr-aes",
			.cra_priority   = 10000,
			.cra_flags      = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_NEED_FALLBACK |
						CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize  = 1,
			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
			.cra_alignmask  = 0xf,
			.cra_module     = THIS_MODULE,
			.cra_init           = nss_cryptoapi_skcipher_init,
			.cra_exit           = nss_cryptoapi_skcipher_exit,
		},
	},
	{
		.setkey         = nss_cryptoapi_skcipher_setkey,
		.encrypt        = nss_cryptoapi_skcipher_encrypt,
		.decrypt        = nss_cryptoapi_skcipher_decrypt,
		.min_keysize    = AES_MIN_KEY_SIZE,
		.max_keysize    = AES_MAX_KEY_SIZE,
		.ivsize         = 0,
		.base = {
			.cra_name       = "ecb(aes)",
			.cra_driver_name = "nss-ecb-aes",
			.cra_priority   = 10000,
			.cra_flags      = CRYPTO_ALG_ASYNC |
						CRYPTO_ALG_NEED_FALLBACK |
						CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize  = AES_BLOCK_SIZE,
			.cra_ctxsize    = sizeof(struct nss_cryptoapi_ctx),
			.cra_alignmask  = 0xf,
			.cra_module     = THIS_MODULE,
			.cra_init       = nss_cryptoapi_skcipher_init,
			.cra_exit       = nss_cryptoapi_skcipher_exit,

		},
	},
};

/*
 * nss_cryptoapi_register()
 * 	register crypto core with the cryptoapi CFI
 */
static nss_crypto_user_ctx_t nss_cryptoapi_register(nss_crypto_handle_t crypto)
{
	int i, rc;
	struct nss_cryptoapi *sc = &gbl_ctx;

	nss_cfi_info("Registering nss_cryptoapi with core\n");

	sc->crypto = crypto;

	for (i = 0; i < ARRAY_SIZE(cryptoapi_skcipher_algs); i++) {
		rc = crypto_register_skcipher(&cryptoapi_skcipher_algs[i]);
		if (rc) {
			nss_cfi_trace("Skcipher registration failed, algo: %s\n"
				, cryptoapi_skcipher_algs[i].base.cra_name);
			cryptoapi_skcipher_algs[i].base.cra_flags = 0;
			continue;
		}
		nss_cfi_info("Skcipher registration succeeded, algo: %s\n",
				cryptoapi_skcipher_algs[i].base.cra_name);
	}

	for (i = 0; i < ARRAY_SIZE(cryptoapi_aead_algs); i++) {
		rc = crypto_register_aead(&cryptoapi_aead_algs[i]);
		if (rc) {
			cryptoapi_aead_algs[i].base.cra_flags = 0;
			nss_cfi_trace("Aead registration failed, algo: %s\n", cryptoapi_aead_algs[i].base.cra_name);
			continue;
		}
		nss_cfi_info("Aead registration succeeded, algo: %s\n", cryptoapi_aead_algs[i].base.cra_name);
	}

	/*
	 * Set the registered flag
	 */
	atomic_set(&gbl_ctx.registered, 1);

	/*
	 * Initialize debugfs for cryptoapi.
	 */
	nss_cryptoapi_debugfs_init(sc);

	return sc;
}

/*
 * nss_cryptoapi_unregister()
 * 	Unregister crypto core with cryptoapi CFI layer
 */
static void nss_cryptoapi_unregister(nss_crypto_user_ctx_t cfi)
{
	struct nss_cryptoapi *sc = &gbl_ctx;
	int i, ret = 0;

	nss_cfi_info("unregister nss_cryptoapi\n");

	/*
	 * Clear the registered flag
	 */
	atomic_set(&gbl_ctx.registered, 0);


	for (i = 0; i < ARRAY_SIZE(cryptoapi_skcipher_algs); i++) {
		if (!cryptoapi_skcipher_algs[i].base.cra_flags) {
			continue;
		}
		crypto_unregister_skcipher(&cryptoapi_skcipher_algs[i]);
		nss_cfi_info("Skcipher unregister succeeded, algo: %s\n",
				cryptoapi_skcipher_algs[i].base.cra_name);
	}

	for (i = 0; i < ARRAY_SIZE(cryptoapi_aead_algs); i++) {
		if (!cryptoapi_aead_algs[i].base.cra_flags) {
			continue;
		}
		crypto_unregister_aead(&cryptoapi_aead_algs[i]);
		nss_cfi_info("Aead unregister succeeded, algo: %s\n", cryptoapi_aead_algs[i].base.cra_name);
	}

	/*
	 * cleanup cryptoapi debugfs.
	 */
	nss_cryptoapi_debugfs_exit(sc);
}

/*
 * nss_cryptoapi_is_registered()
 *	Cryptoapi function to check if crypto driver is registered
 */
bool nss_cryptoapi_is_registered(void)
{
	return !!atomic_read(&gbl_ctx.registered);
}
EXPORT_SYMBOL(nss_cryptoapi_is_registered);

/*
 * nss_cryptoapi_init()
 * 	Initializing crypto core layer
 */
int nss_cryptoapi_init(void)
{
	struct nss_cryptoapi *sc = &gbl_ctx;

	sc->crypto = NULL;

	atomic_set(&gbl_ctx.registered, 0);

	nss_crypto_register_user(nss_cryptoapi_register, nss_cryptoapi_unregister, "nss_cryptoapi");
	nss_cfi_info("initialize nss_cryptoapi\n");

	return 0;
}

/*
 * nss_cryptoapi_exit()
 * 	De-Initialize cryptoapi CFI layer
 */
void nss_cryptoapi_exit(void)
{
	struct nss_cryptoapi *sc = &gbl_ctx;

	if (sc->crypto) {
		nss_crypto_unregister_user(sc->crypto);
	}
	nss_cfi_info("exiting nss_cryptoapi\n");
}

MODULE_LICENSE("Dual BSD/GPL");

module_init(nss_cryptoapi_init);
module_exit(nss_cryptoapi_exit);
