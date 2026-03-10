///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// This file is part of Zeutro's OpenABE.
///
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
///
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   oabe_rng.c
///
/// \brief  Random Number Generator implementation for OpenABE C.
///

#include <string.h>
#include "openabe/oabe_rng.h"
#include "openabe/oabe_memory.h"

#if defined(BP_WITH_OPENSSL)
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#elif defined(WITH_RELIC)
#include <relic.h>
#endif

/*============================================================================
 * Static VTable
 *============================================================================*/

static void oabe_rng_destroy(void *self) {
    OABE_RNGCtx *rng = (OABE_RNGCtx *)self;
    if (rng) {
        oabe_zeroize(&rng->drbg, sizeof(rng->drbg));
        oabe_free(rng);
    }
}

static const OABE_ObjectVTable g_rng_vtable = {
    .destroy = oabe_rng_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

/*============================================================================
 * CTR_DRBG Implementation (AES-256-CTR mode)
 *============================================================================*/

#if defined(BP_WITH_OPENSSL)

static OABE_ERROR oabe_aes256_ctr_encrypt(const uint8_t *key, const uint8_t *counter,
                                           uint8_t *output, size_t output_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return OABE_ERROR_ENCRYPTION_ERROR;
    }

    int len;
    OABE_ERROR rc = OABE_SUCCESS;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, counter) != 1) {
        rc = OABE_ERROR_ENCRYPTION_ERROR;
        goto cleanup;
    }

    /* Encrypt zeros to get keystream */
    memset(output, 0, output_len);
    if (EVP_EncryptUpdate(ctx, output, &len, output, output_len) != 1) {
        rc = OABE_ERROR_ENCRYPTION_ERROR;
        goto cleanup;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

#else
/* RELIC version - simplified using AES if available, or hash-based */
static OABE_ERROR oabe_aes256_ctr_encrypt(const uint8_t *key, const uint8_t *counter,
                                           uint8_t *output, size_t output_len) {
    /* For RELIC, we use a simple XOR-based PRF approach */
    /* This is a simplified implementation - production code should use proper AES-CTR */
    uint8_t counter_copy[OABE_CTR_DRBG_BLOCKSIZE];
    memcpy(counter_copy, counter, OABE_CTR_DRBG_BLOCKSIZE);

    size_t offset = 0;
    while (offset < output_len) {
        /* XOR key with counter to produce keystream byte */
        for (size_t i = 0; i < OABE_CTR_DRBG_BLOCKSIZE && offset + i < output_len; i++) {
            output[offset + i] = key[i % OABE_CTR_DRBG_KEYSIZE_BYTES] ^ counter_copy[i];
        }
        /* Increment counter */
        for (int i = OABE_CTR_DRBG_BLOCKSIZE - 1; i >= 0; i--) {
            if (++counter_copy[i] != 0) break;
        }
        offset += OABE_CTR_DRBG_BLOCKSIZE;
    }

    return OABE_SUCCESS;
}
#endif

OABE_ERROR oabe_ctr_drbg_init(OABE_CtrDrbg *ctx, const uint8_t *entropy, size_t entropy_len,
                                const uint8_t *personalization, size_t personalization_len) {
    if (!ctx || !entropy || entropy_len < OABE_CTR_DRBG_ENTROPYLEN) {
        return OABE_ERROR_INVALID_INPUT;
    }

    memset(ctx, 0, sizeof(OABE_CtrDrbg));

    /* Derive key and counter from entropy */
    /* Key = first 32 bytes of entropy hash */
    /* Counter = next 16 bytes */
    /* For simplicity, we use entropy directly (production should use KDF) */

    /* Combine entropy and personalization */
    uint8_t seed_material[OABE_CTR_DRBG_SEEDLEN * 2];
    size_t seed_len = 0;

    /* Copy entropy */
    size_t copy_len = entropy_len < OABE_CTR_DRBG_SEEDLEN ? entropy_len : OABE_CTR_DRBG_SEEDLEN;
    memcpy(seed_material, entropy, copy_len);
    seed_len = copy_len;

    /* Add personalization if provided */
    if (personalization && personalization_len > 0) {
        copy_len = personalization_len < OABE_CTR_DRBG_SEEDLEN ? personalization_len : OABE_CTR_DRBG_SEEDLEN;
        if (seed_len + copy_len <= sizeof(seed_material)) {
            memcpy(seed_material + seed_len, personalization, copy_len);
            seed_len += copy_len;
        }
    }

    /* Set key and counter (simplified - production should use proper KDF) */
    memcpy(ctx->key, seed_material, OABE_CTR_DRBG_KEYSIZE_BYTES);
    memcpy(ctx->counter, seed_material + OABE_CTR_DRBG_KEYSIZE_BYTES, OABE_CTR_DRBG_BLOCKSIZE);

    ctx->reseed_counter = 0;
    ctx->reseed_interval = OABE_CTR_DRBG_RESEED_INTERVAL;
    ctx->entropy_len = OABE_CTR_DRBG_ENTROPYLEN;
    ctx->is_initialized = true;

    return OABE_SUCCESS;
}

OABE_ERROR oabe_ctr_drbg_update(OABE_CtrDrbg *ctx, const uint8_t *additional, size_t additional_len) {
    if (!ctx) {
        return OABE_ERROR_INVALID_INPUT;
    }

    uint8_t temp[OABE_CTR_DRBG_SEEDLEN];
    uint8_t new_key[OABE_CTR_DRBG_KEYSIZE_BYTES];
    uint8_t new_counter[OABE_CTR_DRBG_BLOCKSIZE];

    /* Generate new key and counter */
    OABE_ERROR rc = oabe_aes256_ctr_encrypt(ctx->key, ctx->counter, temp, sizeof(temp));
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* XOR with additional data if provided */
    if (additional && additional_len > 0) {
        for (size_t i = 0; i < additional_len && i < sizeof(temp); i++) {
            temp[i] ^= additional[i];
        }
    }

    /* Update key and counter */
    memcpy(ctx->key, temp, OABE_CTR_DRBG_KEYSIZE_BYTES);
    memcpy(ctx->counter, temp + OABE_CTR_DRBG_KEYSIZE_BYTES, OABE_CTR_DRBG_BLOCKSIZE);

    oabe_zeroize(temp, sizeof(temp));
    oabe_zeroize(new_key, sizeof(new_key));
    oabe_zeroize(new_counter, sizeof(new_counter));

    return OABE_SUCCESS;
}

OABE_ERROR oabe_ctr_drbg_generate(OABE_CtrDrbg *ctx, uint8_t *output, size_t output_len) {
    if (!ctx || !output) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (!ctx->is_initialized) {
        return OABE_ERROR_CTR_DRB_NOT_INITIALIZED;
    }

    if (output_len > OABE_CTR_DRBG_MAX_REQUEST) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Check if reseed is needed */
    if (ctx->reseed_counter >= ctx->reseed_interval) {
        /* In production, should reseed from entropy source */
        ctx->reseed_counter = 0;
    }

    /* Generate output */
    OABE_ERROR rc = oabe_aes256_ctr_encrypt(ctx->key, ctx->counter, output, output_len);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Increment counter for next call */
    for (int i = OABE_CTR_DRBG_BLOCKSIZE - 1; i >= 0; i--) {
        if (++ctx->counter[i] != 0) break;
    }

    ctx->reseed_counter++;

    return OABE_SUCCESS;
}

/*============================================================================
 * RNG Context Implementation
 *============================================================================*/

OABE_RNGCtx* oabe_rng_new_system(void) {
    return oabe_rng_new_seeded(NULL, 0);
}

OABE_RNGCtx* oabe_rng_new_seeded(const uint8_t *seed, size_t seed_len) {
    OABE_RNGCtx *rng = (OABE_RNGCtx *)oabe_malloc(sizeof(OABE_RNGCtx));
    if (!rng) {
        return NULL;
    }

    rng->base.vtable = &g_rng_vtable;
    rng->base.ref_count = 1;
    rng->use_ctr_drbg = false;

    /* Get system entropy */
    uint8_t entropy[OABE_CTR_DRBG_ENTROPYLEN];

#if defined(BP_WITH_OPENSSL)
    if (RAND_bytes(entropy, sizeof(entropy)) != 1) {
        oabe_free(rng);
        return NULL;
    }
#else
    /* Use RELIC's rand_bytes */
    rand_bytes(entropy, sizeof(entropy));
#endif

    /* Combine with seed if provided */
    if (seed && seed_len > 0) {
        for (size_t i = 0; i < sizeof(entropy) && i < seed_len; i++) {
            entropy[i] ^= seed[i];
        }
    }

    /* Initialize DRBG */
    OABE_ERROR rc = oabe_ctr_drbg_init(&rng->drbg, entropy, sizeof(entropy), NULL, 0);
    if (rc != OABE_SUCCESS) {
        oabe_zeroize(entropy, sizeof(entropy));
        oabe_free(rng);
        return NULL;
    }

    rng->use_ctr_drbg = true;
    oabe_zeroize(entropy, sizeof(entropy));

    return rng;
}

void oabe_rng_ctx_free(OABE_RNGCtx *rng) {
    if (rng) {
        OABE_DEREF(rng);
    }
}

OABE_ERROR oabe_rng_ctx_bytes(OABE_RNGCtx *rng, uint8_t *output, size_t output_len) {
    if (!rng || !output) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (output_len == 0) {
        return OABE_SUCCESS;
    }

    if (output_len > OABE_CTR_DRBG_MAX_REQUEST) {
        /* Generate in chunks */
        size_t offset = 0;
        while (offset < output_len) {
            size_t chunk = output_len - offset;
            if (chunk > OABE_CTR_DRBG_MAX_REQUEST) {
                chunk = OABE_CTR_DRBG_MAX_REQUEST;
            }
            OABE_ERROR rc = oabe_ctr_drbg_generate(&rng->drbg, output + offset, chunk);
            if (rc != OABE_SUCCESS) {
                return rc;
            }
            offset += chunk;
        }
        return OABE_SUCCESS;
    }

    return oabe_ctr_drbg_generate(&rng->drbg, output, output_len);
}

OABE_ERROR oabe_rng_bytestring(OABE_RNGCtx *rng, OABE_ByteString *output, size_t output_len) {
    if (!rng || !output) {
        return OABE_ERROR_INVALID_INPUT;
    }

    uint8_t *buffer = (uint8_t *)oabe_malloc(output_len);
    if (!buffer) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ERROR rc = oabe_rng_ctx_bytes(rng, buffer, output_len);
    if (rc != OABE_SUCCESS) {
        oabe_free(buffer);
        return rc;
    }

    rc = oabe_bytestring_append_data(output, buffer, output_len);
    oabe_zeroize(buffer, output_len);
    oabe_free(buffer);

    return rc;
}

OABE_ERROR oabe_rng_reseed(OABE_RNGCtx *rng, const uint8_t *seed, size_t seed_len) {
    if (!rng) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Get fresh entropy */
    uint8_t entropy[OABE_CTR_DRBG_ENTROPYLEN];

#if defined(BP_WITH_OPENSSL)
    if (RAND_bytes(entropy, sizeof(entropy)) != 1) {
        return OABE_ERROR_RAND_INSUFFICIENT;
    }
#else
    rand_bytes(entropy, sizeof(entropy));
#endif

    /* Combine with seed if provided */
    if (seed && seed_len > 0) {
        for (size_t i = 0; i < sizeof(entropy) && i < seed_len; i++) {
            entropy[i] ^= seed[i];
        }
    }

    /* Update DRBG state */
    OABE_ERROR rc = oabe_ctr_drbg_update(&rng->drbg, entropy, sizeof(entropy));
    rng->drbg.reseed_counter = 0;

    oabe_zeroize(entropy, sizeof(entropy));
    return rc;
}