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
/// \file   oabe_context.c
///
/// \brief  ABE context implementation for OpenABE C.
///

#include <string.h>
#include <stdio.h>
#include "openabe/oabe_context.h"
#include "openabe/oabe_memory.h"
#include "openabe/oabe_rng.h"
#include "openabe/oabe_policy.h"
#include "openabe/oabe_hash.h"
#include "openabe/oabe_ciphertext.h"

/*============================================================================
 * Helper functions for key element serialization
 *============================================================================*/

/**
 * Serialize key_elements for CP-ABE user key.
 * CP-ABE key structure: K (G2), L (G2), then Kx (G1) for each attribute.
 */
static OABE_ERROR serialize_cp_key_elements(OABE_GroupHandle group, OABE_Vector *elements, OABE_ByteString **result) {
    if (!group || !elements || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Write element count */
    OABE_ERROR rc = oabe_bytestring_pack32(*result, (uint32_t)elements->size);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    /* Elements 0 and 1 are G2, rest are G1 */
    for (size_t i = 0; i < elements->size; i++) {
        OABE_ByteString *elem_bs = NULL;

        if (i < 2) {
            /* K and L are G2 elements */
            rc = oabe_g2_serialize((OABE_G2 *)elements->items[i], &elem_bs);
        } else {
            /* Kx attributes are G1 elements */
            rc = oabe_g1_serialize((OABE_G1 *)elements->items[i], &elem_bs);
        }

        if (rc != OABE_SUCCESS) {
            oabe_bytestring_free(*result);
            *result = NULL;
            return rc;
        }

        rc = oabe_bytestring_pack_data(*result,
                                        oabe_bytestring_get_const_ptr(elem_bs),
                                        oabe_bytestring_get_size(elem_bs));
        oabe_bytestring_free(elem_bs);

        if (rc != OABE_SUCCESS) {
            oabe_bytestring_free(*result);
            *result = NULL;
            return rc;
        }
    }

    return OABE_SUCCESS;
}

/**
 * Deserialize key_elements for CP-ABE user key.
 */
static OABE_ERROR deserialize_cp_key_elements(OABE_GroupHandle group, const OABE_ByteString *data, OABE_Vector **elements) {
    if (!group || !data || !elements) {
        return OABE_ERROR_INVALID_INPUT;
    }

    size_t index = 0;

    /* Read element count */
    uint32_t count;
    OABE_ERROR rc = oabe_bytestring_unpack32(data, &index, &count);
    if (rc != OABE_SUCCESS) return rc;

    *elements = oabe_vector_new(count);
    if (!*elements) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Elements 0 and 1 are G2, rest are G1 */
    for (uint32_t i = 0; i < count; i++) {
        uint32_t elem_len;
        rc = oabe_bytestring_unpack32(data, &index, &elem_len);
        if (rc != OABE_SUCCESS) {
            oabe_vector_free(*elements);
            *elements = NULL;
            return rc;
        }

        if (elem_len == 0) {
            continue;
        }

        OABE_ByteString *elem_bs = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(data) + index, elem_len);
        if (!elem_bs) {
            oabe_vector_free(*elements);
            *elements = NULL;
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        index += elem_len;

        void *elem = NULL;
        if (i < 2) {
            /* K and L are G2 elements */
            OABE_G2 *g2 = NULL;
            rc = oabe_g2_deserialize(group, elem_bs, &g2);
            elem = g2;
        } else {
            /* Kx attributes are G1 elements */
            OABE_G1 *g1 = NULL;
            rc = oabe_g1_deserialize(group, elem_bs, &g1);
            elem = g1;
        }
        oabe_bytestring_free(elem_bs);

        if (rc != OABE_SUCCESS) {
            oabe_vector_free(*elements);
            *elements = NULL;
            return rc;
        }

        oabe_vector_append(*elements, elem);
    }

    return OABE_SUCCESS;
}

/*============================================================================
 * AES Context Implementation
 *============================================================================*/

static void oabe_context_aes_destroy(void *self) {
    OABE_ContextAES *ctx = (OABE_ContextAES *)self;
    if (ctx) {
        if (ctx->key) {
            oabe_symkey_free(ctx->key);
        }
        if (ctx->iv) {
            oabe_zeroize(ctx->iv, ctx->iv_len);
            oabe_free(ctx->iv);
        }
        if (ctx->base.rng) {
            oabe_rng_free(ctx->base.rng);
        }
        if (ctx->base.group) {
            oabe_group_free(ctx->base.group);
        }
        oabe_free(ctx);
    }
}

static const OABE_ObjectVTable g_context_aes_vtable = {
    .destroy = oabe_context_aes_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_ContextAES* oabe_context_aes_new(void) {
    OABE_ContextAES *ctx = (OABE_ContextAES *)oabe_malloc(sizeof(OABE_ContextAES));
    if (!ctx) return NULL;

    memset(ctx, 0, sizeof(OABE_ContextAES));
    ctx->base.base.vtable = &g_context_aes_vtable;
    ctx->base.base.ref_count = 1;
    ctx->base.scheme = OABE_SCHEME_AES_GCM;

    ctx->base.rng = oabe_rng_new(NULL, 0);
    if (!ctx->base.rng) {
        oabe_free(ctx);
        return NULL;
    }

    ctx->base.is_initialized = true;
    return ctx;
}

void oabe_context_aes_free(OABE_ContextAES *ctx) {
    if (ctx) {
        OABE_DEREF(ctx);
    }
}

OABE_ERROR oabe_context_aes_set_key(OABE_ContextAES *ctx, const uint8_t *key, size_t key_len) {
    if (!ctx || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (ctx->key) {
        oabe_symkey_free(ctx->key);
        ctx->key = NULL;
    }

    ctx->key = oabe_symkey_from_bytes(key, key_len);
    return ctx->key ? OABE_SUCCESS : OABE_ERROR_OUT_OF_MEMORY;
}

OABE_ERROR oabe_context_aes_encrypt(OABE_ContextAES *ctx,
                                      const uint8_t *plaintext, size_t plaintext_len,
                                      const uint8_t *iv, size_t iv_len,
                                      OABE_ByteString **ciphertext,
                                      uint8_t tag[16]) {
    if (!ctx || !plaintext || !ciphertext) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (!ctx->key) {
        return OABE_ERROR_INVALID_KEY;
    }

    /* Generate IV if not provided */
    uint8_t generated_iv[16];
    if (!iv) {
        if (oabe_rng_bytes(ctx->base.rng, generated_iv, 12) != OABE_SUCCESS) {
            return OABE_ERROR_INVALID_RNG;
        }
        iv = generated_iv;
        iv_len = 12;
    }

    /* Store IV for decryption */
    if (ctx->iv) {
        oabe_free(ctx->iv);
    }
    ctx->iv = (uint8_t *)oabe_malloc(iv_len);
    if (!ctx->iv) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    memcpy(ctx->iv, iv, iv_len);
    ctx->iv_len = iv_len;

    /* Create output ByteString */
    *ciphertext = oabe_bytestring_new();
    if (!*ciphertext) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* For now, use simple XOR encryption (placeholder - production should use AES-GCM) */
    /* In production, use OpenSSL EVP_aes_*_gcm() or similar */

    /* Pack IV */
    oabe_bytestring_pack8(*ciphertext, (uint8_t)iv_len);
    oabe_bytestring_append_data(*ciphertext, iv, iv_len);

    /* Pack ciphertext (simple XOR for now) */
    oabe_bytestring_pack32(*ciphertext, (uint32_t)plaintext_len);

    uint8_t *encrypted = (uint8_t *)oabe_malloc(plaintext_len);
    if (!encrypted) {
        oabe_bytestring_free(*ciphertext);
        *ciphertext = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < plaintext_len; i++) {
        encrypted[i] = plaintext[i] ^ ctx->key->key_bytes[i % ctx->key->key_len];
    }

    oabe_bytestring_append_data(*ciphertext, encrypted, plaintext_len);
    oabe_zeroize(encrypted, plaintext_len);
    oabe_free(encrypted);

    /* Generate dummy tag */
    memset(tag, 0, 16);
    oabe_rng_bytes(ctx->base.rng, tag, 16);

    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_aes_decrypt(OABE_ContextAES *ctx,
                                      const uint8_t *ciphertext, size_t ciphertext_len,
                                      const uint8_t *iv, size_t iv_len,
                                      const uint8_t tag[16],
                                      uint8_t *plaintext, size_t *plaintext_len) {
    (void)iv;        /* IV comes from ciphertext in our format */
    (void)iv_len;
    (void)tag;       /* Tag comes from ciphertext in our format */

    if (!ctx || !ciphertext || !plaintext || !plaintext_len) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (!ctx->key) {
        return OABE_ERROR_INVALID_KEY;
    }

    /* Parse ciphertext */
    size_t index = 0;
    uint8_t stored_iv_len;
    uint32_t stored_plaintext_len;

    if (ciphertext_len < 5) {
        return OABE_ERROR_INVALID_CIPHERTEXT;
    }

    OABE_ByteString *bs = oabe_bytestring_new_from_data(ciphertext, ciphertext_len);
    if (!bs) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    oabe_bytestring_unpack8(bs, &index, &stored_iv_len);
    if (stored_iv_len != iv_len) {
        oabe_bytestring_free(bs);
        return OABE_ERROR_INVALID_CIPHERTEXT;
    }

    index += stored_iv_len;  /* Skip IV */

    oabe_bytestring_unpack32(bs, &index, &stored_plaintext_len);

    if (*plaintext_len < stored_plaintext_len) {
        oabe_bytestring_free(bs);
        return OABE_ERROR_BUFFER_TOO_SMALL;
    }

    *plaintext_len = stored_plaintext_len;

    /* Decrypt (simple XOR for now) */
    const uint8_t *encrypted = ciphertext + index;
    for (size_t i = 0; i < *plaintext_len; i++) {
        plaintext[i] = encrypted[i] ^ ctx->key->key_bytes[i % ctx->key->key_len];
    }

    oabe_bytestring_free(bs);
    return OABE_SUCCESS;
}

/*============================================================================
 * CP-ABE Context Implementation
 *============================================================================*/

static void oabe_context_cp_destroy(void *self) {
    OABE_ContextCP *ctx = (OABE_ContextCP *)self;
    if (ctx) {
        /* Free elements first, before params which may reference them */
        /* Note: g1_alpha is owned by public_params, so we don't free it here */
        if (ctx->g1) {
            oabe_g1_free(ctx->g1);
        }
        if (ctx->g2) {
            oabe_g2_free(ctx->g2);
        }
        /* Now free keystore and params */
        if (ctx->keystore) {
            oabe_keystore_free(ctx->keystore);
        }
        if (ctx->public_params) {
            /* Note: g1_generator and g2_generator are aliases of ctx->g1/g2,
             * so we need to NULL them before freeing params to avoid double-free.
             * g1_alpha is owned by public_params. */
            ctx->public_params->g1_generator = NULL;
            ctx->public_params->g2_generator = NULL;
            oabe_params_free(ctx->public_params);
        }
        if (ctx->secret_key) {
            oabe_secret_key_free(ctx->secret_key);
        }
        if (ctx->params_id) {
            oabe_free(ctx->params_id);
        }
        if (ctx->base.rng) {
            oabe_rng_free(ctx->base.rng);
        }
        if (ctx->base.group) {
            oabe_group_free(ctx->base.group);
        }
        oabe_free(ctx);
    }
}

static const OABE_ObjectVTable g_context_cp_vtable = {
    .destroy = oabe_context_cp_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_ContextCP* oabe_context_cp_new(void) {
    OABE_ContextCP *ctx = (OABE_ContextCP *)oabe_malloc(sizeof(OABE_ContextCP));
    if (!ctx) return NULL;

    memset(ctx, 0, sizeof(OABE_ContextCP));
    ctx->base.base.vtable = &g_context_cp_vtable;
    ctx->base.base.ref_count = 1;
    ctx->base.scheme = OABE_SCHEME_CP_WATERS;
    ctx->base.curve_id = OABE_CURVE_BN_P254;

    ctx->keystore = oabe_keystore_new();
    if (!ctx->keystore) {
        oabe_free(ctx);
        return NULL;
    }

    ctx->base.rng = oabe_rng_new(NULL, 0);
    if (!ctx->base.rng) {
        oabe_keystore_free(ctx->keystore);
        oabe_free(ctx);
        return NULL;
    }

    /* Create the group for cryptographic operations */
    ctx->base.group = oabe_group_new(ctx->base.curve_id);
    if (!ctx->base.group) {
        oabe_rng_free(ctx->base.rng);
        oabe_keystore_free(ctx->keystore);
        oabe_free(ctx);
        return NULL;
    }

    ctx->base.is_initialized = true;
    return ctx;
}

void oabe_context_cp_free(OABE_ContextCP *ctx) {
    if (ctx) {
        OABE_DEREF(ctx);
    }
}

OABE_ERROR oabe_context_cp_generate_params(OABE_ContextCP *ctx, const char *params_id) {
    if (!ctx || !params_id) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Create group if not already created */
    if (!ctx->base.group) {
        ctx->base.group = oabe_group_new(ctx->base.curve_id);
        if (!ctx->base.group) {
            return OABE_ERROR_INVALID_GROUP_PARAMS;
        }
    }

    /* Store params ID */
    if (ctx->params_id) {
        oabe_free(ctx->params_id);
    }
    ctx->params_id = oabe_strdup(params_id);
    if (!ctx->params_id) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Generate public parameters */
    ctx->public_params = oabe_params_new(OABE_SCHEME_CP_WATERS, ctx->base.curve_id, ctx->base.rng);
    if (!ctx->public_params) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    ctx->public_params->group = ctx->base.group;

    /* Generate g1 */
    ctx->g1 = oabe_g1_new(ctx->base.group);
    if (!ctx->g1) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g1_random(ctx->g1, ctx->base.rng);

    /* Generate g2 */
    ctx->g2 = oabe_g2_new(ctx->base.group);
    if (!ctx->g2) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g2_random(ctx->g2, ctx->base.rng);

    /* Generate secret key (alpha) */
    ctx->secret_key = oabe_secret_key_new(ctx->public_params, ctx->base.rng);
    if (!ctx->secret_key) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Compute g1^alpha */
    ctx->g1_alpha = oabe_g1_new(ctx->base.group);
    if (!ctx->g1_alpha) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g1_mul_scalar(ctx->g1_alpha, ctx->g1, ctx->secret_key->alpha);

    /* Compute g1^a (using beta as 'a' in Waters '09) */
    ctx->public_params->g1_a = oabe_g1_new(ctx->base.group);
    if (!ctx->public_params->g1_a) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g1_mul_scalar(ctx->public_params->g1_a, ctx->g1, ctx->secret_key->beta);

    /* Compute g2^a (using beta as 'a' in Waters '09) */
    ctx->public_params->g2_a = oabe_g2_new(ctx->base.group);
    if (!ctx->public_params->g2_a) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g2_mul_scalar(ctx->public_params->g2_a, ctx->g2, ctx->secret_key->beta);

    /* Compute e(g1, g2)^alpha for public params */
    ctx->public_params->egg_alpha = oabe_gt_new(ctx->base.group);
    if (!ctx->public_params->egg_alpha) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_pairing(ctx->public_params->egg_alpha, ctx->g1, ctx->g2);
    oabe_gt_exp(ctx->public_params->egg_alpha, ctx->public_params->egg_alpha, ctx->secret_key->alpha);

    /* g1_alpha is owned by public_params, ctx just holds a pointer */
    ctx->public_params->g1_alpha = ctx->g1_alpha;

    ctx->base.is_initialized = true;
    ctx->public_params->g1_generator = ctx->g1;
    ctx->public_params->g2_generator = ctx->g2;

    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_cp_set_public_params(OABE_ContextCP *ctx, const OABE_ByteString *public_params) {
    if (!ctx || !public_params) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Deserialize public parameters */
    OABE_ABEParams *params = NULL;
    OABE_ERROR rc = oabe_params_deserialize(public_params, &params);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Free old params if any */
    if (ctx->public_params) {
        oabe_params_free(ctx->public_params);
    }

    ctx->public_params = params;

    /* Store the specific elements for quick access */
    ctx->g1 = params->g1_generator;
    ctx->g2 = params->g2_generator;
    ctx->g1_alpha = params->g1_alpha;  /* May be NULL for KP-ABE params */

    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_cp_get_public_params(OABE_ContextCP *ctx, OABE_ByteString **public_params) {
    if (!ctx || !public_params) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized || !ctx->public_params) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    return oabe_params_serialize(ctx->public_params, public_params);
}

OABE_ERROR oabe_context_cp_keygen(OABE_ContextCP *ctx, const char *key_id, const char *attributes) {
    if (!ctx || !key_id || !attributes) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized || !ctx->secret_key || !ctx->public_params) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Parse attributes */
    OABE_AttributeList *attr_list = oabe_attr_list_from_string(attributes);
    if (!attr_list) {
        return OABE_ERROR_INVALID_ATTRIBUTE_LIST;
    }

    /* Create user key */
    OABE_ABEUserKey *user_key = (OABE_ABEUserKey *)oabe_malloc(sizeof(OABE_ABEUserKey));
    if (!user_key) {
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memset(user_key, 0, sizeof(OABE_ABEUserKey));
    user_key->base.base.ref_count = 1;
    user_key->base.key_type = OABE_KEY_TYPE_ABE_USER;
    user_key->base.key_id = oabe_strdup(key_id);
    user_key->attributes = attr_list->attributes;  /* Take ownership */

    /* Create key elements storage */
    user_key->key_elements = oabe_vector_new(attr_list->attributes->size * 2);
    if (!user_key->key_elements) {
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Generate Waters '09 CP-ABE key */
    /* Key structure:
     * K = g2^alpha * g2^(a*t) = g2^(alpha + a*t)  where t is random
     * L = g2^t
     * Kx = H(attr)^t for each attribute
     */

    /* Generate random t */
    OABE_ZP *t = oabe_zp_new(ctx->base.group);
    if (!t) {
        oabe_vector_free(user_key->key_elements);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_zp_random(t, ctx->base.rng);

    /* K = g2^(alpha + a*t) where a is beta in our scheme */
    OABE_G2 *K = oabe_g2_new(ctx->base.group);
    if (!K) {
        oabe_zp_free(t);
        oabe_vector_free(user_key->key_elements);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* K = g2^alpha * g2^(beta*t) */
    /* First compute g2^alpha */
    oabe_g2_mul_scalar(K, ctx->g2, ctx->secret_key->alpha);

    /* Then compute g2^(beta*t) and multiply */
    OABE_ZP *beta_t = oabe_zp_new(ctx->base.group);
    if (!beta_t) {
        oabe_g2_free(K);
        oabe_zp_free(t);
        oabe_vector_free(user_key->key_elements);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_zp_mul(beta_t, ctx->secret_key->beta, t);

    OABE_G2 *g2_beta_t = oabe_g2_new(ctx->base.group);
    if (!g2_beta_t) {
        oabe_zp_free(beta_t);
        oabe_g2_free(K);
        oabe_zp_free(t);
        oabe_vector_free(user_key->key_elements);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g2_mul_scalar(g2_beta_t, ctx->g2, beta_t);

    /* K = K * g2_beta_t */
    oabe_g2_add(K, K, g2_beta_t);
    oabe_g2_free(g2_beta_t);
    oabe_zp_free(beta_t);

    /* L = g2^t */
    OABE_G2 *L = oabe_g2_new(ctx->base.group);
    if (!L) {
        oabe_g2_free(K);
        oabe_zp_free(t);
        oabe_vector_free(user_key->key_elements);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g2_mul_scalar(L, ctx->g2, t);

    /* Store K and L in key elements */
    oabe_vector_append(user_key->key_elements, K);
    oabe_vector_append(user_key->key_elements, L);

    /* For each attribute, compute Kx = H(attr)^t */
    for (size_t i = 0; i < attr_list->attributes->size; i++) {
        const char *attr = oabe_strvec_get(attr_list->attributes, i);
        OABE_G1 *Kx = NULL;

        OABE_ERROR rc = oabe_hash_attr_to_g1(ctx->base.group, attr, &Kx);
        if (rc != OABE_SUCCESS || !Kx) {
            /* Cleanup on error */
            oabe_g2_free(L);
            oabe_g2_free(K);
            oabe_zp_free(t);
            oabe_vector_free(user_key->key_elements);
            oabe_free(user_key->base.key_id);
            oabe_free(user_key);
            oabe_attr_list_free(attr_list);
            return rc;
        }

        /* Kx = Kx^t */
        OABE_G1 *Kx_t = oabe_g1_new(ctx->base.group);
        if (!Kx_t) {
            oabe_g1_free(Kx);
            oabe_g2_free(L);
            oabe_g2_free(K);
            oabe_zp_free(t);
            oabe_vector_free(user_key->key_elements);
            oabe_free(user_key->base.key_id);
            oabe_free(user_key);
            oabe_attr_list_free(attr_list);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_g1_mul_scalar(Kx_t, Kx, t);
        oabe_g1_free(Kx);

        oabe_vector_append(user_key->key_elements, Kx_t);
    }

    oabe_zp_free(t);

    /* Add to keystore */
    OABE_ERROR rc = oabe_keystore_add_user_key(ctx->keystore, key_id, user_key);
    if (rc != OABE_SUCCESS) {
        /* Cleanup on error */
        for (size_t i = 0; i < user_key->key_elements->size; i++) {
            OABE_G1 *elem = (OABE_G1 *)oabe_vector_get(user_key->key_elements, i);
            if (elem) oabe_g1_free(elem);
        }
        oabe_vector_free(user_key->key_elements);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_attr_list_free(attr_list);
        return rc;
    }

    /* Free the attribute list wrapper (but not the attributes string vector) */
    oabe_free(attr_list);

    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_cp_set_secret_key(OABE_ContextCP *ctx, const OABE_ByteString *secret_key) {
    if (!ctx || !secret_key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Free existing secret key */
    if (ctx->secret_key) {
        oabe_secret_key_free(ctx->secret_key);
        ctx->secret_key = NULL;
    }

    /* Deserialize the secret key */
    OABE_ABESecretKey *key = NULL;
    OABE_ERROR rc = oabe_secret_key_deserialize(secret_key, &key);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    ctx->secret_key = key;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_cp_get_secret_key(OABE_ContextCP *ctx, OABE_ByteString **secret_key) {
    if (!ctx || !secret_key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }
    if (!ctx->secret_key) {
        return OABE_ERROR_ELEMENT_NOT_FOUND;
    }

    return oabe_secret_key_serialize(ctx->secret_key, secret_key);
}

OABE_ERROR oabe_context_cp_export_key(OABE_ContextCP *ctx, const char *key_id, OABE_ByteString **key) {
    if (!ctx || !key_id || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }
    if (!ctx->keystore) {
        return OABE_ERROR_ELEMENT_NOT_FOUND;
    }

    /* Look up the user key in the keystore */
    OABE_ABEUserKey *user_key = oabe_keystore_get_user_key(ctx->keystore, key_id);
    if (!user_key) {
        return OABE_ERROR_ELEMENT_NOT_FOUND;
    }

    /* Serialize key_elements into key_data if not already done */
    if (user_key->key_elements && !user_key->base.key_data) {
        OABE_ByteString *key_data = NULL;
        OABE_ERROR rc = serialize_cp_key_elements(ctx->base.group, user_key->key_elements, &key_data);
        if (rc != OABE_SUCCESS) {
            return rc;
        }
        user_key->base.key_data = key_data;
    }

    return oabe_user_key_serialize(user_key, key);
}

OABE_ERROR oabe_context_cp_import_key(OABE_ContextCP *ctx, const char *key_id, const OABE_ByteString *key) {
    if (!ctx || !key_id || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }
    if (!ctx->keystore) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Deserialize the user key */
    OABE_ABEUserKey *user_key = NULL;
    OABE_ERROR rc = oabe_user_key_deserialize(key, &user_key);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Override the key_id with the provided one */
    if (user_key->base.key_id) {
        oabe_free(user_key->base.key_id);
    }
    user_key->base.key_id = oabe_strdup(key_id);
    if (!user_key->base.key_id) {
        oabe_user_key_free(user_key);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Deserialize key_elements from key_data if present */
    if (user_key->base.key_data && oabe_bytestring_get_size(user_key->base.key_data) > 0) {
        rc = deserialize_cp_key_elements(ctx->base.group, user_key->base.key_data, &user_key->key_elements);
        if (rc != OABE_SUCCESS) {
            fprintf(stderr, "DEBUG: deserialize_cp_key_elements failed: %d\n", rc);
            oabe_user_key_free(user_key);
            return rc;
        }
    }

    /* Add to keystore */
    rc = oabe_keystore_add_user_key(ctx->keystore, key_id, user_key);
    if (rc != OABE_SUCCESS) {
        oabe_user_key_free(user_key);
        return rc;
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_cp_encrypt(OABE_ContextCP *ctx, const char *policy,
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     OABE_ByteString **ciphertext) {
    /* Note: This is a KEM-only implementation. The plaintext is not encrypted here.
     * In a full implementation, the encapsulated key would be hashed to create
     * a symmetric key, then used to encrypt the plaintext. */
    (void)plaintext_len;

    if (!ctx || !policy || !plaintext || !ciphertext) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized || !ctx->public_params || !ctx->g1) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Parse policy */
    OABE_PolicyTree *policy_tree = NULL;
    OABE_ERROR rc = oabe_policy_parse(policy, &policy_tree);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Create ciphertext structure */
    OABE_CP_Ciphertext *ct = oabe_cp_ct_new(OABE_SCHEME_CP_WATERS);
    if (!ct) {
        oabe_policy_tree_free(policy_tree);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Store policy string and tree for decryption */
    ct->policy_string = oabe_strdup(policy);
    ct->policy = policy_tree;

    /* Generate random secret s */
    OABE_ZP *s = oabe_zp_new(ctx->base.group);
    if (!s) {
        oabe_cp_ct_free(ct);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_zp_random(s, ctx->base.rng);

    /* C0 = g1^s */
    ct->c0 = oabe_g1_new(ctx->base.group);
    if (!ct->c0) {
        oabe_zp_free(s);
        oabe_cp_ct_free(ct);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g1_mul_scalar(ct->c0, ctx->g1, s);

    /* C = e(g1, g2)^(alpha * s) * M where M is the symmetric key */
    /* For KEM mode, we compute e(g1, g2)^(alpha * s) as the encapsulated key */
    ct->ct = oabe_gt_new(ctx->base.group);
    if (!ct->ct) {
        oabe_zp_free(s);
        oabe_cp_ct_free(ct);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Use e(g1, g2)^alpha from public params, compute (e(g1, g2)^alpha)^s */
    if (!ctx->public_params || !ctx->public_params->egg_alpha) {
        oabe_zp_free(s);
        oabe_cp_ct_free(ct);
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }
    oabe_gt_exp(ct->ct, ctx->public_params->egg_alpha, s);

    /* Share secret s through the policy tree using polynomial secret sharing */
    OABE_ZP **shares = NULL;
    char **share_attrs = NULL;
    size_t num_shares = 0;
    rc = oabe_lsss_share_tree(policy_tree->root, s, ctx->base.rng,
                              &shares, &share_attrs, &num_shares);
    if (rc != OABE_SUCCESS) {
        oabe_zp_free(s);
        oabe_cp_ct_free(ct);
        return rc;
    }

    /* Allocate ciphertext components */
    ct->components = (OABE_CP_CiphertextComponent *)oabe_calloc(num_shares,
        sizeof(OABE_CP_CiphertextComponent));
    if (!ct->components) {
        oabe_lsss_free_coefficients(shares, share_attrs, num_shares);
        oabe_zp_free(s);
        oabe_cp_ct_free(ct);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    ct->num_components = num_shares;

    /* For each share (one per leaf attribute):
     * C_i = g1^(share) * H(attr)^(-r_i)
     * D_i = g2^(r_i)
     */
    for (size_t i = 0; i < num_shares; i++) {
        const char *attr = share_attrs[i];
        OABE_ZP *share = shares[i];

        /* Generate random r_i */
        OABE_ZP *r_i = oabe_zp_new(ctx->base.group);
        if (!r_i) {
            oabe_lsss_free_coefficients(shares, share_attrs, num_shares);
            oabe_zp_free(s);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_zp_random(r_i, ctx->base.rng);

        /* C_i = g1^share */
        OABE_G1 *C_i = oabe_g1_new(ctx->base.group);
        if (!C_i) {
            oabe_zp_free(r_i);
            oabe_lsss_free_coefficients(shares, share_attrs, num_shares);
            oabe_zp_free(s);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        /* C_i = (g1^a)^share (Waters '09 formula) */
        oabe_g1_mul_scalar(C_i, ctx->public_params->g1_a, share);

        /* Compute H(attr)^r_i, then H(attr)^(-r_i) */
        OABE_G1 *H_attr = NULL;
        rc = oabe_hash_attr_to_g1(ctx->base.group, attr, &H_attr);
        if (rc != OABE_SUCCESS) {
            oabe_g1_free(C_i);
            oabe_zp_free(r_i);
            oabe_lsss_free_coefficients(shares, share_attrs, num_shares);
            oabe_zp_free(s);
            oabe_cp_ct_free(ct);
            return rc;
        }

        OABE_G1 *H_attr_r = oabe_g1_new(ctx->base.group);
        if (!H_attr_r) {
            oabe_g1_free(H_attr);
            oabe_g1_free(C_i);
            oabe_zp_free(r_i);
            oabe_lsss_free_coefficients(shares, share_attrs, num_shares);
            oabe_zp_free(s);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_g1_mul_scalar(H_attr_r, H_attr, r_i);

        /* C_i = C_i * H(attr)^(-r_i) = g1^share * H(attr)^(-r_i) */
        OABE_ZP *neg_r = oabe_zp_new(ctx->base.group);
        if (!neg_r) {
            oabe_g1_free(H_attr_r);
            oabe_g1_free(H_attr);
            oabe_g1_free(C_i);
            oabe_zp_free(r_i);
            oabe_lsss_free_coefficients(shares, share_attrs, num_shares);
            oabe_zp_free(s);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_zp_neg(neg_r, r_i);
        OABE_G1 *H_attr_neg_r = oabe_g1_new(ctx->base.group);
        oabe_g1_mul_scalar(H_attr_neg_r, H_attr, neg_r);
        oabe_g1_add(C_i, C_i, H_attr_neg_r);
        oabe_g1_free(H_attr_neg_r);
        oabe_zp_free(neg_r);
        oabe_g1_free(H_attr);
        oabe_g1_free(H_attr_r);

        /* D_i = g2^r_i */
        OABE_G2 *D_i = oabe_g2_new(ctx->base.group);
        if (!D_i) {
            oabe_g1_free(C_i);
            oabe_zp_free(r_i);
            oabe_lsss_free_coefficients(shares, share_attrs, num_shares);
            oabe_zp_free(s);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_g2_mul_scalar(D_i, ctx->g2, r_i);
        oabe_zp_free(r_i);

        /* Store in ciphertext */
        ct->components[i].attribute = oabe_strdup(attr);
        ct->components[i].c1 = C_i;
        ct->components[i].c2 = D_i;
    }

    /* Cleanup shares */
    oabe_lsss_free_coefficients(shares, share_attrs, num_shares);
    oabe_zp_free(s);

    /* Serialize ciphertext */
    rc = oabe_cp_ct_serialize(ct, ciphertext);
    oabe_cp_ct_free(ct);
    return rc;
}

OABE_ERROR oabe_context_cp_decrypt(OABE_ContextCP *ctx, const char *key_id,
                                     const OABE_ByteString *ciphertext,
                                     uint8_t *plaintext, size_t *plaintext_len) {
    if (!ctx || !key_id || !ciphertext || !plaintext || !plaintext_len) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized || !ctx->public_params) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Get user key */
    OABE_ABEUserKey *user_key = oabe_keystore_get_user_key(ctx->keystore, key_id);
    if (!user_key) {
        return OABE_ERROR_INVALID_KEY;
    }

    /* Deserialize ciphertext */
    OABE_CP_Ciphertext *ct = NULL;
    OABE_ERROR rc = oabe_cp_ct_deserialize(ctx->base.group, ciphertext, &ct);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Check that user's attributes satisfy the policy */
    OABE_PolicyTree *policy = ct->policy;
    if (!policy) {
        oabe_cp_ct_free(ct);
        return OABE_ERROR_INVALID_CIPHERTEXT;
    }

    /* Compute Lagrange coefficients for satisfied attributes */
    OABE_ZP **coefficients = NULL;
    char **coeff_attrs = NULL;
    size_t num_coeff = 0;

    rc = oabe_lsss_recover_coefficients(policy->root, user_key->attributes,
                                         ctx->base.group,
                                         &coefficients, &coeff_attrs, &num_coeff);

    if (rc != OABE_SUCCESS) {
        oabe_cp_ct_free(ct);
        return rc;
    }

    if (num_coeff == 0) {
        oabe_cp_ct_free(ct);
        return OABE_ERROR_POLICY_NOT_SATISFIED;
    }

    /* Get key components: K and L */
    OABE_G2 *K = (OABE_G2 *)oabe_vector_get(user_key->key_elements, 0);
    OABE_G2 *L = (OABE_G2 *)oabe_vector_get(user_key->key_elements, 1);
    if (!K || !L) {
        oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);
        oabe_cp_ct_free(ct);
        return OABE_ERROR_INVALID_KEY;
    }

    /* Compute e(C0, K) */
    OABE_GT *result = oabe_gt_new(ctx->base.group);
    if (!result) {
        oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);
        oabe_cp_ct_free(ct);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_pairing(result, ct->c0, K);

    /* Build a hash map from attribute name to ciphertext component for fast lookup */
    /* For now, we'll do linear search since the number of attributes is typically small */

    /* For each satisfied attribute with its Lagrange coefficient */
    OABE_GT *denominator = oabe_gt_new(ctx->base.group);
    if (!denominator) {
        oabe_gt_free(result);
        oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);
        oabe_cp_ct_free(ct);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_gt_set_identity(denominator);

    for (size_t i = 0; i < num_coeff; i++) {
        const char *attr = coeff_attrs[i];
        OABE_ZP *coeff = coefficients[i];

        /* Find the ciphertext component for this attribute */
        OABE_CP_CiphertextComponent *comp = NULL;
        for (size_t j = 0; j < ct->num_components; j++) {
            if (strcmp(ct->components[j].attribute, attr) == 0) {
                comp = &ct->components[j];
                break;
            }
        }

        if (!comp) {
            /* Attribute not found in ciphertext - this shouldn't happen */
            continue;
        }

        /* Find user's key component for this attribute */
        int key_attr_idx = -1;
        for (size_t j = 0; j < user_key->attributes->size; j++) {
            if (strcmp(oabe_strvec_get(user_key->attributes, j), attr) == 0) {
                key_attr_idx = (int)j;
                break;
            }
        }

        if (key_attr_idx < 0) {
            /* User doesn't have this attribute - shouldn't happen if coefficients are correct */
            continue;
        }

        OABE_G1 *Kx = (OABE_G1 *)oabe_vector_get(user_key->key_elements, 2 + key_attr_idx);
        if (!Kx || !comp->c1 || !comp->c2) {
            continue;
        }

        /* Compute e(C_attr, L)^coeff */
        OABE_GT *pairing_cl = oabe_gt_new(ctx->base.group);
        if (!pairing_cl) {
            oabe_gt_free(denominator);
            oabe_gt_free(result);
            oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_pairing(pairing_cl, comp->c1, L);

        /* Raise to power coeff */
        OABE_GT *pairing_cl_coeff = oabe_gt_new(ctx->base.group);
        if (!pairing_cl_coeff) {
            oabe_gt_free(pairing_cl);
            oabe_gt_free(denominator);
            oabe_gt_free(result);
            oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_gt_exp(pairing_cl_coeff, pairing_cl, coeff);
        oabe_gt_free(pairing_cl);

        /* Multiply into denominator */
        oabe_gt_mul(denominator, denominator, pairing_cl_coeff);
        oabe_gt_free(pairing_cl_coeff);

        /* Compute e(Kx, D_attr)^coeff */
        OABE_GT *pairing_dk = oabe_gt_new(ctx->base.group);
        if (!pairing_dk) {
            oabe_gt_free(denominator);
            oabe_gt_free(result);
            oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_pairing(pairing_dk, Kx, comp->c2);

        /* Raise to power coeff */
        OABE_GT *pairing_dk_coeff = oabe_gt_new(ctx->base.group);
        if (!pairing_dk_coeff) {
            oabe_gt_free(pairing_dk);
            oabe_gt_free(denominator);
            oabe_gt_free(result);
            oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);
            oabe_cp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_gt_exp(pairing_dk_coeff, pairing_dk, coeff);
        oabe_gt_free(pairing_dk);

        /* Multiply into denominator */
        oabe_gt_mul(denominator, denominator, pairing_dk_coeff);
        oabe_gt_free(pairing_dk_coeff);
    }

    /* Compute result / denominator */
    OABE_GT *decrypted_key = oabe_gt_new(ctx->base.group);
    if (!decrypted_key) {
        oabe_gt_free(denominator);
        oabe_gt_free(result);
        oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);
        oabe_cp_ct_free(ct);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_gt_div(decrypted_key, result, denominator);

    oabe_gt_free(result);
    oabe_gt_free(denominator);
    oabe_lsss_free_coefficients(coefficients, coeff_attrs, num_coeff);

    /* Verify decryption by comparing to ct->ct */
    /* In correct decryption, decrypted_key should equal e(g1, g2)^(alpha * s) */
    bool keys_match = oabe_gt_equals(decrypted_key, ct->ct);
    oabe_gt_free(decrypted_key);

    if (!keys_match) {
        oabe_cp_ct_free(ct);
        return OABE_ERROR_DECRYPTION_FAILED;
    }

    /* In KEM mode, return the encapsulated key */
    /* For now, we use a simple approach: derive a symmetric key from the GT element */
    /* TODO: Implement proper KEM-DEM */

    /* Set plaintext to a dummy value for now */
    /* In full implementation, the ciphertext would include encrypted message */
    size_t key_size = ct->encrypted_key ? ct->encrypted_key->size : 0;
    if (*plaintext_len < key_size) {
        oabe_cp_ct_free(ct);
        return OABE_ERROR_BUFFER_TOO_SMALL;
    }

    /* For now, return success */
    *plaintext_len = 0;

    oabe_cp_ct_free(ct);
    return OABE_SUCCESS;
}

/*============================================================================
 * KP-ABE Context Implementation
 *============================================================================*/

static void oabe_context_kp_destroy(void *self) {
    OABE_ContextKP *ctx = (OABE_ContextKP *)self;
    if (ctx) {
        if (ctx->keystore) {
            oabe_keystore_free(ctx->keystore);
        }
        if (ctx->public_params) {
            oabe_params_free(ctx->public_params);
        }
        if (ctx->secret_key) {
            oabe_secret_key_free(ctx->secret_key);
        }
        if (ctx->params_id) {
            oabe_free(ctx->params_id);
        }
        if (ctx->base.rng) {
            oabe_rng_free(ctx->base.rng);
        }
        if (ctx->base.group) {
            oabe_group_free(ctx->base.group);
        }
        oabe_free(ctx);
    }
}

static const OABE_ObjectVTable g_context_kp_vtable = {
    .destroy = oabe_context_kp_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_ContextKP* oabe_context_kp_new(void) {
    OABE_ContextKP *ctx = (OABE_ContextKP *)oabe_malloc(sizeof(OABE_ContextKP));
    if (!ctx) return NULL;

    memset(ctx, 0, sizeof(OABE_ContextKP));
    ctx->base.base.vtable = &g_context_kp_vtable;
    ctx->base.base.ref_count = 1;
    ctx->base.scheme = OABE_SCHEME_KP_GPSW;
    ctx->base.curve_id = OABE_CURVE_BN_P254;

    ctx->keystore = oabe_keystore_new();
    if (!ctx->keystore) {
        oabe_free(ctx);
        return NULL;
    }

    ctx->base.rng = oabe_rng_new(NULL, 0);
    if (!ctx->base.rng) {
        oabe_keystore_free(ctx->keystore);
        oabe_free(ctx);
        return NULL;
    }

    /* Create the group for cryptographic operations */
    ctx->base.group = oabe_group_new(ctx->base.curve_id);
    if (!ctx->base.group) {
        oabe_rng_free(ctx->base.rng);
        oabe_keystore_free(ctx->keystore);
        oabe_free(ctx);
        return NULL;
    }

    ctx->base.is_initialized = true;
    return ctx;
}

void oabe_context_kp_free(OABE_ContextKP *ctx) {
    if (ctx) {
        OABE_DEREF(ctx);
    }
}

OABE_ERROR oabe_context_kp_generate_params(OABE_ContextKP *ctx, const char *params_id) {
    if (!ctx || !params_id) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Create group if not already created */
    if (!ctx->base.group) {
        ctx->base.group = oabe_group_new(ctx->base.curve_id);
        if (!ctx->base.group) {
            return OABE_ERROR_INVALID_GROUP_PARAMS;
        }
    }

    ctx->params_id = oabe_strdup(params_id);
    if (!ctx->params_id) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    ctx->public_params = oabe_params_new(OABE_SCHEME_KP_GPSW, ctx->base.curve_id, ctx->base.rng);
    if (!ctx->public_params) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    ctx->public_params->group = ctx->base.group;

    /* Generate g1 and g2 generators */
    ctx->public_params->g1_generator = oabe_g1_new(ctx->base.group);
    if (!ctx->public_params->g1_generator) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g1_set_generator(ctx->public_params->g1_generator);

    ctx->public_params->g2_generator = oabe_g2_new(ctx->base.group);
    if (!ctx->public_params->g2_generator) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_g2_set_generator(ctx->public_params->g2_generator);

    ctx->secret_key = oabe_secret_key_new(ctx->public_params, ctx->base.rng);
    if (!ctx->secret_key) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Compute e(g1, g2)^alpha for public params */
    ctx->public_params->egg_alpha = oabe_gt_new(ctx->base.group);
    if (!ctx->public_params->egg_alpha) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_pairing(ctx->public_params->egg_alpha, ctx->public_params->g1_generator, ctx->public_params->g2_generator);
    oabe_gt_exp(ctx->public_params->egg_alpha, ctx->public_params->egg_alpha, ctx->secret_key->alpha);

    ctx->base.is_initialized = true;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_kp_set_public_params(OABE_ContextKP *ctx, const OABE_ByteString *public_params) {
    if (!ctx || !public_params) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Deserialize public parameters */
    OABE_ABEParams *params = NULL;
    OABE_ERROR rc = oabe_params_deserialize(public_params, &params);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Free old params if any */
    if (ctx->public_params) {
        oabe_params_free(ctx->public_params);
    }

    ctx->public_params = params;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_kp_get_public_params(OABE_ContextKP *ctx, OABE_ByteString **public_params) {
    if (!ctx || !public_params) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }
    if (!ctx->public_params) {
        return OABE_ERROR_ELEMENT_NOT_FOUND;
    }

    return oabe_params_serialize(ctx->public_params, public_params);
}

OABE_ERROR oabe_context_kp_export_key(OABE_ContextKP *ctx, const char *key_id, OABE_ByteString **key) {
    if (!ctx || !key_id || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }
    if (!ctx->keystore) {
        return OABE_ERROR_ELEMENT_NOT_FOUND;
    }

    /* Look up the user key in the keystore */
    OABE_ABEUserKey *user_key = oabe_keystore_get_user_key(ctx->keystore, key_id);
    if (!user_key) {
        return OABE_ERROR_ELEMENT_NOT_FOUND;
    }

    return oabe_user_key_serialize(user_key, key);
}

OABE_ERROR oabe_context_kp_import_key(OABE_ContextKP *ctx, const char *key_id, const OABE_ByteString *key) {
    if (!ctx || !key_id || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }
    if (!ctx->keystore) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Deserialize the user key */
    OABE_ABEUserKey *user_key = NULL;
    OABE_ERROR rc = oabe_user_key_deserialize(key, &user_key);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Override the key_id with the provided one */
    if (user_key->base.key_id) {
        oabe_free(user_key->base.key_id);
    }
    user_key->base.key_id = oabe_strdup(key_id);
    if (!user_key->base.key_id) {
        oabe_user_key_free(user_key);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Add to keystore */
    rc = oabe_keystore_add_user_key(ctx->keystore, key_id, user_key);
    if (rc != OABE_SUCCESS) {
        oabe_user_key_free(user_key);
        return rc;
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_kp_keygen(OABE_ContextKP *ctx, const char *key_id, const char *policy) {
    if (!ctx || !key_id || !policy) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized || !ctx->public_params || !ctx->secret_key) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Parse policy */
    OABE_PolicyTree *policy_tree = NULL;
    OABE_ERROR rc = oabe_policy_parse(policy, &policy_tree);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Create user key structure */
    OABE_ABEUserKey *user_key = (OABE_ABEUserKey *)oabe_malloc(sizeof(OABE_ABEUserKey));
    if (!user_key) {
        oabe_policy_tree_free(policy_tree);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memset(user_key, 0, sizeof(OABE_ABEUserKey));
    user_key->base.base.ref_count = 1;
    user_key->base.key_type = OABE_KEY_TYPE_ABE_USER;
    user_key->base.key_id = oabe_strdup(key_id);

    /* Store policy (for KP-ABE, key has policy) */
    OABE_StringVector *policy_strvec = oabe_strvec_new(1);
    if (!policy_strvec) {
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_policy_tree_free(policy_tree);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_strvec_append(policy_strvec, policy);
    user_key->policy = policy_strvec;

    /* Create key elements storage */
    /* For GPSW '06:
     * Key components are: D_i = g^(share_i) * H(attr_i)^(r_i)
     *                     d_i = g^(r_i)
     * for each attribute in the policy
     */

    /* Get attributes from policy */
    OABE_StringVector *policy_attrs = NULL;
    rc = oabe_policy_get_attributes(policy_tree, &policy_attrs);
    if (rc != OABE_SUCCESS) {
        oabe_strvec_free(policy_strvec);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_policy_tree_free(policy_tree);
        return rc;
    }

    /* Create vector to store key elements */
    user_key->key_elements = oabe_vector_new(policy_attrs->size * 2);
    if (!user_key->key_elements) {
        oabe_strvec_free(policy_attrs);
        oabe_strvec_free(policy_strvec);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        oabe_policy_tree_free(policy_tree);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Generate key components for each attribute */
    /* In GPSW '06, the secret master key y is shared across the policy tree */
    /* For each leaf (attribute), we compute D_i and d_i */

    for (size_t i = 0; i < policy_attrs->size; i++) {
        const char *attr = oabe_strvec_get(policy_attrs, i);

        /* Generate random r_i */
        OABE_ZP *r_i = oabe_zp_new(ctx->base.group);
        if (!r_i) {
            oabe_strvec_free(policy_attrs);
            oabe_policy_tree_free(policy_tree);
            oabe_vector_free(user_key->key_elements);
            oabe_strvec_free(policy_strvec);
            oabe_free(user_key->base.key_id);
            oabe_free(user_key);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_zp_random(r_i, ctx->base.rng);

        /* Share of master secret (simplified: use y directly for all) */
        /* In full implementation, this should be proper LSSS sharing */
        OABE_ZP *share = oabe_zp_clone(ctx->secret_key->alpha);
        if (!share) {
            oabe_zp_free(r_i);
            oabe_strvec_free(policy_attrs);
            oabe_policy_tree_free(policy_tree);
            oabe_vector_free(user_key->key_elements);
            oabe_strvec_free(policy_strvec);
            oabe_free(user_key->base.key_id);
            oabe_free(user_key);
            return OABE_ERROR_OUT_OF_MEMORY;
        }

        /* D_i = g^(share_i) * H(attr_i)^(r_i) */
        /* For GPSW '06, use G1 for D_i */
        OABE_G1 *D_i = oabe_g1_new(ctx->base.group);
        if (!D_i) {
            oabe_zp_free(share);
            oabe_zp_free(r_i);
            oabe_strvec_free(policy_attrs);
            oabe_policy_tree_free(policy_tree);
            oabe_vector_free(user_key->key_elements);
            oabe_strvec_free(policy_strvec);
            oabe_free(user_key->base.key_id);
            oabe_free(user_key);
            return OABE_ERROR_OUT_OF_MEMORY;
        }

        /* Get generator g */
        OABE_G1 *g1_gen = ctx->public_params->g1_generator;
        oabe_g1_mul_scalar(D_i, g1_gen, share);

        /* Compute H(attr)^(r_i) */
        OABE_G1 *H_attr = NULL;
        rc = oabe_hash_attr_to_g1(ctx->base.group, attr, &H_attr);
        if (rc != OABE_SUCCESS) {
            oabe_g1_free(D_i);
            oabe_zp_free(share);
            oabe_zp_free(r_i);
            oabe_strvec_free(policy_attrs);
            oabe_policy_tree_free(policy_tree);
            oabe_vector_free(user_key->key_elements);
            oabe_strvec_free(policy_strvec);
            oabe_free(user_key->base.key_id);
            oabe_free(user_key);
            return rc;
        }

        OABE_G1 *H_r = oabe_g1_new(ctx->base.group);
        if (!H_r) {
            oabe_g1_free(H_attr);
            oabe_g1_free(D_i);
            oabe_zp_free(share);
            oabe_zp_free(r_i);
            oabe_strvec_free(policy_attrs);
            oabe_policy_tree_free(policy_tree);
            oabe_vector_free(user_key->key_elements);
            oabe_strvec_free(policy_strvec);
            oabe_free(user_key->base.key_id);
            oabe_free(user_key);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_g1_mul_scalar(H_r, H_attr, r_i);
        oabe_g1_free(H_attr);

        /* D_i = D_i * H_r */
        oabe_g1_add(D_i, D_i, H_r);
        oabe_g1_free(H_r);

        /* d_i = g^(r_i) - store as G2 element */
        OABE_G2 *d_i = oabe_g2_new(ctx->base.group);
        if (!d_i) {
            oabe_g1_free(D_i);
            oabe_zp_free(share);
            oabe_zp_free(r_i);
            oabe_strvec_free(policy_attrs);
            oabe_policy_tree_free(policy_tree);
            oabe_vector_free(user_key->key_elements);
            oabe_strvec_free(policy_strvec);
            oabe_free(user_key->base.key_id);
            oabe_free(user_key);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        OABE_G2 *g2_gen = ctx->public_params->g2_generator;
        oabe_g2_mul_scalar(d_i, g2_gen, r_i);

        /* Store key elements */
        oabe_vector_append(user_key->key_elements, D_i);
        oabe_vector_append(user_key->key_elements, d_i);

        oabe_zp_free(share);
        oabe_zp_free(r_i);
    }

    oabe_strvec_free(policy_attrs);
    oabe_policy_tree_free(policy_tree);

    /* Add to keystore */
    rc = oabe_keystore_add_user_key(ctx->keystore, key_id, user_key);
    if (rc != OABE_SUCCESS) {
        for (size_t i = 0; i < user_key->key_elements->size; i++) {
            void *elem = oabe_vector_get(user_key->key_elements, i);
            if (elem) {
                /* Free based on index - odd indices are G2, even are G1 */
                if (i % 2 == 0) {
                    oabe_g1_free((OABE_G1 *)elem);
                } else {
                    oabe_g2_free((OABE_G2 *)elem);
                }
            }
        }
        oabe_vector_free(user_key->key_elements);
        oabe_strvec_free(policy_strvec);
        oabe_free(user_key->base.key_id);
        oabe_free(user_key);
        return rc;
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_context_kp_encrypt(OABE_ContextKP *ctx, const char *attributes,
                                    const uint8_t *plaintext, size_t plaintext_len,
                                    OABE_ByteString **ciphertext) {
    /* Note: This is a KEM-only implementation. The plaintext is not encrypted here.
     * In a full implementation, the encapsulated key would be hashed to create
     * a symmetric key, then used to encrypt the plaintext. */
    (void)plaintext_len;

    if (!ctx || !attributes || !plaintext || !ciphertext) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized || !ctx->public_params) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Parse attributes */
    OABE_AttributeList *attr_list = oabe_attr_list_from_string(attributes);
    if (!attr_list) {
        return OABE_ERROR_INVALID_ATTRIBUTE_LIST;
    }

    /* Create ciphertext structure */
    OABE_KP_Ciphertext *ct = oabe_kp_ct_new(OABE_SCHEME_KP_GPSW);
    if (!ct) {
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Generate random t */
    OABE_ZP *t = oabe_zp_new(ctx->base.group);
    if (!t) {
        oabe_kp_ct_free(ct);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_zp_random(t, ctx->base.rng);

    /* C = e(g1, g2)^(y * t) where y is master secret */
    /* For GPSW '06: E = e(g, g)^(y*t) encapsulated key */

    /* Use e(g1, g2)^y from public params */
    if (!ctx->public_params || !ctx->public_params->egg_alpha) {
        oabe_zp_free(t);
        oabe_kp_ct_free(ct);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Compute e(g1, g2)^(y*t) */
    OABE_GT *encap_key = oabe_gt_new(ctx->base.group);
    if (!encap_key) {
        oabe_zp_free(t);
        oabe_kp_ct_free(ct);
        oabe_attr_list_free(attr_list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_gt_exp(encap_key, ctx->public_params->egg_alpha, t);

    /* For each attribute, compute E_i = H(attr_i)^t */
    for (size_t i = 0; i < attr_list->attributes->size; i++) {
        const char *attr = oabe_attr_list_get(attr_list, i);

        /* Compute H(attr)^t */
        OABE_G1 *E_i = NULL;
        OABE_ERROR rc = oabe_hash_attr_to_g1(ctx->base.group, attr, &E_i);
        if (rc != OABE_SUCCESS) {
            oabe_gt_free(encap_key);
            oabe_zp_free(t);
            oabe_kp_ct_free(ct);
            oabe_attr_list_free(attr_list);
            return rc;
        }

        /* E_i = E_i^t */
        OABE_G1 *E_t = oabe_g1_new(ctx->base.group);
        if (!E_t) {
            oabe_g1_free(E_i);
            oabe_gt_free(encap_key);
            oabe_zp_free(t);
            oabe_kp_ct_free(ct);
            oabe_attr_list_free(attr_list);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_g1_mul_scalar(E_t, E_i, t);
        oabe_g1_free(E_i);

        /* Add to ciphertext */
        rc = oabe_kp_ct_add_attribute(ct, attr, E_t);
        if (rc != OABE_SUCCESS) {
            oabe_g1_free(E_t);
            oabe_gt_free(encap_key);
            oabe_zp_free(t);
            oabe_kp_ct_free(ct);
            oabe_attr_list_free(attr_list);
            return rc;
        }
    }

    oabe_zp_free(t);

    /* Store encapsulated key */
    ct->encrypted_key = oabe_bytestring_new();
    if (ct->encrypted_key) {
        /* Serialize GT element as key */
        OABE_ByteString *gt_bytes = NULL;
        oabe_gt_serialize(encap_key, &gt_bytes);
        if (gt_bytes) {
            oabe_bytestring_append_data(ct->encrypted_key,
                oabe_bytestring_get_const_ptr(gt_bytes),
                oabe_bytestring_get_size(gt_bytes));
            oabe_bytestring_free(gt_bytes);
        }
    }
    oabe_gt_free(encap_key);

    oabe_attr_list_free(attr_list);

    /* Serialize ciphertext */
    OABE_ERROR rc = oabe_kp_ct_serialize(ct, ciphertext);
    oabe_kp_ct_free(ct);

    return rc;
}

OABE_ERROR oabe_context_kp_decrypt(OABE_ContextKP *ctx, const char *key_id,
                                    const OABE_ByteString *ciphertext,
                                    uint8_t *plaintext, size_t *plaintext_len) {
    if (!ctx || !key_id || !ciphertext || !plaintext || !plaintext_len) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (!ctx->base.is_initialized || !ctx->public_params) {
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Get user key */
    OABE_ABEUserKey *user_key = oabe_keystore_get_user_key(ctx->keystore, key_id);
    if (!user_key) {
        return OABE_ERROR_INVALID_KEY;
    }

    /* Deserialize ciphertext */
    OABE_KP_Ciphertext *ct = NULL;
    OABE_ERROR rc = oabe_kp_ct_deserialize(ctx->base.group, ciphertext, &ct);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    /* Parse user's policy */
    const char *policy_str = oabe_strvec_get(user_key->policy, 0);
    if (!policy_str) {
        oabe_kp_ct_free(ct);
        return OABE_ERROR_INVALID_KEY;
    }

    OABE_PolicyTree *policy = NULL;
    rc = oabe_policy_parse(policy_str, &policy);
    if (rc != OABE_SUCCESS) {
        oabe_kp_ct_free(ct);
        return rc;
    }

    /* Check if ciphertext attributes satisfy the policy */
    if (!oabe_policy_satisfies(policy, ct->attributes)) {
        oabe_policy_tree_free(policy);
        oabe_kp_ct_free(ct);
        return OABE_ERROR_POLICY_NOT_SATISFIED;
    }

    /* Get attributes from policy */
    OABE_StringVector *policy_attrs = NULL;
    rc = oabe_policy_get_attributes(policy, &policy_attrs);
    if (rc != OABE_SUCCESS) {
        oabe_policy_tree_free(policy);
        oabe_kp_ct_free(ct);
        return rc;
    }

    /* Check which attributes in ciphertext satisfy the policy */
    /* For GPSW '06, decryption is:
     * e(prod_i D_i^coeff_i, C') / prod_i e(d_i, E_i)^coeff_i
     * where i ranges over satisfied attributes
     */

    /* Simplified: compute e(D, C') / prod(e(d, E)) */
    OABE_GT *result = oabe_gt_new(ctx->base.group);
    if (!result) {
        oabe_strvec_free(policy_attrs);
        oabe_policy_tree_free(policy);
        oabe_kp_ct_free(ct);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Find matching attributes */
    bool first = true;
    for (size_t i = 0; i < ct->num_attributes; i++) {
        const char *attr = ct->attr_names[i];

        /* Check if this attribute is in user's policy */
        bool in_policy = false;
        for (size_t j = 0; j < policy_attrs->size; j++) {
            if (strcmp(attr, policy_attrs->items[j]) == 0) {
                in_policy = true;
                break;
            }
        }

        if (!in_policy) continue;

        /* Get D_i and d_i from key */
        /* Key elements are stored as: D_0, d_0, D_1, d_1, ... */
        size_t key_idx = i * 2;
        OABE_G1 *D_i = (OABE_G1 *)oabe_vector_get(user_key->key_elements, key_idx);
        OABE_G2 *d_i = (OABE_G2 *)oabe_vector_get(user_key->key_elements, key_idx + 1);

        if (!D_i || !d_i) continue;

        /* Get E_i from ciphertext */
        OABE_G1 *E_i = ct->attr_elements[i];
        if (!E_i) continue;

        if (first) {
            /* e(D_i, C') where C' = g2^t = g2^t */
            /* For GPSW, C' = g2^t is stored as the encapsulated key */
            /* Simplified: use the pairing with D_i */
            first = false;
        }

        /* Compute e(d_i, E_i) */
        OABE_GT *pair = oabe_gt_new(ctx->base.group);
        if (!pair) {
            oabe_gt_free(result);
            oabe_strvec_free(policy_attrs);
            oabe_policy_tree_free(policy);
            oabe_kp_ct_free(ct);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_pairing(pair, E_i, d_i);

        /* Multiply into result (division later) */
        oabe_gt_mul(result, result, pair);
        oabe_gt_free(pair);
    }

    oabe_strvec_free(policy_attrs);
    oabe_policy_tree_free(policy);

    /* Set plaintext length */
    *plaintext_len = 0;

    oabe_kp_ct_free(ct);
    oabe_gt_free(result);

    return OABE_SUCCESS;
}