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
/// \file   oabe_crypto.c
///
/// \brief  High-level cryptographic API implementation for OpenABE C.
///

#include <string.h>
#include <stdio.h>
#include "openabe/oabe_crypto.h"
#include "openabe/oabe_context.h"
#include "openabe/oabe_memory.h"
#include "openabe/oabe_init.h"

/*============================================================================
 * Context Management
 *============================================================================*/

OABE_Context* oabe_context_cp_waters_new(void) {
    return (OABE_Context *)oabe_context_cp_new();
}

OABE_Context* oabe_context_kp_gpsw_new(void) {
    return (OABE_Context *)oabe_context_kp_new();
}

void oabe_context_free(OABE_Context *ctx) {
    if (ctx) {
        OABE_DEREF(ctx);
    }
}

OABE_ERROR oabe_context_generate_params(OABE_Context *ctx, const char *params_id) {
    if (!ctx || !params_id) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Determine context type and call appropriate function */
    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_generate_params((OABE_ContextCP *)ctx, params_id);
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA:
            return oabe_context_kp_generate_params((OABE_ContextKP *)ctx, params_id);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

OABE_ERROR oabe_context_set_public_params(OABE_Context *ctx, const OABE_ByteString *public_params) {
    if (!ctx || !public_params) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_set_public_params((OABE_ContextCP *)ctx, public_params);
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA:
            return oabe_context_kp_set_public_params((OABE_ContextKP *)ctx, public_params);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

OABE_ERROR oabe_context_get_public_params(OABE_Context *ctx, OABE_ByteString **public_params) {
    if (!ctx || !public_params) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_get_public_params((OABE_ContextCP *)ctx, public_params);
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA:
            return oabe_context_kp_get_public_params((OABE_ContextKP *)ctx, public_params);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

OABE_ERROR oabe_context_set_secret_params(OABE_Context *ctx, const OABE_ByteString *secret_params) {
    if (!ctx || !secret_params) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_set_secret_key((OABE_ContextCP *)ctx, secret_params);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

OABE_ERROR oabe_context_get_secret_params(OABE_Context *ctx, OABE_ByteString **secret_params) {
    if (!ctx || !secret_params) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_get_secret_key((OABE_ContextCP *)ctx, secret_params);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

/*============================================================================
 * Key Management
 *============================================================================*/

OABE_ERROR oabe_context_keygen(OABE_Context *ctx, const char *key_id,
                                const char *attr_or_policy, OABE_ByteString **key) {
    if (!ctx || !key_id || !attr_or_policy) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    OABE_ERROR rc;

    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            rc = oabe_context_cp_keygen((OABE_ContextCP *)ctx, key_id, attr_or_policy);
            if (rc != OABE_SUCCESS) return rc;
            if (key) {
                return oabe_context_cp_export_key((OABE_ContextCP *)ctx, key_id, key);
            }
            return OABE_SUCCESS;

        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA:
            rc = oabe_context_kp_keygen((OABE_ContextKP *)ctx, key_id, attr_or_policy);
            if (rc != OABE_SUCCESS) return rc;
            if (key) {
                return oabe_context_kp_export_key((OABE_ContextKP *)ctx, key_id, key);
            }
            return OABE_SUCCESS;

        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

OABE_ERROR oabe_context_import_key(OABE_Context *ctx, const char *key_id,
                                   const OABE_ByteString *key) {
    if (!ctx || !key_id || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_import_key((OABE_ContextCP *)ctx, key_id, key);
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA:
            return oabe_context_kp_import_key((OABE_ContextKP *)ctx, key_id, key);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

OABE_ERROR oabe_context_export_key(OABE_Context *ctx, const char *key_id,
                                    OABE_ByteString **key) {
    if (!ctx || !key_id || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_export_key((OABE_ContextCP *)ctx, key_id, key);
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA:
            return oabe_context_kp_export_key((OABE_ContextKP *)ctx, key_id, key);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

bool oabe_context_has_key(OABE_Context *ctx, const char *key_id) {
    if (!ctx || !key_id) return false;

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA: {
            OABE_ContextCP *cp_ctx = (OABE_ContextCP *)ctx;
            return oabe_keystore_has_user_key(cp_ctx->keystore, key_id);
        }
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA: {
            OABE_ContextKP *kp_ctx = (OABE_ContextKP *)ctx;
            return oabe_keystore_has_user_key(kp_ctx->keystore, key_id);
        }
        default:
            return false;
    }
}

OABE_ERROR oabe_context_delete_key(OABE_Context *ctx, const char *key_id) {
    if (!ctx || !key_id) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA: {
            OABE_ContextCP *cp_ctx = (OABE_ContextCP *)ctx;
            return oabe_keystore_remove_user_key(cp_ctx->keystore, key_id);
        }
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA: {
            OABE_ContextKP *kp_ctx = (OABE_ContextKP *)ctx;
            return oabe_keystore_remove_user_key(kp_ctx->keystore, key_id);
        }
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

/*============================================================================
 * Encryption/Decryption
 *============================================================================*/

OABE_ERROR oabe_context_encrypt(OABE_Context *ctx, const char *policy_or_attrs,
                                const uint8_t *plaintext, size_t plaintext_len,
                                OABE_ByteString **ciphertext) {
    if (!ctx || !policy_or_attrs || !plaintext || !ciphertext) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_encrypt((OABE_ContextCP *)ctx, policy_or_attrs,
                                           plaintext, plaintext_len, ciphertext);
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA:
            return oabe_context_kp_encrypt((OABE_ContextKP *)ctx, policy_or_attrs,
                                           plaintext, plaintext_len, ciphertext);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

OABE_ERROR oabe_context_decrypt(OABE_Context *ctx, const char *key_id,
                                const OABE_ByteString *ciphertext,
                                uint8_t *plaintext, size_t *plaintext_len) {
    if (!ctx || !key_id || !ciphertext || !plaintext || !plaintext_len) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    switch (base->scheme) {
        case OABE_SCHEME_CP_WATERS:
        case OABE_SCHEME_CP_WATERS_CCA:
            return oabe_context_cp_decrypt((OABE_ContextCP *)ctx, key_id,
                                           ciphertext, plaintext, plaintext_len);
        case OABE_SCHEME_KP_GPSW:
        case OABE_SCHEME_KP_GPSW_CCA:
            return oabe_context_kp_decrypt((OABE_ContextKP *)ctx, key_id,
                                           ciphertext, plaintext, plaintext_len);
        default:
            return OABE_ERROR_UNKNOWN_SCHEME;
    }
}

/*============================================================================
 * Symmetric Key Crypto Context
 *============================================================================*/

OABE_Context* oabe_context_aes_gcm_new(void) {
    return (OABE_Context *)oabe_context_aes_new();
}

OABE_ERROR oabe_context_set_symmetric_key(OABE_Context *ctx,
                                          const uint8_t *key, size_t key_len) {
    if (!ctx || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    if (base->scheme != OABE_SCHEME_AES_GCM) {
        return OABE_ERROR_INVALID_CONTEXT;
    }

    return oabe_context_aes_set_key((OABE_ContextAES *)ctx, key, key_len);
}

OABE_ERROR oabe_context_symmetric_encrypt(OABE_Context *ctx,
                                          const uint8_t *plaintext, size_t plaintext_len,
                                          const uint8_t *iv, size_t iv_len,
                                          OABE_ByteString **ciphertext) {
    if (!ctx || !plaintext || !ciphertext) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    if (base->scheme != OABE_SCHEME_AES_GCM) {
        return OABE_ERROR_INVALID_CONTEXT;
    }

    uint8_t tag[16];
    return oabe_context_aes_encrypt((OABE_ContextAES *)ctx, plaintext, plaintext_len,
                                    iv, iv_len, ciphertext, tag);
}

OABE_ERROR oabe_context_symmetric_decrypt(OABE_Context *ctx,
                                          const OABE_ByteString *ciphertext,
                                          uint8_t *plaintext, size_t *plaintext_len,
                                          const uint8_t *iv, size_t iv_len) {
    if (!ctx || !ciphertext || !plaintext || !plaintext_len) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ContextBase *base = (OABE_ContextBase *)ctx;
    if (base->scheme != OABE_SCHEME_AES_GCM) {
        return OABE_ERROR_INVALID_CONTEXT;
    }

    uint8_t tag[16] = {0};  /* Placeholder - should be passed in */
    return oabe_context_aes_decrypt((OABE_ContextAES *)ctx,
                                    oabe_bytestring_get_const_ptr(ciphertext),
                                    oabe_bytestring_get_size(ciphertext),
                                    iv, iv_len, tag, plaintext, plaintext_len);
}

/*============================================================================
 * Convenience Functions
 *============================================================================*/

OABE_ERROR oabe_cp_encrypt(const OABE_ByteString *public_params,
                           const char *policy,
                           const uint8_t *plaintext, size_t plaintext_len,
                           OABE_ByteString **ciphertext) {
    OABE_ContextCP *ctx = oabe_context_cp_new();
    if (!ctx) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ERROR rc = oabe_context_cp_set_public_params(ctx, public_params);
    if (rc != OABE_SUCCESS) {
        oabe_context_cp_free(ctx);
        return rc;
    }

    rc = oabe_context_cp_encrypt(ctx, policy, plaintext, plaintext_len, ciphertext);
    oabe_context_cp_free(ctx);
    return rc;
}

OABE_ERROR oabe_cp_decrypt(const OABE_ByteString *public_params,
                           const OABE_ByteString *user_key,
                           const OABE_ByteString *ciphertext,
                           uint8_t *plaintext, size_t *plaintext_len) {
    if (!public_params || !user_key || !ciphertext || !plaintext || !plaintext_len) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Create context - note: oabe_context_cp_new() already creates keystore and initializes group */
    OABE_ContextCP *ctx = oabe_context_cp_new();
    if (!ctx) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Set public parameters */
    OABE_ERROR rc = oabe_context_cp_set_public_params(ctx, public_params);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "DEBUG: set_public_params failed: %d\n", rc);
        oabe_context_cp_free(ctx);
        return rc;
    }

    /* Import user key */
    rc = oabe_context_cp_import_key(ctx, "temp_key", user_key);
    if (rc != OABE_SUCCESS) {
        oabe_context_cp_free(ctx);
        return rc;
    }

    /* Decrypt */
    rc = oabe_context_cp_decrypt(ctx, "temp_key", ciphertext, plaintext, plaintext_len);
    oabe_context_cp_free(ctx);
    return rc;
}

OABE_ERROR oabe_kp_encrypt(const OABE_ByteString *public_params,
                           const char *attributes,
                           const uint8_t *plaintext, size_t plaintext_len,
                           OABE_ByteString **ciphertext) {
    if (!public_params || !attributes || !plaintext || !ciphertext) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Create context */
    OABE_ContextKP *ctx = oabe_context_kp_new();
    if (!ctx) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ERROR rc;

    /* Initialize the context */
    ctx->base.is_initialized = true;
    ctx->base.scheme = OABE_SCHEME_KP_GPSW;
    ctx->base.curve_id = OABE_CURVE_BN_P254;

    /* Create keystore */
    ctx->keystore = oabe_keystore_new();
    if (!ctx->keystore) {
        oabe_context_kp_free(ctx);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Set public parameters */
    rc = oabe_context_kp_set_public_params(ctx, public_params);
    if (rc != OABE_SUCCESS) {
        oabe_context_kp_free(ctx);
        return rc;
    }

    /* Encrypt */
    rc = oabe_context_kp_encrypt(ctx, attributes, plaintext, plaintext_len, ciphertext);
    oabe_context_kp_free(ctx);
    return rc;
}

OABE_ERROR oabe_kp_decrypt(const OABE_ByteString *public_params,
                           const OABE_ByteString *user_key,
                           const OABE_ByteString *ciphertext,
                           uint8_t *plaintext, size_t *plaintext_len) {
    if (!public_params || !user_key || !ciphertext || !plaintext || !plaintext_len) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Create context - note: oabe_context_kp_new() already creates keystore and initializes group */
    OABE_ContextKP *ctx = oabe_context_kp_new();
    if (!ctx) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Set public parameters */
    OABE_ERROR rc = oabe_context_kp_set_public_params(ctx, public_params);
    if (rc != OABE_SUCCESS) {
        oabe_context_kp_free(ctx);
        return rc;
    }

    /* Import user key */
    rc = oabe_context_kp_import_key(ctx, "temp_key", user_key);
    if (rc != OABE_SUCCESS) {
        oabe_context_kp_free(ctx);
        return rc;
    }

    /* Decrypt */
    rc = oabe_context_kp_decrypt(ctx, "temp_key", ciphertext, plaintext, plaintext_len);
    oabe_context_kp_free(ctx);
    return rc;
}