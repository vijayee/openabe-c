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
/// \file   oabe_context.h
///
/// \brief  ABE context structures for OpenABE C implementation.
///

#ifndef OABE_CONTEXT_H
#define OABE_CONTEXT_H

#include "oabe_types.h"
#include "oabe_memory.h"
#include "oabe_bytestring.h"
#include "oabe_zml.h"
#include "oabe_key.h"
#include "oabe_policy.h"
#include "oabe_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Context Base Structure
 *============================================================================*/

/**
 * Base context structure.
 */
typedef struct OABE_ContextBase {
    OABE_Object base;
    OABE_Scheme scheme;
    OABE_CurveID curve_id;
    OABE_GroupHandle group;
    OABE_RNGHandle rng;
    bool is_initialized;
} OABE_ContextBase;

/*============================================================================
 * Symmetric Key Context
 *============================================================================*/

/**
 * Symmetric encryption context (AES-GCM).
 */
typedef struct OABE_ContextAES {
    OABE_ContextBase base;
    OABE_SymKey *key;
    uint8_t *iv;               /* Last used IV */
    size_t iv_len;
} OABE_ContextAES;

/**
 * Create a new AES-GCM context.
 * @return Context, or NULL on failure
 */
OABE_ContextAES* oabe_context_aes_new(void);

/**
 * Free an AES context.
 * @param ctx Context
 */
void oabe_context_aes_free(OABE_ContextAES *ctx);

/**
 * Set the encryption key.
 * @param ctx Context
 * @param key Key bytes
 * @param key_len Key length (16, 24, or 32)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_aes_set_key(OABE_ContextAES *ctx, const uint8_t *key, size_t key_len);

/**
 * Encrypt data using AES-GCM.
 * @param ctx Context
 * @param plaintext Plaintext
 * @param plaintext_len Length of plaintext
 * @param iv Initialization vector (can be NULL for auto-generation)
 * @param iv_len Length of IV (should be 12 for GCM)
 * @param ciphertext Output ByteString (caller must free)
 * @param tag Output authentication tag (16 bytes)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_aes_encrypt(OABE_ContextAES *ctx,
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     const uint8_t *iv, size_t iv_len,
                                     OABE_ByteString **ciphertext,
                                     uint8_t tag[16]);

/**
 * Decrypt data using AES-GCM.
 * @param ctx Context
 * @param ciphertext Ciphertext
 * @param ciphertext_len Length of ciphertext
 * @param iv Initialization vector
 * @param iv_len Length of IV
 * @param tag Authentication tag (16 bytes)
 * @param plaintext Output buffer
 * @param plaintext_len Input: buffer size, Output: actual length
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_aes_decrypt(OABE_ContextAES *ctx,
                                     const uint8_t *ciphertext, size_t ciphertext_len,
                                     const uint8_t *iv, size_t iv_len,
                                     const uint8_t tag[16],
                                     uint8_t *plaintext, size_t *plaintext_len);

/*============================================================================
 * CP-ABE Context (Waters '09)
 *============================================================================*/

/**
 * CP-ABE context structure.
 */
typedef struct OABE_ContextCP {
    OABE_ContextBase base;
    OABE_KeyStore *keystore;
    OABE_ABEParams *public_params;
    OABE_ABESecretKey *secret_key;
    char *params_id;
    /* Waters '09 specific elements */
    OABE_G1 *g1;              /* Generator g */
    OABE_G1 *g1_alpha;        /* g^alpha */
    OABE_G2 *g2;              /* Generator h */
} OABE_ContextCP;

/**
 * Create a new CP-ABE Waters context.
 * @return Context, or NULL on failure
 */
OABE_ContextCP* oabe_context_cp_new(void);

/**
 * Free a CP-ABE context.
 * @param ctx Context
 */
void oabe_context_cp_free(OABE_ContextCP *ctx);

/**
 * Generate public and secret parameters.
 * @param ctx Context
 * @param params_id Parameters identifier
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_generate_params(OABE_ContextCP *ctx, const char *params_id);

/**
 * Set public parameters from serialized data.
 * @param ctx Context
 * @param public_params Serialized public parameters
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_set_public_params(OABE_ContextCP *ctx, const OABE_ByteString *public_params);

/**
 * Get public parameters as serialized data.
 * @param ctx Context
 * @param public_params Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_get_public_params(OABE_ContextCP *ctx, OABE_ByteString **public_params);

/**
 * Set secret key from serialized data.
 * @param ctx Context
 * @param secret_key Serialized secret key
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_set_secret_key(OABE_ContextCP *ctx, const OABE_ByteString *secret_key);

/**
 * Get secret key as serialized data.
 * @param ctx Context
 * @param secret_key Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_get_secret_key(OABE_ContextCP *ctx, OABE_ByteString **secret_key);

/**
 * Generate a user key for an attribute list.
 * @param ctx Context
 * @param key_id Key identifier
 * @param attributes Attribute list (pipe-separated)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_keygen(OABE_ContextCP *ctx, const char *key_id, const char *attributes);

/**
 * Export a user key.
 * @param ctx Context
 * @param key_id Key identifier
 * @param key Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_export_key(OABE_ContextCP *ctx, const char *key_id, OABE_ByteString **key);

/**
 * Import a user key.
 * @param ctx Context
 * @param key_id Key identifier
 * @param key Serialized key
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_import_key(OABE_ContextCP *ctx, const char *key_id, const OABE_ByteString *key);

/**
 * Encrypt data with a policy.
 * @param ctx Context
 * @param policy Encryption policy
 * @param plaintext Plaintext
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_encrypt(OABE_ContextCP *ctx, const char *policy,
                                    const uint8_t *plaintext, size_t plaintext_len,
                                    OABE_ByteString **ciphertext);

/**
 * Decrypt data with a user key.
 * @param ctx Context
 * @param key_id Key identifier
 * @param ciphertext Ciphertext
 * @param plaintext Output buffer
 * @param plaintext_len Input: buffer size, Output: actual length
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_cp_decrypt(OABE_ContextCP *ctx, const char *key_id,
                                    const OABE_ByteString *ciphertext,
                                    uint8_t *plaintext, size_t *plaintext_len);

/*============================================================================
 * KP-ABE Context (GPSW '06)
 *============================================================================*/

/**
 * KP-ABE context structure.
 */
typedef struct OABE_ContextKP {
    OABE_ContextBase base;
    OABE_KeyStore *keystore;
    OABE_ABEParams *public_params;
    OABE_ABESecretKey *secret_key;
    char *params_id;
} OABE_ContextKP;

/**
 * Create a new KP-ABE GPSW context.
 * @return Context, or NULL on failure
 */
OABE_ContextKP* oabe_context_kp_new(void);

/**
 * Free a KP-ABE context.
 * @param ctx Context
 */
void oabe_context_kp_free(OABE_ContextKP *ctx);

/**
 * Generate public and secret parameters.
 * @param ctx Context
 * @param params_id Parameters identifier
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_kp_generate_params(OABE_ContextKP *ctx, const char *params_id);

/**
 * Set public parameters.
 * @param ctx Context
 * @param public_params Serialized public parameters
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_kp_set_public_params(OABE_ContextKP *ctx, const OABE_ByteString *public_params);

/**
 * Get public parameters.
 * @param ctx Context
 * @param public_params Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_kp_get_public_params(OABE_ContextKP *ctx, OABE_ByteString **public_params);

/**
 * Export a user key.
 * @param ctx Context
 * @param key_id Key identifier
 * @param key Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_kp_export_key(OABE_ContextKP *ctx, const char *key_id, OABE_ByteString **key);

/**
 * Import a user key.
 * @param ctx Context
 * @param key_id Key identifier
 * @param key Serialized key
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_kp_import_key(OABE_ContextKP *ctx, const char *key_id, const OABE_ByteString *key);

/**
 * Generate a user key for a policy.
 * @param ctx Context
 * @param key_id Key identifier
 * @param policy Key policy
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_kp_keygen(OABE_ContextKP *ctx, const char *key_id, const char *policy);

/**
 * Encrypt data with attributes.
 * @param ctx Context
 * @param attributes Attributes (pipe-separated)
 * @param plaintext Plaintext
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_kp_encrypt(OABE_ContextKP *ctx, const char *attributes,
                                    const uint8_t *plaintext, size_t plaintext_len,
                                    OABE_ByteString **ciphertext);

/**
 * Decrypt data with a user key.
 * @param ctx Context
 * @param key_id Key identifier
 * @param ciphertext Ciphertext
 * @param plaintext Output buffer
 * @param plaintext_len Input: buffer size, Output: actual length
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_kp_decrypt(OABE_ContextKP *ctx, const char *key_id,
                                    const OABE_ByteString *ciphertext,
                                    uint8_t *plaintext, size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* OABE_CONTEXT_H */