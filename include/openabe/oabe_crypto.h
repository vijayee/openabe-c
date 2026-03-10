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
/// \file   oabe_crypto.h
///
/// \brief  High-level cryptographic API for OpenABE C implementation.
///         This provides a simplified interface for ABE operations.
///

#ifndef OABE_CRYPTO_H
#define OABE_CRYPTO_H

#include "oabe_types.h"
#include "oabe_memory.h"
#include "oabe_bytestring.h"
#include "oabe_zml.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * ABE Context Handle
 *============================================================================*/

/**
 * Opaque handle to an ABE context.
 */
typedef struct OABE_Context OABE_Context;

/**
 * Opaque handle to a key store.
 */
typedef struct OABE_KeyStore OABE_KeyStore;

/*============================================================================
 * Context Management
 *============================================================================*/

/**
 * Create a new ABE context for CP-ABE Waters scheme.
 * @return Context handle, or NULL on failure
 */
OABE_Context* oabe_context_cp_waters_new(void);

/**
 * Create a new ABE context for KP-ABE GPSW scheme.
 * @return Context handle, or NULL on failure
 */
OABE_Context* oabe_context_kp_gpsw_new(void);

/**
 * Free an ABE context.
 * @param ctx Context handle
 */
void oabe_context_free(OABE_Context *ctx);

/**
 * Generate public and secret parameters for an ABE scheme.
 * @param ctx Context handle
 * @param params_id Identifier for the parameters (e.g., "auth1")
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_generate_params(OABE_Context *ctx, const char *params_id);

/**
 * Set public parameters for an ABE context.
 * @param ctx Context handle
 * @param public_params Serialized public parameters
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_set_public_params(OABE_Context *ctx, const OABE_ByteString *public_params);

/**
 * Get public parameters from an ABE context.
 * @param ctx Context handle
 * @param public_params Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_get_public_params(OABE_Context *ctx, OABE_ByteString **public_params);

/**
 * Set secret parameters for an ABE context.
 * @param ctx Context handle
 * @param secret_params Serialized secret parameters
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_set_secret_params(OABE_Context *ctx, const OABE_ByteString *secret_params);

/**
 * Get secret parameters from an ABE context.
 * @param ctx Context handle
 * @param secret_params Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_get_secret_params(OABE_Context *ctx, OABE_ByteString **secret_params);

/*============================================================================
 * Key Management
 *============================================================================*/

/**
 * Generate a secret key for an attribute list (CP-ABE) or policy (KP-ABE).
 * @param ctx Context handle
 * @param key_id Key identifier (e.g., "user1")
 * @param attr_or_policy Attributes (CP-ABE) or policy (KP-ABE)
 * @param key Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_keygen(OABE_Context *ctx, const char *key_id,
                               const char *attr_or_policy, OABE_ByteString **key);

/**
 * Import a key into the context.
 * @param ctx Context handle
 * @param key_id Key identifier
 * @param key Serialized key
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_import_key(OABE_Context *ctx, const char *key_id,
                                   const OABE_ByteString *key);

/**
 * Export a key from the context.
 * @param ctx Context handle
 * @param key_id Key identifier
 * @param key Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_export_key(OABE_Context *ctx, const char *key_id,
                                    OABE_ByteString **key);

/**
 * Check if a key exists in the context.
 * @param ctx Context handle
 * @param key_id Key identifier
 * @return true if key exists, false otherwise
 */
bool oabe_context_has_key(OABE_Context *ctx, const char *key_id);

/**
 * Delete a key from the context.
 * @param ctx Context handle
 * @param key_id Key identifier
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_delete_key(OABE_Context *ctx, const char *key_id);

/*============================================================================
 * Encryption/Decryption
 *============================================================================*/

/**
 * Encrypt data using ABE with a policy (CP-ABE) or attributes (KP-ABE).
 * @param ctx Context handle
 * @param policy_or_attrs Policy (CP-ABE) or attributes (KP-ABE)
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_encrypt(OABE_Context *ctx, const char *policy_or_attrs,
                                const uint8_t *plaintext, size_t plaintext_len,
                                OABE_ByteString **ciphertext);

/**
 * Decrypt ABE-encrypted data.
 * @param ctx Context handle
 * @param key_id Key identifier for decryption
 * @param ciphertext Ciphertext data
 * @param plaintext Output buffer
 * @param plaintext_len Input: buffer size, Output: actual length
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_decrypt(OABE_Context *ctx, const char *key_id,
                                const OABE_ByteString *ciphertext,
                                uint8_t *plaintext, size_t *plaintext_len);

/*============================================================================
 * Symmetric Key Crypto Context
 *============================================================================*/

/**
 * Create a new symmetric key context for AES-GCM.
 * @return Context handle, or NULL on failure
 */
OABE_Context* oabe_context_aes_gcm_new(void);

/**
 * Set symmetric key for encryption/decryption.
 * @param ctx Context handle
 * @param key Key bytes
 * @param key_len Length of key (16, 24, or 32 bytes)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_set_symmetric_key(OABE_Context *ctx,
                                          const uint8_t *key, size_t key_len);

/**
 * Encrypt data using symmetric key.
 * @param ctx Context handle
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param iv Initialization vector (can be NULL for auto-generation)
 * @param iv_len Length of IV (16 bytes for AES-GCM)
 * @param ciphertext Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_symmetric_encrypt(OABE_Context *ctx,
                                          const uint8_t *plaintext, size_t plaintext_len,
                                          const uint8_t *iv, size_t iv_len,
                                          OABE_ByteString **ciphertext);

/**
 * Decrypt data using symmetric key.
 * @param ctx Context handle
 * @param ciphertext Ciphertext data
 * @param plaintext Output buffer
 * @param plaintext_len Input: buffer size, Output: actual length
 * @param iv Initialization vector
 * @param iv_len Length of IV
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_context_symmetric_decrypt(OABE_Context *ctx,
                                          const OABE_ByteString *ciphertext,
                                          uint8_t *plaintext, size_t *plaintext_len,
                                          const uint8_t *iv, size_t iv_len);

/*============================================================================
 * Key Store Functions
 *============================================================================*/

/**
 * Create a new key store.
 * @return Key store handle, or NULL on failure
 */
OABE_KeyStore* oabe_keystore_new(void);

/**
 * Free a key store.
 * @param store Key store handle
 */
void oabe_keystore_free(OABE_KeyStore *store);

/**
 * Add a key to the key store.
 * @param store Key store handle
 * @param key_id Key identifier
 * @param key Serialized key
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_keystore_add_key(OABE_KeyStore *store, const char *key_id,
                                  const OABE_ByteString *key);

/**
 * Get a key from the key store.
 * @param store Key store handle
 * @param key_id Key identifier
 * @param key Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_keystore_get_key(OABE_KeyStore *store, const char *key_id,
                                  OABE_ByteString **key);

/**
 * Remove a key from the key store.
 * @param store Key store handle
 * @param key_id Key identifier
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_keystore_remove_key(OABE_KeyStore *store, const char *key_id);

/**
 * Check if a key exists in the key store.
 * @param store Key store handle
 * @param key_id Key identifier
 * @return true if key exists, false otherwise
 */
bool oabe_keystore_has_key(OABE_KeyStore *store, const char *key_id);

/**
 * Get the number of keys in the key store.
 * @param store Key store handle
 * @return Number of keys
 */
size_t oabe_keystore_get_count(OABE_KeyStore *store);

/*============================================================================
 * Convenience Functions
 *============================================================================*/

/**
 * One-shot CP-ABE encryption.
 * @param public_params Serialized public parameters
 * @param policy Encryption policy
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_cp_encrypt(const OABE_ByteString *public_params,
                           const char *policy,
                           const uint8_t *plaintext, size_t plaintext_len,
                           OABE_ByteString **ciphertext);

/**
 * One-shot CP-ABE decryption.
 * @param public_params Serialized public parameters
 * @param secret_key Serialized secret key
 * @param ciphertext Ciphertext data
 * @param plaintext Output buffer
 * @param plaintext_len Input: buffer size, Output: actual length
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_cp_decrypt(const OABE_ByteString *public_params,
                           const OABE_ByteString *secret_key,
                           const OABE_ByteString *ciphertext,
                           uint8_t *plaintext, size_t *plaintext_len);

/**
 * One-shot KP-ABE encryption.
 * @param public_params Serialized public parameters
 * @param attributes Attributes for encryption
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_kp_encrypt(const OABE_ByteString *public_params,
                           const char *attributes,
                           const uint8_t *plaintext, size_t plaintext_len,
                           OABE_ByteString **ciphertext);

/**
 * One-shot KP-ABE decryption.
 * @param public_params Serialized public parameters
 * @param secret_key Serialized secret key
 * @param ciphertext Ciphertext data
 * @param plaintext Output buffer
 * @param plaintext_len Input: buffer size, Output: actual length
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_kp_decrypt(const OABE_ByteString *public_params,
                           const OABE_ByteString *secret_key,
                           const OABE_ByteString *ciphertext,
                           uint8_t *plaintext, size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* OABE_CRYPTO_H */