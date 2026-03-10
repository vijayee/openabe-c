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
/// \file   oabe_key.h
///
/// \brief  Key structures for OpenABE C implementation.
///

#ifndef OABE_KEY_H
#define OABE_KEY_H

#include "oabe_types.h"
#include "oabe_memory.h"
#include "oabe_bytestring.h"
#include "oabe_zml.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Key Types
 *============================================================================*/

/**
 * Key type enumeration.
 */
typedef enum {
    OABE_KEY_TYPE_NONE = 0,
    OABE_KEY_TYPE_PUBLIC,           /* Public key */
    OABE_KEY_TYPE_SECRET,          /* Secret/master key */
    OABE_KEY_TYPE_PRIVATE,         /* Private key */
    OABE_KEY_TYPE_SYMMETRIC,       /* Symmetric key */
    OABE_KEY_TYPE_ABE_PUBLIC,      /* ABE public parameters */
    OABE_KEY_TYPE_ABE_SECRET,      /* ABE secret/master key */
    OABE_KEY_TYPE_ABE_USER         /* ABE user key */
} OABE_KeyType;

/**
 * Key header structure (serialized format).
 */
typedef struct {
    uint8_t key_type;               /* OABE_KeyType */
    uint8_t scheme_type;            /* OABE_Scheme */
    uint8_t curve_id;               /* OABE_CurveID */
    uint8_t reserved;
    uint32_t key_id;                /* Unique key ID */
    uint32_t body_len;              /* Length of key body */
} OABE_KeyHeader;

/*============================================================================
 * Base Key Structure
 *============================================================================*/

/**
 * Base key structure.
 */
typedef struct OABE_Key {
    OABE_Object base;
    OABE_KeyType key_type;
    OABE_Scheme scheme;
    char *key_id;                    /* Key identifier */
    OABE_ByteString *key_data;       /* Serialized key data */
} OABE_Key;

/*============================================================================
 * Symmetric Key
 *============================================================================*/

/**
 * Symmetric key structure.
 */
typedef struct OABE_SymKey {
    OABE_Key base;
    size_t key_len;                  /* Key length in bytes */
    uint8_t *key_bytes;              /* Raw key bytes */
} OABE_SymKey;

/**
 * Create a new symmetric key.
 * @param key_len Key length in bytes (16, 24, or 32 for AES)
 * @param rng RNG handle
 * @return Symmetric key, or NULL on failure
 */
OABE_SymKey* oabe_symkey_new(size_t key_len, OABE_RNGHandle rng);

/**
 * Create a symmetric key from bytes.
 * @param key_bytes Key bytes
 * @param key_len Length of key
 * @return Symmetric key, or NULL on failure
 */
OABE_SymKey* oabe_symkey_from_bytes(const uint8_t *key_bytes, size_t key_len);

/**
 * Free a symmetric key.
 * @param key Key to free
 */
void oabe_symkey_free(OABE_SymKey *key);

/**
 * Clone a symmetric key.
 * @param key Key to clone
 * @return Cloned key, or NULL on failure
 */
OABE_SymKey* oabe_symkey_clone(const OABE_SymKey *key);

/**
 * Serialize symmetric key to ByteString.
 * @param key Key
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_symkey_serialize(const OABE_SymKey *key, OABE_ByteString **result);

/**
 * Deserialize symmetric key from ByteString.
 * @param input Input ByteString
 * @param key Output key (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_symkey_deserialize(const OABE_ByteString *input, OABE_SymKey **key);

/*============================================================================
 * ABE Public Parameters
 *============================================================================*/

/**
 * ABE public parameters structure.
 */
typedef struct OABE_ABEParams {
    OABE_Key base;
    OABE_GroupHandle group;          /* Bilinear group */
    OABE_G1 *g1_generator;           /* G1 generator */
    OABE_G2 *g2_generator;           /* G2 generator (if applicable) */
    OABE_GT *gt_generator;           /* GT generator */
    /* CP-ABE public parameters */
    OABE_G1 *g1_alpha;               /* g1^alpha (h in Waters '09) */
    OABE_G1 *g1_a;                   /* g1^a (for Waters '09 encryption) */
    OABE_G2 *g2_a;                   /* g2^a (for Waters '09 keygen) */
    OABE_GT *egg_alpha;              /* e(g1, g2)^alpha */
    /* Scheme-specific parameters stored in key_data */
} OABE_ABEParams;

/**
 * Create ABE public parameters.
 * @param scheme Scheme type
 * @param curve_id Curve ID
 * @param rng RNG handle
 * @return Public parameters, or NULL on failure
 */
OABE_ABEParams* oabe_params_new(OABE_Scheme scheme, OABE_CurveID curve_id, OABE_RNGHandle rng);

/**
 * Free ABE public parameters.
 * @param params Parameters to free
 */
void oabe_params_free(OABE_ABEParams *params);

/**
 * Serialize ABE public parameters.
 * @param params Parameters
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_params_serialize(const OABE_ABEParams *params, OABE_ByteString **result);

/**
 * Deserialize ABE public parameters.
 * @param input Input ByteString
 * @param params Output parameters (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_params_deserialize(const OABE_ByteString *input, OABE_ABEParams **params);

/*============================================================================
 * ABE Secret Key (Master Key)
 *============================================================================*/

/**
 * ABE secret/master key structure.
 */
typedef struct OABE_ABESecretKey {
    OABE_Key base;
    OABE_ZP *alpha;                  /* Master secret (for CP-ABE) */
    OABE_ZP *beta;                   /* Additional secret parameter */
    /* Additional parameters stored in key_data */
} OABE_ABESecretKey;

/**
 * Create ABE secret key.
 * @param params Public parameters
 * @param rng RNG handle
 * @return Secret key, or NULL on failure
 */
OABE_ABESecretKey* oabe_secret_key_new(OABE_ABEParams *params, OABE_RNGHandle rng);

/**
 * Free ABE secret key.
 * @param key Key to free
 */
void oabe_secret_key_free(OABE_ABESecretKey *key);

/**
 * Serialize ABE secret key.
 * @param key Key
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_secret_key_serialize(const OABE_ABESecretKey *key, OABE_ByteString **result);

/**
 * Deserialize ABE secret key.
 * @param input Input ByteString
 * @param key Output key (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_secret_key_deserialize(const OABE_ByteString *input, OABE_ABESecretKey **key);

/*============================================================================
 * ABE User Key
 *============================================================================*/

/**
 * ABE user key structure.
 */
typedef struct OABE_ABEUserKey {
    OABE_Key base;
    OABE_StringVector *attributes;   /* Attributes (for CP-ABE) */
    OABE_StringVector *policy;        /* Policy (for KP-ABE) */
    OABE_Vector *key_elements;        /* Key elements (G1, G2 points) */
    /* Additional data stored in key_data */
} OABE_ABEUserKey;

/**
 * Create ABE user key.
 * @param key_id Key identifier
 * @param params Public parameters
 * @return User key, or NULL on failure
 */
OABE_ABEUserKey* oabe_user_key_new(const char *key_id, OABE_ABEParams *params);

/**
 * Free ABE user key.
 * @param key Key to free
 */
void oabe_user_key_free(OABE_ABEUserKey *key);

/**
 * Serialize ABE user key.
 * @param key Key
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_user_key_serialize(const OABE_ABEUserKey *key, OABE_ByteString **result);

/**
 * Deserialize ABE user key.
 * @param input Input ByteString
 * @param key Output key (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_user_key_deserialize(const OABE_ByteString *input, OABE_ABEUserKey **key);

/*============================================================================
 * Key Store
 *============================================================================*/

/**
 * Key store structure for managing multiple keys.
 */
typedef struct OABE_KeyStore {
    OABE_Object base;
    OABE_StringMap *public_keys;     /* Public parameters by ID */
    OABE_StringMap *secret_keys;    /* Secret keys by ID */
    OABE_StringMap *user_keys;      /* User keys by ID */
} OABE_KeyStore;

/**
 * Create a new key store.
 * @return Key store, or NULL on failure
 */
OABE_KeyStore* oabe_keystore_new(void);

/**
 * Free a key store.
 * @param store Key store
 */
void oabe_keystore_free(OABE_KeyStore *store);

/**
 * Add public parameters to key store.
 * @param store Key store
 * @param params_id Parameters identifier
 * @param params Public parameters
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_keystore_add_public(OABE_KeyStore *store, const char *params_id,
                                     OABE_ABEParams *params);

/**
 * Get public parameters from key store.
 * @param store Key store
 * @param params_id Parameters identifier
 * @return Public parameters, or NULL if not found
 */
OABE_ABEParams* oabe_keystore_get_public(OABE_KeyStore *store, const char *params_id);

/**
 * Add secret key to key store.
 * @param store Key store
 * @param params_id Parameters identifier
 * @param key Secret key
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_keystore_add_secret(OABE_KeyStore *store, const char *params_id,
                                     OABE_ABESecretKey *key);

/**
 * Get secret key from key store.
 * @param store Key store
 * @param params_id Parameters identifier
 * @return Secret key, or NULL if not found
 */
OABE_ABESecretKey* oabe_keystore_get_secret(OABE_KeyStore *store, const char *params_id);

/**
 * Add user key to key store.
 * @param store Key store
 * @param key_id Key identifier
 * @param key User key
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_keystore_add_user_key(OABE_KeyStore *store, const char *key_id,
                                       OABE_ABEUserKey *key);

/**
 * Get user key from key store.
 * @param store Key store
 * @param key_id Key identifier
 * @return User key, or NULL if not found
 */
OABE_ABEUserKey* oabe_keystore_get_user_key(OABE_KeyStore *store, const char *key_id);

/**
 * Remove user key from key store.
 * @param store Key store
 * @param key_id Key identifier
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_keystore_remove_user_key(OABE_KeyStore *store, const char *key_id);

/**
 * Check if user key exists in key store.
 * @param store Key store
 * @param key_id Key identifier
 * @return true if key exists, false otherwise
 */
bool oabe_keystore_has_user_key(OABE_KeyStore *store, const char *key_id);

/**
 * Get number of user keys in key store.
 * @param store Key store
 * @return Number of user keys
 */
size_t oabe_keystore_get_user_key_count(OABE_KeyStore *store);

#ifdef __cplusplus
}
#endif

#endif /* OABE_KEY_H */