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
/// \file   oabe_hash.c
///
/// \brief  Hash-to-curve functions for ABE attribute hashing.
///

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <relic.h>
#include "openabe/oabe_hash.h"
#include "openabe/oabe_memory.h"

/*============================================================================
 * Internal Helper Functions
 *============================================================================*/

/**
 * Compute SHA-256 hash of prefix || attr.
 * @param prefix Prefix string
 * @param attr Attribute string
 * @param output Output buffer (must be at least 32 bytes)
 * @return OABE_SUCCESS or error code
 */
static OABE_ERROR compute_hash(const char *prefix, const char *attr, uint8_t *output) {
    if (!prefix || !attr || !output) {
        return OABE_ERROR_INVALID_INPUT;
    }

    size_t prefix_len = strlen(prefix);
    size_t attr_len = strlen(attr);

    /* Create combined buffer: prefix || attr */
    uint8_t *buffer = (uint8_t *)oabe_malloc(prefix_len + attr_len);
    if (!buffer) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memcpy(buffer, prefix, prefix_len);
    memcpy(buffer + prefix_len, attr, attr_len);

    /* Compute SHA-256 */
    SHA256(buffer, prefix_len + attr_len, output);

    oabe_free(buffer);
    return OABE_SUCCESS;
}

/**
 * Compute SHA-256 hash of prefix || ZP bytes.
 * @param prefix Prefix string
 * @param zp ZP element
 * @param output Output buffer (must be at least 32 bytes)
 * @return OABE_SUCCESS or error code
 */
static OABE_ERROR compute_hash_zp(const char *prefix, const OABE_ZP *zp, uint8_t *output) {
    if (!prefix || !zp || !output) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Get ZP bytes */
    OABE_ByteString *zp_bytes = NULL;
    OABE_ERROR rc = oabe_zp_serialize(zp, &zp_bytes);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    size_t prefix_len = strlen(prefix);
    size_t zp_len = oabe_bytestring_get_size(zp_bytes);
    const uint8_t *zp_data = oabe_bytestring_get_const_ptr(zp_bytes);

    /* Create combined buffer */
    uint8_t *buffer = (uint8_t *)oabe_malloc(prefix_len + zp_len);
    if (!buffer) {
        oabe_bytestring_free(zp_bytes);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memcpy(buffer, prefix, prefix_len);
    memcpy(buffer + prefix_len, zp_data, zp_len);

    /* Compute SHA-256 */
    SHA256(buffer, prefix_len + zp_len, output);

    oabe_free(buffer);
    oabe_bytestring_free(zp_bytes);
    return OABE_SUCCESS;
}

/*============================================================================
 * Internal G2 Structure Access
 *============================================================================*/

/* Forward declaration of internal G2 structure (matches oabe_zml_relic.c) */
typedef struct OABE_G2_Impl {
    OABE_Object base;
    OABE_GroupHandle group;
    g2_t point;
} OABE_G2_Impl;

/*============================================================================
 * Hash-to-Curve Implementation
 *============================================================================*/

OABE_ERROR oabe_hash_to_g1(OABE_GroupHandle group,
                            const char *prefix,
                            const char *attr,
                            OABE_G1 **result) {
    if (!group || !prefix || !attr || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = NULL;

    /* Allocate result */
    OABE_G1 *g1 = oabe_g1_new(group);
    if (!g1) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Compute hash */
    uint8_t hash[32];
    OABE_ERROR rc = compute_hash(prefix, attr, hash);
    if (rc != OABE_SUCCESS) {
        oabe_g1_free(g1);
        return rc;
    }

    /* Use hash to map to G1 */
    rc = oabe_g1_hash(g1, hash, 32);
    if (rc != OABE_SUCCESS) {
        oabe_g1_free(g1);
        return rc;
    }

    *result = g1;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_hash_to_g2(OABE_GroupHandle group,
                            const char *prefix,
                            const char *attr,
                            OABE_G2 **result) {
    if (!group || !prefix || !attr || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = NULL;

    /* Allocate result */
    OABE_G2 *g2 = oabe_g2_new(group);
    if (!g2) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Compute hash */
    uint8_t hash[32];
    OABE_ERROR rc = compute_hash(prefix, attr, hash);
    if (rc != OABE_SUCCESS) {
        oabe_g2_free(g2);
        return rc;
    }

    /* Map to G2 using RELIC's g2_map */
    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;
    g2_map(impl->point, hash, 32);

    *result = g2;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_hash_zp_to_g1(OABE_GroupHandle group,
                                const char *prefix,
                                const OABE_ZP *zp,
                                OABE_G1 **result) {
    if (!group || !prefix || !zp || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = NULL;

    /* Allocate result */
    OABE_G1 *g1 = oabe_g1_new(group);
    if (!g1) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Compute hash */
    uint8_t hash[32];
    OABE_ERROR rc = compute_hash_zp(prefix, zp, hash);
    if (rc != OABE_SUCCESS) {
        oabe_g1_free(g1);
        return rc;
    }

    /* Map to G1 */
    rc = oabe_g1_hash(g1, hash, 32);
    if (rc != OABE_SUCCESS) {
        oabe_g1_free(g1);
        return rc;
    }

    *result = g1;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_hash_zp_to_g2(OABE_GroupHandle group,
                                const char *prefix,
                                const OABE_ZP *zp,
                                OABE_G2 **result) {
    if (!group || !prefix || !zp || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = NULL;

    /* Allocate result */
    OABE_G2 *g2 = oabe_g2_new(group);
    if (!g2) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Compute hash */
    uint8_t hash[32];
    OABE_ERROR rc = compute_hash_zp(prefix, zp, hash);
    if (rc != OABE_SUCCESS) {
        oabe_g2_free(g2);
        return rc;
    }

    /* Map to G2 using RELIC */
    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;
    g2_map(impl->point, hash, 32);

    *result = g2;
    return OABE_SUCCESS;
}

/*============================================================================
 * Attribute Hash Functions
 *============================================================================*/

OABE_ERROR oabe_hash_attr_to_g1(OABE_GroupHandle group,
                                 const char *attr,
                                 OABE_G1 **result) {
    /* Use "0" as default prefix for attributes (Waters '09) */
    return oabe_hash_to_g1(group, OABE_HASH_FUNCTION_STRINGS, attr, result);
}

OABE_ERROR oabe_hash_attr_to_g2(OABE_GroupHandle group,
                                 const char *attr,
                                 OABE_G2 **result) {
    /* Use "0" as default prefix for attributes (GPSW '06) */
    return oabe_hash_to_g2(group, OABE_HASH_FUNCTION_STRINGS, attr, result);
}