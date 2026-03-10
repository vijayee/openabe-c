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
/// \file   oabe_key.c
///
/// \brief  Key structures implementation for OpenABE C.
///

#include <string.h>
#include "openabe/oabe_key.h"
#include "openabe/oabe_memory.h"
#include "openabe/oabe_rng.h"

/*============================================================================
 * Symmetric Key Implementation
 *============================================================================*/

static void oabe_symkey_destroy(void *self) {
    OABE_SymKey *key = (OABE_SymKey *)self;
    if (key) {
        if (key->key_bytes) {
            oabe_zeroize(key->key_bytes, key->key_len);
            oabe_free(key->key_bytes);
        }
        if (key->base.key_id) {
            oabe_free(key->base.key_id);
        }
        if (key->base.key_data) {
            oabe_bytestring_free(key->base.key_data);
        }
        oabe_free(key);
    }
}

static const OABE_ObjectVTable g_symkey_vtable = {
    .destroy = oabe_symkey_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_SymKey* oabe_symkey_new(size_t key_len, OABE_RNGHandle rng) {
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        return NULL;  /* AES key sizes only */
    }

    OABE_SymKey *key = (OABE_SymKey *)oabe_malloc(sizeof(OABE_SymKey));
    if (!key) return NULL;

    memset(key, 0, sizeof(OABE_SymKey));
    key->base.base.vtable = &g_symkey_vtable;
    key->base.base.ref_count = 1;
    key->base.key_type = OABE_KEY_TYPE_SYMMETRIC;
    key->key_len = key_len;

    key->key_bytes = (uint8_t *)oabe_malloc(key_len);
    if (!key->key_bytes) {
        oabe_free(key);
        return NULL;
    }

    if (rng) {
        /* Use the provided ZML RNG handle */
        if (oabe_rng_bytes(rng, key->key_bytes, key_len) != OABE_SUCCESS) {
            oabe_free(key->key_bytes);
            oabe_free(key);
            return NULL;
        }
    } else {
        /* Use system RNG (CTR_DRBG) */
        OABE_RNGCtx *sys_rng = oabe_rng_new_system();
        if (!sys_rng) {
            oabe_free(key->key_bytes);
            oabe_free(key);
            return NULL;
        }
        OABE_ERROR rc = oabe_rng_ctx_bytes(sys_rng, key->key_bytes, key_len);
        oabe_rng_ctx_free(sys_rng);
        if (rc != OABE_SUCCESS) {
            oabe_free(key->key_bytes);
            oabe_free(key);
            return NULL;
        }
    }

    return key;
}

OABE_SymKey* oabe_symkey_from_bytes(const uint8_t *key_bytes, size_t key_len) {
    if (!key_bytes || (key_len != 16 && key_len != 24 && key_len != 32)) {
        return NULL;
    }

    OABE_SymKey *key = (OABE_SymKey *)oabe_malloc(sizeof(OABE_SymKey));
    if (!key) return NULL;

    memset(key, 0, sizeof(OABE_SymKey));
    key->base.base.vtable = &g_symkey_vtable;
    key->base.base.ref_count = 1;
    key->base.key_type = OABE_KEY_TYPE_SYMMETRIC;
    key->key_len = key_len;

    key->key_bytes = (uint8_t *)oabe_malloc(key_len);
    if (!key->key_bytes) {
        oabe_free(key);
        return NULL;
    }

    memcpy(key->key_bytes, key_bytes, key_len);
    return key;
}

void oabe_symkey_free(OABE_SymKey *key) {
    if (key) {
        OABE_DEREF(key);
    }
}

OABE_SymKey* oabe_symkey_clone(const OABE_SymKey *key) {
    if (!key) return NULL;
    return oabe_symkey_from_bytes(key->key_bytes, key->key_len);
}

OABE_ERROR oabe_symkey_serialize(const OABE_SymKey *key, OABE_ByteString **result) {
    if (!key || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Pack header */
    OABE_KeyHeader header = {
        .key_type = key->base.key_type,
        .scheme_type = 0,
        .curve_id = 0,
        .reserved = 0,
        .key_id = 0,
        .body_len = (uint32_t)key->key_len
    };

    oabe_bytestring_append_data(*result, (const uint8_t *)&header, sizeof(header));
    oabe_bytestring_append_data(*result, key->key_bytes, key->key_len);

    return OABE_SUCCESS;
}

OABE_ERROR oabe_symkey_deserialize(const OABE_ByteString *input, OABE_SymKey **key) {
    if (!input || !key || input->size < sizeof(OABE_KeyHeader)) {
        return OABE_ERROR_INVALID_INPUT;
    }

    const uint8_t *data = input->data;
    const OABE_KeyHeader *header = (const OABE_KeyHeader *)data;

    if (header->key_type != OABE_KEY_TYPE_SYMMETRIC) {
        return OABE_ERROR_INVALID_KEY_HEADER;
    }

    if (input->size < sizeof(OABE_KeyHeader) + header->body_len) {
        return OABE_ERROR_INVALID_KEY_BODY;
    }

    *key = oabe_symkey_from_bytes(data + sizeof(OABE_KeyHeader), header->body_len);
    return *key ? OABE_SUCCESS : OABE_ERROR_OUT_OF_MEMORY;
}

/*============================================================================
 * Key Store Implementation
 *============================================================================*/

static void oabe_keystore_destroy(void *self) {
    OABE_KeyStore *store = (OABE_KeyStore *)self;
    if (store) {
        /* Note: We don't free the keys themselves, just the maps */
        /* The keys should be freed separately by the caller */
        if (store->public_keys) {
            oabe_strmap_free(store->public_keys);
        }
        if (store->secret_keys) {
            oabe_strmap_free(store->secret_keys);
        }
        if (store->user_keys) {
            oabe_strmap_free(store->user_keys);
        }
        oabe_free(store);
    }
}

static const OABE_ObjectVTable g_keystore_vtable = {
    .destroy = oabe_keystore_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_KeyStore* oabe_keystore_new(void) {
    OABE_KeyStore *store = (OABE_KeyStore *)oabe_malloc(sizeof(OABE_KeyStore));
    if (!store) return NULL;

    memset(store, 0, sizeof(OABE_KeyStore));
    store->base.vtable = &g_keystore_vtable;
    store->base.ref_count = 1;

    store->public_keys = oabe_strmap_new(0);
    store->secret_keys = oabe_strmap_new(0);
    store->user_keys = oabe_strmap_new(0);

    if (!store->public_keys || !store->secret_keys || !store->user_keys) {
        if (store->public_keys) oabe_strmap_free(store->public_keys);
        if (store->secret_keys) oabe_strmap_free(store->secret_keys);
        if (store->user_keys) oabe_strmap_free(store->user_keys);
        oabe_free(store);
        return NULL;
    }

    return store;
}

void oabe_keystore_free(OABE_KeyStore *store) {
    if (store) {
        OABE_DEREF(store);
    }
}

OABE_ERROR oabe_keystore_add_public(OABE_KeyStore *store, const char *params_id,
                                     OABE_ABEParams *params) {
    if (!store || !params_id || !params) {
        return OABE_ERROR_INVALID_INPUT;
    }
    return oabe_strmap_insert(store->public_keys, params_id, params);
}

OABE_ABEParams* oabe_keystore_get_public(OABE_KeyStore *store, const char *params_id) {
    if (!store || !params_id) return NULL;
    return (OABE_ABEParams *)oabe_strmap_get(store->public_keys, params_id);
}

OABE_ERROR oabe_keystore_add_secret(OABE_KeyStore *store, const char *params_id,
                                     OABE_ABESecretKey *key) {
    if (!store || !params_id || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    return oabe_strmap_insert(store->secret_keys, params_id, key);
}

OABE_ABESecretKey* oabe_keystore_get_secret(OABE_KeyStore *store, const char *params_id) {
    if (!store || !params_id) return NULL;
    return (OABE_ABESecretKey *)oabe_strmap_get(store->secret_keys, params_id);
}

OABE_ERROR oabe_keystore_add_user_key(OABE_KeyStore *store, const char *key_id,
                                       OABE_ABEUserKey *key) {
    if (!store || !key_id || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    return oabe_strmap_insert(store->user_keys, key_id, key);
}

OABE_ABEUserKey* oabe_keystore_get_user_key(OABE_KeyStore *store, const char *key_id) {
    if (!store || !key_id) return NULL;
    return (OABE_ABEUserKey *)oabe_strmap_get(store->user_keys, key_id);
}

OABE_ERROR oabe_keystore_remove_user_key(OABE_KeyStore *store, const char *key_id) {
    if (!store || !key_id) {
        return OABE_ERROR_INVALID_INPUT;
    }
    return oabe_strmap_remove(store->user_keys, key_id);
}

bool oabe_keystore_has_user_key(OABE_KeyStore *store, const char *key_id) {
    if (!store || !key_id) return false;
    return oabe_strmap_contains(store->user_keys, key_id);
}

size_t oabe_keystore_get_user_key_count(OABE_KeyStore *store) {
    return store ? store->user_keys->size : 0;
}

/*============================================================================
 * ABE Params Implementation (Stub)
 *============================================================================*/

static void oabe_params_destroy(void *self) {
    OABE_ABEParams *params = (OABE_ABEParams *)self;
    if (params) {
        if (params->group) {
            oabe_group_free(params->group);
        }
        if (params->g1_generator) {
            oabe_g1_free(params->g1_generator);
        }
        if (params->g2_generator) {
            oabe_g2_free(params->g2_generator);
        }
        if (params->gt_generator) {
            oabe_gt_free(params->gt_generator);
        }
        if (params->g1_alpha) {
            oabe_g1_free(params->g1_alpha);
        }
        if (params->egg_alpha) {
            oabe_gt_free(params->egg_alpha);
        }
        if (params->g1_a) {
            oabe_g1_free(params->g1_a);
        }
        if (params->g2_a) {
            oabe_g2_free(params->g2_a);
        }
        oabe_free(params);
    }
}

static const OABE_ObjectVTable g_params_vtable = {
    .destroy = oabe_params_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_ABEParams* oabe_params_new(OABE_Scheme scheme, OABE_CurveID curve_id, OABE_RNGHandle rng) {
    (void)scheme; /* TODO: Use scheme for scheme-specific parameters */
    (void)rng; /* TODO: Use RNG for parameter generation */

    OABE_ABEParams *params = (OABE_ABEParams *)oabe_malloc(sizeof(OABE_ABEParams));
    if (!params) return NULL;

    memset(params, 0, sizeof(OABE_ABEParams));
    params->base.base.vtable = &g_params_vtable;
    params->base.base.ref_count = 1;
    params->base.key_type = OABE_KEY_TYPE_ABE_PUBLIC;

    /* Create group */
    params->group = oabe_group_new(curve_id);
    if (!params->group) {
        oabe_free(params);
        return NULL;
    }

    /* Create G1 generator */
    params->g1_generator = oabe_g1_new(params->group);
    if (!params->g1_generator) {
        oabe_group_free(params->group);
        oabe_free(params);
        return NULL;
    }
    oabe_g1_set_generator(params->g1_generator);

    /* Create G2 generator */
    params->g2_generator = oabe_g2_new(params->group);
    if (!params->g2_generator) {
        oabe_g1_free(params->g1_generator);
        oabe_group_free(params->group);
        oabe_free(params);
        return NULL;
    }
    oabe_g2_set_generator(params->g2_generator);

    /* Create GT element */
    params->gt_generator = oabe_gt_new(params->group);
    if (!params->gt_generator) {
        oabe_g2_free(params->g2_generator);
        oabe_g1_free(params->g1_generator);
        oabe_group_free(params->group);
        oabe_free(params);
        return NULL;
    }

    /* Compute pairing e(g1, g2) */
    oabe_pairing(params->gt_generator, params->g1_generator, params->g2_generator);

    return params;
}

void oabe_params_free(OABE_ABEParams *params) {
    if (params) {
        OABE_DEREF(params);
    }
}

OABE_ERROR oabe_params_serialize(const OABE_ABEParams *params, OABE_ByteString **result) {
    if (!params || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ByteString *temp = NULL;
    OABE_ERROR rc;

    /* Write header: curve_id, scheme */
    rc = oabe_bytestring_append_byte(*result, (uint8_t)params->base.scheme);
    if (rc != OABE_SUCCESS) goto error;

    rc = oabe_bytestring_append_byte(*result, (uint8_t)oabe_group_get_curve_id(params->group));
    if (rc != OABE_SUCCESS) goto error;

    /* Serialize g1_generator */
    if (params->g1_generator) {
        rc = oabe_g1_serialize(params->g1_generator, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result, oabe_bytestring_get_const_ptr(temp), oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);  /* Length 0 for NULL */
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize g2_generator */
    if (params->g2_generator) {
        rc = oabe_g2_serialize(params->g2_generator, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result, oabe_bytestring_get_const_ptr(temp), oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize gt_generator */
    if (params->gt_generator) {
        rc = oabe_gt_serialize(params->gt_generator, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result, oabe_bytestring_get_const_ptr(temp), oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize g1_alpha (for CP-ABE) */
    if (params->g1_alpha) {
        rc = oabe_g1_serialize(params->g1_alpha, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result, oabe_bytestring_get_const_ptr(temp), oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize egg_alpha (for CP-ABE) */
    if (params->egg_alpha) {
        rc = oabe_gt_serialize(params->egg_alpha, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result, oabe_bytestring_get_const_ptr(temp), oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize g1_a (for Waters '09) */
    if (params->g1_a) {
        rc = oabe_g1_serialize(params->g1_a, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result, oabe_bytestring_get_const_ptr(temp), oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize g2_a (for Waters '09) */
    if (params->g2_a) {
        rc = oabe_g2_serialize(params->g2_a, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result, oabe_bytestring_get_const_ptr(temp), oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize key_data if present */
    if (params->base.key_data) {
        rc = oabe_bytestring_pack_data(*result,
                                   oabe_bytestring_get_const_ptr(params->base.key_data),
                                   oabe_bytestring_get_size(params->base.key_data));
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    return OABE_SUCCESS;

error:
    if (temp) oabe_bytestring_free(temp);
    oabe_bytestring_free(*result);
    *result = NULL;
    return rc;
}

OABE_ERROR oabe_params_deserialize(const OABE_ByteString *input, OABE_ABEParams **params) {
    if (!input || !params) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *params = NULL;
    size_t index = 0;
    OABE_ERROR rc;

    /* Read header */
    uint8_t scheme_byte, curve_byte;
    rc = oabe_bytestring_unpack8(input, &index, &scheme_byte);
    if (rc != OABE_SUCCESS) return rc;

    rc = oabe_bytestring_unpack8(input, &index, &curve_byte);
    if (rc != OABE_SUCCESS) return rc;

    OABE_CurveID curve_id = (OABE_CurveID)curve_byte;

    /* Create group */
    OABE_GroupHandle group = oabe_group_new(curve_id);
    if (!group) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Create params structure */
    OABE_ABEParams *p = (OABE_ABEParams *)oabe_malloc(sizeof(OABE_ABEParams));
    if (!p) {
        oabe_group_free(group);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memset(p, 0, sizeof(OABE_ABEParams));
    p->base.base.vtable = &g_params_vtable;
    p->base.base.ref_count = 1;
    p->base.scheme = (OABE_Scheme)scheme_byte;
    p->group = group;

    /* Read g1_generator */
    uint32_t g1_len;
    rc = oabe_bytestring_unpack32(input, &index, &g1_len);
    if (rc != OABE_SUCCESS) goto error;

    if (g1_len > 0) {
        OABE_ByteString *g1_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, g1_len);
        if (!g1_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        rc = oabe_g1_deserialize(group, g1_data, &p->g1_generator);
        oabe_bytestring_free(g1_data);
        if (rc != OABE_SUCCESS) goto error;
        index += g1_len;
    }

    /* Read g2_generator */
    uint32_t g2_len;
    rc = oabe_bytestring_unpack32(input, &index, &g2_len);
    if (rc != OABE_SUCCESS) goto error;

    if (g2_len > 0) {
        OABE_ByteString *g2_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, g2_len);
        if (!g2_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        rc = oabe_g2_deserialize(group, g2_data, &p->g2_generator);
        oabe_bytestring_free(g2_data);
        if (rc != OABE_SUCCESS) goto error;
        index += g2_len;
    }

    /* Read gt_generator */
    uint32_t gt_len;
    rc = oabe_bytestring_unpack32(input, &index, &gt_len);
    if (rc != OABE_SUCCESS) goto error;

    if (gt_len > 0) {
        OABE_ByteString *gt_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, gt_len);
        if (!gt_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        rc = oabe_gt_deserialize(group, gt_data, &p->gt_generator);
        oabe_bytestring_free(gt_data);
        if (rc != OABE_SUCCESS) goto error;
        index += gt_len;
    }

    /* Read g1_alpha (for CP-ABE) */
    uint32_t g1_alpha_len;
    rc = oabe_bytestring_unpack32(input, &index, &g1_alpha_len);
    if (rc != OABE_SUCCESS) goto error;

    if (g1_alpha_len > 0) {
        OABE_ByteString *g1_alpha_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, g1_alpha_len);
        if (!g1_alpha_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        rc = oabe_g1_deserialize(group, g1_alpha_data, &p->g1_alpha);
        oabe_bytestring_free(g1_alpha_data);
        if (rc != OABE_SUCCESS) goto error;
        index += g1_alpha_len;
    }

    /* Read egg_alpha (for CP-ABE) */
    uint32_t egg_alpha_len;
    rc = oabe_bytestring_unpack32(input, &index, &egg_alpha_len);
    if (rc != OABE_SUCCESS) goto error;

    if (egg_alpha_len > 0) {
        OABE_ByteString *egg_alpha_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, egg_alpha_len);
        if (!egg_alpha_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        rc = oabe_gt_deserialize(group, egg_alpha_data, &p->egg_alpha);
        oabe_bytestring_free(egg_alpha_data);
        if (rc != OABE_SUCCESS) goto error;
        index += egg_alpha_len;
    }

    /* Read g1_a (for Waters '09) */
    uint32_t g1_a_len;
    rc = oabe_bytestring_unpack32(input, &index, &g1_a_len);
    if (rc != OABE_SUCCESS) goto error;

    if (g1_a_len > 0) {
        OABE_ByteString *g1_a_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, g1_a_len);
        if (!g1_a_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        rc = oabe_g1_deserialize(group, g1_a_data, &p->g1_a);
        oabe_bytestring_free(g1_a_data);
        if (rc != OABE_SUCCESS) goto error;
        index += g1_a_len;
    }

    /* Read g2_a (for Waters '09) */
    uint32_t g2_a_len;
    rc = oabe_bytestring_unpack32(input, &index, &g2_a_len);
    if (rc != OABE_SUCCESS) goto error;

    if (g2_a_len > 0) {
        OABE_ByteString *g2_a_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, g2_a_len);
        if (!g2_a_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        rc = oabe_g2_deserialize(group, g2_a_data, &p->g2_a);
        oabe_bytestring_free(g2_a_data);
        if (rc != OABE_SUCCESS) goto error;
        index += g2_a_len;
    }

    /* Read key_data */
    uint32_t key_data_len;
    rc = oabe_bytestring_unpack32(input, &index, &key_data_len);
    if (rc != OABE_SUCCESS) goto error;

    if (key_data_len > 0) {
        p->base.key_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, key_data_len);
        if (!p->base.key_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    *params = p;
    return OABE_SUCCESS;

error:
    oabe_params_free(p);
    return rc;
}

/*============================================================================
 * ABE Secret Key Implementation (Stub)
 *============================================================================*/

static void oabe_secret_key_destroy(void *self) {
    OABE_ABESecretKey *key = (OABE_ABESecretKey *)self;
    if (key) {
        if (key->alpha) {
            oabe_zp_free(key->alpha);
        }
        if (key->beta) {
            oabe_zp_free(key->beta);
        }
        if (key->base.key_data) {
            oabe_bytestring_free(key->base.key_data);
        }
        if (key->base.key_id) {
            oabe_free(key->base.key_id);
        }
        oabe_free(key);
    }
}

static const OABE_ObjectVTable g_secret_key_vtable = {
    .destroy = oabe_secret_key_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_ABESecretKey* oabe_secret_key_new(OABE_ABEParams *params, OABE_RNGHandle rng) {
    if (!params) return NULL;

    OABE_ABESecretKey *key = (OABE_ABESecretKey *)oabe_malloc(sizeof(OABE_ABESecretKey));
    if (!key) return NULL;

    memset(key, 0, sizeof(OABE_ABESecretKey));
    key->base.base.vtable = &g_secret_key_vtable;
    key->base.base.ref_count = 1;
    key->base.key_type = OABE_KEY_TYPE_ABE_SECRET;

    /* Create random alpha and beta */
    key->alpha = oabe_zp_new(params->group);
    if (!key->alpha) {
        oabe_free(key);
        return NULL;
    }

    key->beta = oabe_zp_new(params->group);
    if (!key->beta) {
        oabe_zp_free(key->alpha);
        oabe_free(key);
        return NULL;
    }

    /* Generate random values */
    if (rng) {
        oabe_zp_random(key->alpha, rng);
        oabe_zp_random(key->beta, rng);
    } else {
        /* Use RELIC's internal RNG if no RNG provided */
        oabe_zp_random(key->alpha, NULL);
        oabe_zp_random(key->beta, NULL);
    }

    return key;
}

void oabe_secret_key_free(OABE_ABESecretKey *key) {
    if (key) {
        OABE_DEREF(key);
    }
}

OABE_ERROR oabe_secret_key_serialize(const OABE_ABESecretKey *key, OABE_ByteString **result) {
    if (!key || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ByteString *temp = NULL;
    OABE_ERROR rc;

    /* Write header */
    rc = oabe_bytestring_append_byte(*result, (uint8_t)key->base.key_type);
    if (rc != OABE_SUCCESS) goto error;

    rc = oabe_bytestring_append_byte(*result, (uint8_t)key->base.scheme);
    if (rc != OABE_SUCCESS) goto error;

    /* Serialize alpha */
    if (key->alpha) {
        rc = oabe_zp_serialize(key->alpha, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result,
                                   oabe_bytestring_get_const_ptr(temp),
                                   oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize beta */
    if (key->beta) {
        rc = oabe_zp_serialize(key->beta, &temp);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_pack_data(*result,
                                   oabe_bytestring_get_const_ptr(temp),
                                   oabe_bytestring_get_size(temp));
        oabe_bytestring_free(temp);
        temp = NULL;
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize key_id */
    if (key->base.key_id) {
        size_t id_len = strlen(key->base.key_id);
        rc = oabe_bytestring_pack32(*result, (uint32_t)id_len);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_append_data(*result, (const uint8_t *)key->base.key_id, id_len);
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Serialize key_data */
    if (key->base.key_data) {
        rc = oabe_bytestring_pack_data(*result,
                                   oabe_bytestring_get_const_ptr(key->base.key_data),
                                   oabe_bytestring_get_size(key->base.key_data));
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    return OABE_SUCCESS;

error:
    if (temp) oabe_bytestring_free(temp);
    oabe_bytestring_free(*result);
    *result = NULL;
    return rc;
}

OABE_ERROR oabe_secret_key_deserialize(const OABE_ByteString *input, OABE_ABESecretKey **key) {
    if (!input || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *key = NULL;
    size_t index = 0;
    OABE_ERROR rc;

    /* Read header */
    uint8_t key_type_byte, scheme_byte;
    rc = oabe_bytestring_unpack8(input, &index, &key_type_byte);
    if (rc != OABE_SUCCESS) return rc;

    rc = oabe_bytestring_unpack8(input, &index, &scheme_byte);
    if (rc != OABE_SUCCESS) return rc;

    /* Create key structure */
    OABE_ABESecretKey *k = (OABE_ABESecretKey *)oabe_malloc(sizeof(OABE_ABESecretKey));
    if (!k) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memset(k, 0, sizeof(OABE_ABESecretKey));
    k->base.base.vtable = &g_secret_key_vtable;
    k->base.base.ref_count = 1;
    k->base.key_type = (OABE_KeyType)key_type_byte;
    k->base.scheme = (OABE_Scheme)scheme_byte;

    /* Read alpha */
    uint32_t alpha_len;
    rc = oabe_bytestring_unpack32(input, &index, &alpha_len);
    if (rc != OABE_SUCCESS) goto error;

    if (alpha_len > 0) {
        OABE_ByteString *alpha_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, alpha_len);
        if (!alpha_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        /* Deserialize ZP - need group handle, which we don't have here */
        /* For now, create a placeholder - this should be fixed */
        index += alpha_len;
        oabe_bytestring_free(alpha_data);
    }

    /* Read beta */
    uint32_t beta_len;
    rc = oabe_bytestring_unpack32(input, &index, &beta_len);
    if (rc != OABE_SUCCESS) goto error;

    if (beta_len > 0) {
        OABE_ByteString *beta_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, beta_len);
        if (!beta_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        index += beta_len;
        oabe_bytestring_free(beta_data);
    }

    /* Read key_id */
    uint32_t id_len;
    rc = oabe_bytestring_unpack32(input, &index, &id_len);
    if (rc != OABE_SUCCESS) goto error;

    if (id_len > 0) {
        k->base.key_id = (char *)oabe_malloc(id_len + 1);
        if (!k->base.key_id) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        memcpy(k->base.key_id, oabe_bytestring_get_const_ptr(input) + index, id_len);
        k->base.key_id[id_len] = '\0';
        index += id_len;
    }

    /* Read key_data */
    uint32_t key_data_len;
    rc = oabe_bytestring_unpack32(input, &index, &key_data_len);
    if (rc != OABE_SUCCESS) goto error;

    if (key_data_len > 0) {
        k->base.key_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, key_data_len);
        if (!k->base.key_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    *key = k;
    return OABE_SUCCESS;

error:
    if (k->base.key_id) oabe_free(k->base.key_id);
    oabe_free(k);
    return rc;
}

/*============================================================================
 * ABE User Key Implementation
 *============================================================================*/

static void oabe_user_key_destroy(void *self) {
    OABE_ABEUserKey *key = (OABE_ABEUserKey *)self;
    if (key) {
        if (key->base.key_id) {
            oabe_free(key->base.key_id);
        }
        if (key->base.key_data) {
            oabe_bytestring_free(key->base.key_data);
        }
        if (key->attributes) {
            oabe_strvec_free(key->attributes);
        }
        if (key->policy) {
            oabe_strvec_free(key->policy);
        }
        if (key->key_elements) {
            oabe_vector_free(key->key_elements);
        }
        oabe_free(key);
    }
}

static const OABE_ObjectVTable g_user_key_vtable = {
    .destroy = oabe_user_key_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_ABEUserKey* oabe_user_key_new(const char *key_id, OABE_ABEParams *params) {
    if (!key_id || !params) {
        return NULL;
    }

    OABE_ABEUserKey *key = (OABE_ABEUserKey *)oabe_malloc(sizeof(OABE_ABEUserKey));
    if (!key) return NULL;

    memset(key, 0, sizeof(OABE_ABEUserKey));
    key->base.base.vtable = &g_user_key_vtable;
    key->base.base.ref_count = 1;
    key->base.key_type = OABE_KEY_TYPE_ABE_USER;
    key->base.scheme = params->base.scheme;

    key->base.key_id = oabe_strdup(key_id);
    if (!key->base.key_id) {
        oabe_free(key);
        return NULL;
    }

    return key;
}

void oabe_user_key_free(OABE_ABEUserKey *key) {
    if (key) {
        oabe_user_key_destroy(key);
    }
}

OABE_ERROR oabe_user_key_serialize(const OABE_ABEUserKey *key, OABE_ByteString **result) {
    if (!key || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ByteString *temp = NULL;
    OABE_ERROR rc;

    /* Write header */
    rc = oabe_bytestring_append_byte(*result, (uint8_t)key->base.key_type);
    if (rc != OABE_SUCCESS) goto error;

    rc = oabe_bytestring_append_byte(*result, (uint8_t)key->base.scheme);
    if (rc != OABE_SUCCESS) goto error;

    /* Write key_id */
    if (key->base.key_id) {
        size_t id_len = strlen(key->base.key_id);
        rc = oabe_bytestring_pack32(*result, (uint32_t)id_len);
        if (rc != OABE_SUCCESS) goto error;
        rc = oabe_bytestring_append_data(*result, (const uint8_t *)key->base.key_id, id_len);
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Write attributes count and strings (for CP-ABE) */
    if (key->attributes) {
        uint32_t attr_count = (uint32_t)key->attributes->size;
        rc = oabe_bytestring_pack32(*result, attr_count);
        if (rc != OABE_SUCCESS) goto error;

        for (uint32_t i = 0; i < attr_count; i++) {
            const char *attr = oabe_strvec_get(key->attributes, i);
            if (attr) {
                size_t attr_len = strlen(attr);
                rc = oabe_bytestring_pack32(*result, (uint32_t)attr_len);
                if (rc != OABE_SUCCESS) goto error;
                rc = oabe_bytestring_append_data(*result, (const uint8_t *)attr, attr_len);
                if (rc != OABE_SUCCESS) goto error;
            } else {
                rc = oabe_bytestring_pack32(*result, 0);
                if (rc != OABE_SUCCESS) goto error;
            }
        }
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Write policy string (for KP-ABE) - policy is stored as a StringVector with one element */
    if (key->policy && key->policy->size > 0) {
        const char *policy_str = oabe_strvec_get(key->policy, 0);
        if (policy_str) {
            size_t policy_len = strlen(policy_str);
            rc = oabe_bytestring_pack32(*result, (uint32_t)policy_len);
            if (rc != OABE_SUCCESS) goto error;
            rc = oabe_bytestring_append_data(*result, (const uint8_t *)policy_str, policy_len);
            if (rc != OABE_SUCCESS) goto error;
        } else {
            rc = oabe_bytestring_pack32(*result, 0);
            if (rc != OABE_SUCCESS) goto error;
        }
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Write key_data (contains serialized key elements) */
    if (key->base.key_data) {
        rc = oabe_bytestring_pack_data(*result,
                                   oabe_bytestring_get_const_ptr(key->base.key_data),
                                   oabe_bytestring_get_size(key->base.key_data));
        if (rc != OABE_SUCCESS) goto error;
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
        if (rc != OABE_SUCCESS) goto error;
    }

    return OABE_SUCCESS;

error:
    if (temp) oabe_bytestring_free(temp);
    oabe_bytestring_free(*result);
    *result = NULL;
    return rc;
}

OABE_ERROR oabe_user_key_deserialize(const OABE_ByteString *input, OABE_ABEUserKey **key) {
    if (!input || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *key = NULL;
    size_t index = 0;
    OABE_ERROR rc;

    /* Read header */
    uint8_t key_type_byte, scheme_byte;
    rc = oabe_bytestring_unpack8(input, &index, &key_type_byte);
    if (rc != OABE_SUCCESS) return rc;

    rc = oabe_bytestring_unpack8(input, &index, &scheme_byte);
    if (rc != OABE_SUCCESS) return rc;

    /* Create key structure (without params - we create a minimal one) */
    OABE_ABEUserKey *k = (OABE_ABEUserKey *)oabe_malloc(sizeof(OABE_ABEUserKey));
    if (!k) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memset(k, 0, sizeof(OABE_ABEUserKey));
    k->base.base.vtable = &g_user_key_vtable;
    k->base.base.ref_count = 1;
    k->base.key_type = (OABE_KeyType)key_type_byte;
    k->base.scheme = (OABE_Scheme)scheme_byte;

    /* Read key_id */
    uint32_t id_len;
    rc = oabe_bytestring_unpack32(input, &index, &id_len);
    if (rc != OABE_SUCCESS) goto error;

    if (id_len > 0) {
        k->base.key_id = (char *)oabe_malloc(id_len + 1);
        if (!k->base.key_id) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        memcpy(k->base.key_id, oabe_bytestring_get_const_ptr(input) + index, id_len);
        k->base.key_id[id_len] = '\0';
        index += id_len;
    }

    /* Read attributes */
    uint32_t attr_count;
    rc = oabe_bytestring_unpack32(input, &index, &attr_count);
    if (rc != OABE_SUCCESS) goto error;

    if (attr_count > 0) {
        k->attributes = oabe_strvec_new(attr_count);
        if (!k->attributes) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }

        for (uint32_t i = 0; i < attr_count; i++) {
            uint32_t attr_len;
            rc = oabe_bytestring_unpack32(input, &index, &attr_len);
            if (rc != OABE_SUCCESS) goto error;

            if (attr_len > 0) {
                char *attr = (char *)oabe_malloc(attr_len + 1);
                if (!attr) {
                    rc = OABE_ERROR_OUT_OF_MEMORY;
                    goto error;
                }
                memcpy(attr, oabe_bytestring_get_const_ptr(input) + index, attr_len);
                attr[attr_len] = '\0';
                index += attr_len;

                rc = oabe_strvec_append(k->attributes, attr);
                oabe_free(attr);
                if (rc != OABE_SUCCESS) goto error;
            }
        }
    }

    /* Read policy */
    uint32_t policy_len;
    rc = oabe_bytestring_unpack32(input, &index, &policy_len);
    if (rc != OABE_SUCCESS) goto error;

    if (policy_len > 0) {
        /* Policy is stored as a StringVector with one element */
        k->policy = oabe_strvec_new(1);
        if (!k->policy) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }

        char *policy_str = (char *)oabe_malloc(policy_len + 1);
        if (!policy_str) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        memcpy(policy_str, oabe_bytestring_get_const_ptr(input) + index, policy_len);
        policy_str[policy_len] = '\0';
        index += policy_len;

        rc = oabe_strvec_append(k->policy, policy_str);
        oabe_free(policy_str);
        if (rc != OABE_SUCCESS) goto error;
    }

    /* Read key_data */
    uint32_t key_data_len;
    rc = oabe_bytestring_unpack32(input, &index, &key_data_len);
    if (rc != OABE_SUCCESS) goto error;

    if (key_data_len > 0) {
        k->base.key_data = oabe_bytestring_new_from_data(
            oabe_bytestring_get_const_ptr(input) + index, key_data_len);
        if (!k->base.key_data) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    *key = k;
    return OABE_SUCCESS;

error:
    if (k->base.key_id) oabe_free(k->base.key_id);
    if (k->attributes) oabe_strvec_free(k->attributes);
    if (k->policy) oabe_strvec_free(k->policy);
    oabe_free(k);
    return rc;
}