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
/// \file   oabe_ciphertext.c
///
/// \brief  Ciphertext structures implementation for OpenABE C.
///

#include <string.h>
#include "openabe/oabe_ciphertext.h"
#include "openabe/oabe_serialize.h"
#include "openabe/oabe_memory.h"

/*============================================================================
 * AES-GCM Ciphertext Implementation
 *============================================================================*/

static void oabe_aes_ct_destroy(void *self) {
    OABE_AES_Ciphertext *ct = (OABE_AES_Ciphertext *)self;
    if (ct) {
        oabe_zeroize(ct->iv, sizeof(ct->iv));
        oabe_zeroize(ct->tag, sizeof(ct->tag));
        if (ct->ciphertext) {
            oabe_bytestring_free(ct->ciphertext);
        }
        oabe_free(ct);
    }
}

static const OABE_ObjectVTable g_aes_ct_vtable = {
    .destroy = oabe_aes_ct_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_AES_Ciphertext* oabe_aes_ct_new(void) {
    OABE_AES_Ciphertext *ct = (OABE_AES_Ciphertext *)oabe_malloc(sizeof(OABE_AES_Ciphertext));
    if (!ct) return NULL;

    memset(ct, 0, sizeof(OABE_AES_Ciphertext));
    ct->base.vtable = &g_aes_ct_vtable;
    ct->base.ref_count = 1;

    return ct;
}

void oabe_aes_ct_free(OABE_AES_Ciphertext *ct) {
    if (ct) {
        OABE_DEREF(ct);
    }
}

OABE_ERROR oabe_aes_ct_serialize(const OABE_AES_Ciphertext *ct, OABE_ByteString **result) {
    if (!ct || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Write IV length and IV */
    OABE_ERROR rc = oabe_bytestring_pack8(*result, (uint8_t)ct->iv_len);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    rc = oabe_bytestring_append_data(*result, ct->iv, ct->iv_len);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    /* Write tag */
    rc = oabe_bytestring_append_data(*result, ct->tag, sizeof(ct->tag));
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    /* Write ciphertext */
    if (ct->ciphertext && oabe_bytestring_get_size(ct->ciphertext) > 0) {
        rc = oabe_bytestring_pack_bytestring(*result, ct->ciphertext);
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
    }

    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
    }

    return rc;
}

OABE_ERROR oabe_aes_ct_deserialize(const OABE_ByteString *input, OABE_AES_Ciphertext **ct) {
    if (!input || !ct) {
        return OABE_ERROR_INVALID_INPUT;
    }

    size_t index = 0;

    *ct = oabe_aes_ct_new();
    if (!*ct) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Read IV length */
    uint8_t iv_len;
    OABE_ERROR rc = oabe_bytestring_unpack8(input, &index, &iv_len);
    if (rc != OABE_SUCCESS) {
        oabe_aes_ct_free(*ct);
        *ct = NULL;
        return rc;
    }
    (*ct)->iv_len = iv_len;

    /* Read IV */
    if (index + iv_len > oabe_bytestring_get_size(input)) {
        oabe_aes_ct_free(*ct);
        *ct = NULL;
        return OABE_ERROR_DESERIALIZATION_FAILED;
    }
    memcpy((*ct)->iv, oabe_bytestring_get_const_ptr(input) + index, iv_len);
    index += iv_len;

    /* Read tag */
    if (index + sizeof((*ct)->tag) > oabe_bytestring_get_size(input)) {
        oabe_aes_ct_free(*ct);
        *ct = NULL;
        return OABE_ERROR_DESERIALIZATION_FAILED;
    }
    memcpy((*ct)->tag, oabe_bytestring_get_const_ptr(input) + index, sizeof((*ct)->tag));
    index += sizeof((*ct)->tag);

    /* Read ciphertext */
    OABE_ByteString *ct_bs = NULL;
    rc = oabe_bytestring_unpack(input, &index, &ct_bs);
    if (rc != OABE_SUCCESS) {
        oabe_aes_ct_free(*ct);
        *ct = NULL;
        return rc;
    }
    (*ct)->ciphertext = ct_bs;

    return OABE_SUCCESS;
}

/*============================================================================
 * CP-ABE Ciphertext Implementation
 *============================================================================*/

static void oabe_cp_ct_destroy(void *self) {
    OABE_CP_Ciphertext *ct = (OABE_CP_Ciphertext *)self;
    if (ct) {
        if (ct->policy_string) {
            oabe_free(ct->policy_string);
        }
        if (ct->policy) {
            oabe_policy_tree_free(ct->policy);
        }
        if (ct->ct) {
            oabe_gt_free(ct->ct);
        }
        if (ct->c0) {
            oabe_g1_free(ct->c0);
        }
        if (ct->components) {
            for (size_t i = 0; i < ct->num_components; i++) {
                if (ct->components[i].attribute) {
                    oabe_free(ct->components[i].attribute);
                }
                if (ct->components[i].c1) {
                    oabe_g1_free(ct->components[i].c1);
                }
                if (ct->components[i].c2) {
                    oabe_g2_free(ct->components[i].c2);
                }
            }
            oabe_free(ct->components);
        }
        if (ct->encrypted_key) {
            oabe_bytestring_free(ct->encrypted_key);
        }
        if (ct->encrypted_msg) {
            oabe_bytestring_free(ct->encrypted_msg);
        }
        oabe_free(ct);
    }
}

static const OABE_ObjectVTable g_cp_ct_vtable = {
    .destroy = oabe_cp_ct_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_CP_Ciphertext* oabe_cp_ct_new(OABE_Scheme scheme) {
    OABE_CP_Ciphertext *ct = (OABE_CP_Ciphertext *)oabe_malloc(sizeof(OABE_CP_Ciphertext));
    if (!ct) return NULL;

    memset(ct, 0, sizeof(OABE_CP_Ciphertext));
    ct->base.vtable = &g_cp_ct_vtable;
    ct->base.ref_count = 1;
    ct->scheme = scheme;

    return ct;
}

void oabe_cp_ct_free(OABE_CP_Ciphertext *ct) {
    if (ct) {
        OABE_DEREF(ct);
    }
}

OABE_ERROR oabe_cp_ct_add_component(OABE_CP_Ciphertext *ct, const char *attribute,
                                     OABE_G1 *c1, OABE_G2 *c2) {
    if (!ct || !attribute || !c1) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Grow components array */
    size_t new_count = ct->num_components + 1;
    OABE_CP_CiphertextComponent *new_components = (OABE_CP_CiphertextComponent *)
        oabe_realloc(ct->components, new_count * sizeof(OABE_CP_CiphertextComponent));

    if (!new_components) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    ct->components = new_components;
    ct->components[ct->num_components].attribute = oabe_strdup(attribute);
    ct->components[ct->num_components].c1 = c1;
    ct->components[ct->num_components].c2 = c2;
    ct->num_components = new_count;

    if (!ct->components[ct->num_components - 1].attribute) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_cp_ct_serialize(const OABE_CP_Ciphertext *ct, OABE_ByteString **result) {
    if (!ct || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Write scheme type */
    OABE_ERROR rc = oabe_bytestring_pack8(*result, (uint8_t)ct->scheme);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Write policy string */
    if (ct->policy_string) {
        size_t len = strlen(ct->policy_string);
        rc = oabe_bytestring_pack32(*result, (uint32_t)len);
        if (rc == OABE_SUCCESS) {
            rc = oabe_bytestring_append_data(*result, (const uint8_t *)ct->policy_string, len);
        }
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
    }
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Write C0 */
    if (ct->c0) {
        OABE_ByteString *c0_bs = NULL;
        rc = oabe_g1_serialize(ct->c0, &c0_bs);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
        rc = oabe_bytestring_pack_bytestring(*result, c0_bs);
        oabe_bytestring_free(c0_bs);
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
    }
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Write CT */
    if (ct->ct) {
        OABE_ByteString *ct_bs = NULL;
        rc = oabe_gt_serialize(ct->ct, &ct_bs);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
        rc = oabe_bytestring_pack_bytestring(*result, ct_bs);
        oabe_bytestring_free(ct_bs);
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
    }
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Write number of components */
    rc = oabe_bytestring_pack32(*result, (uint32_t)ct->num_components);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Write each component */
    for (size_t i = 0; i < ct->num_components; i++) {
        /* Write attribute */
        size_t attr_len = strlen(ct->components[i].attribute);
        rc = oabe_bytestring_pack32(*result, (uint32_t)attr_len);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
        rc = oabe_bytestring_append_data(*result,
            (const uint8_t *)ct->components[i].attribute, attr_len);
        if (rc != OABE_SUCCESS) {
            goto error;
        }

        /* Write C1 */
        if (ct->components[i].c1) {
            OABE_ByteString *c1_bs = NULL;
            rc = oabe_g1_serialize(ct->components[i].c1, &c1_bs);
            if (rc != OABE_SUCCESS) {
                goto error;
            }
            rc = oabe_bytestring_pack_bytestring(*result, c1_bs);
            oabe_bytestring_free(c1_bs);
        } else {
            rc = oabe_bytestring_pack32(*result, 0);
        }
        if (rc != OABE_SUCCESS) {
            goto error;
        }

        /* Write C2 if present */
        uint8_t has_c2 = ct->components[i].c2 ? 1 : 0;
        rc = oabe_bytestring_pack8(*result, has_c2);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
        if (has_c2) {
            OABE_ByteString *c2_bs = NULL;
            rc = oabe_g2_serialize(ct->components[i].c2, &c2_bs);
            if (rc != OABE_SUCCESS) {
                goto error;
            }
            rc = oabe_bytestring_pack_bytestring(*result, c2_bs);
            oabe_bytestring_free(c2_bs);
            if (rc != OABE_SUCCESS) {
                goto error;
            }
        }
    }

    /* Write encrypted key and message */
    if (ct->encrypted_key) {
        rc = oabe_bytestring_pack_bytestring(*result, ct->encrypted_key);
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
    }
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    if (ct->encrypted_msg) {
        rc = oabe_bytestring_pack_bytestring(*result, ct->encrypted_msg);
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
    }
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    return OABE_SUCCESS;

error:
    oabe_bytestring_free(*result);
    *result = NULL;
    return rc;
}

OABE_ERROR oabe_cp_ct_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                   OABE_CP_Ciphertext **ct) {
    if (!group || !input || !ct) {
        return OABE_ERROR_INVALID_INPUT;
    }

    size_t index = 0;

    *ct = oabe_cp_ct_new(OABE_SCHEME_CP_WATERS);
    if (!*ct) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Read scheme type */
    uint8_t scheme;
    OABE_ERROR rc = oabe_bytestring_unpack8(input, &index, &scheme);
    if (rc != OABE_SUCCESS) {
        goto error;
    }
    (*ct)->scheme = (OABE_Scheme)scheme;

    /* Read policy string */
    uint32_t policy_len;
    rc = oabe_bytestring_unpack32(input, &index, &policy_len);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    if (policy_len > 0) {
        (*ct)->policy_string = (char *)oabe_malloc(policy_len + 1);
        if (!(*ct)->policy_string) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        memcpy((*ct)->policy_string, oabe_bytestring_get_const_ptr(input) + index, policy_len);
        (*ct)->policy_string[policy_len] = '\0';
        index += policy_len;

        /* Parse policy */
        oabe_policy_parse((*ct)->policy_string, &(*ct)->policy);
    }

    /* Read C0 */
    OABE_ByteString *c0_bs = NULL;
    rc = oabe_bytestring_unpack(input, &index, &c0_bs);
    if (rc != OABE_SUCCESS) {
        goto error;
    }
    if (oabe_bytestring_get_size(c0_bs) > 0) {
        rc = oabe_g1_deserialize(group, c0_bs, &(*ct)->c0);
    }
    oabe_bytestring_free(c0_bs);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Read CT */
    OABE_ByteString *ct_bs = NULL;
    rc = oabe_bytestring_unpack(input, &index, &ct_bs);
    if (rc != OABE_SUCCESS) {
        goto error;
    }
    if (oabe_bytestring_get_size(ct_bs) > 0) {
        rc = oabe_gt_deserialize(group, ct_bs, &(*ct)->ct);
    }
    oabe_bytestring_free(ct_bs);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Read number of components */
    uint32_t num_components;
    rc = oabe_bytestring_unpack32(input, &index, &num_components);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Allocate components */
    (*ct)->components = (OABE_CP_CiphertextComponent *)
        oabe_calloc(num_components, sizeof(OABE_CP_CiphertextComponent));
    if (!(*ct)->components && num_components > 0) {
        rc = OABE_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    (*ct)->num_components = num_components;

    /* Read each component */
    for (size_t i = 0; i < num_components; i++) {
        /* Read attribute */
        uint32_t attr_len;
        rc = oabe_bytestring_unpack32(input, &index, &attr_len);
        if (rc != OABE_SUCCESS) {
            goto error;
        }

        (*ct)->components[i].attribute = (char *)oabe_malloc(attr_len + 1);
        if (!(*ct)->components[i].attribute) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        memcpy((*ct)->components[i].attribute,
               oabe_bytestring_get_const_ptr(input) + index, attr_len);
        (*ct)->components[i].attribute[attr_len] = '\0';
        index += attr_len;

        /* Read C1 */
        OABE_ByteString *c1_bs = NULL;
        rc = oabe_bytestring_unpack(input, &index, &c1_bs);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
        if (oabe_bytestring_get_size(c1_bs) > 0) {
            rc = oabe_g1_deserialize(group, c1_bs, &(*ct)->components[i].c1);
        }
        oabe_bytestring_free(c1_bs);
        if (rc != OABE_SUCCESS) {
            goto error;
        }

        /* Read C2 if present */
        uint8_t has_c2;
        rc = oabe_bytestring_unpack8(input, &index, &has_c2);
        if (rc != OABE_SUCCESS) {
            goto error;
        }

        if (has_c2) {
            OABE_ByteString *c2_bs = NULL;
            rc = oabe_bytestring_unpack(input, &index, &c2_bs);
            if (rc != OABE_SUCCESS) {
                goto error;
            }
            rc = oabe_g2_deserialize(group, c2_bs, &(*ct)->components[i].c2);
            oabe_bytestring_free(c2_bs);
            if (rc != OABE_SUCCESS) {
                goto error;
            }
        }
    }

    /* Read encrypted key and message */
    rc = oabe_bytestring_unpack(input, &index, &(*ct)->encrypted_key);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    rc = oabe_bytestring_unpack(input, &index, &(*ct)->encrypted_msg);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    return OABE_SUCCESS;

error:
    oabe_cp_ct_free(*ct);
    *ct = NULL;
    return rc;
}

/*============================================================================
 * KP-ABE Ciphertext Implementation
 *============================================================================*/

static void oabe_kp_ct_destroy(void *self) {
    OABE_KP_Ciphertext *ct = (OABE_KP_Ciphertext *)self;
    if (ct) {
        if (ct->attributes) {
            oabe_strvec_free(ct->attributes);
        }
        if (ct->attr_names) {
            for (size_t i = 0; i < ct->num_attributes; i++) {
                oabe_free(ct->attr_names[i]);
            }
            oabe_free(ct->attr_names);
        }
        if (ct->attr_elements) {
            for (size_t i = 0; i < ct->num_attributes; i++) {
                if (ct->attr_elements[i]) {
                    oabe_g1_free(ct->attr_elements[i]);
                }
            }
            oabe_free(ct->attr_elements);
        }
        if (ct->encrypted_key) {
            oabe_bytestring_free(ct->encrypted_key);
        }
        if (ct->encrypted_msg) {
            oabe_bytestring_free(ct->encrypted_msg);
        }
        oabe_free(ct);
    }
}

static const OABE_ObjectVTable g_kp_ct_vtable = {
    .destroy = oabe_kp_ct_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_KP_Ciphertext* oabe_kp_ct_new(OABE_Scheme scheme) {
    OABE_KP_Ciphertext *ct = (OABE_KP_Ciphertext *)oabe_malloc(sizeof(OABE_KP_Ciphertext));
    if (!ct) return NULL;

    memset(ct, 0, sizeof(OABE_KP_Ciphertext));
    ct->base.vtable = &g_kp_ct_vtable;
    ct->base.ref_count = 1;
    ct->scheme = scheme;

    return ct;
}

void oabe_kp_ct_free(OABE_KP_Ciphertext *ct) {
    if (ct) {
        OABE_DEREF(ct);
    }
}

OABE_ERROR oabe_kp_ct_add_attribute(OABE_KP_Ciphertext *ct, const char *attribute, OABE_G1 *element) {
    if (!ct || !attribute || !element) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Grow arrays */
    size_t new_count = ct->num_attributes + 1;

    char **new_names = (char **)oabe_realloc(ct->attr_names, new_count * sizeof(char *));
    if (!new_names) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    ct->attr_names = new_names;

    OABE_G1 **new_elements = (OABE_G1 **)oabe_realloc(ct->attr_elements, new_count * sizeof(OABE_G1 *));
    if (!new_elements) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    ct->attr_elements = new_elements;

    ct->attr_names[ct->num_attributes] = oabe_strdup(attribute);
    if (!ct->attr_names[ct->num_attributes]) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    ct->attr_elements[ct->num_attributes] = element;
    ct->num_attributes = new_count;

    /* Also update the attributes StringVector for policy checking */
    if (!ct->attributes) {
        ct->attributes = oabe_strvec_new(8);
        if (!ct->attributes) {
            return OABE_ERROR_OUT_OF_MEMORY;
        }
    }
    OABE_ERROR rc = oabe_strvec_append(ct->attributes, attribute);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_kp_ct_serialize(const OABE_KP_Ciphertext *ct, OABE_ByteString **result) {
    if (!ct || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Write scheme type */
    OABE_ERROR rc = oabe_bytestring_pack8(*result, (uint8_t)ct->scheme);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Write number of attributes */
    rc = oabe_bytestring_pack32(*result, (uint32_t)ct->num_attributes);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Write each attribute and element */
    for (size_t i = 0; i < ct->num_attributes; i++) {
        /* Write attribute name */
        size_t attr_len = strlen(ct->attr_names[i]);
        rc = oabe_bytestring_pack32(*result, (uint32_t)attr_len);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
        rc = oabe_bytestring_append_data(*result,
            (const uint8_t *)ct->attr_names[i], attr_len);
        if (rc != OABE_SUCCESS) {
            goto error;
        }

        /* Write element */
        OABE_ByteString *elem_bs = NULL;
        rc = oabe_g1_serialize(ct->attr_elements[i], &elem_bs);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
        rc = oabe_bytestring_pack_bytestring(*result, elem_bs);
        oabe_bytestring_free(elem_bs);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
    }

    /* Write encrypted key and message */
    if (ct->encrypted_key) {
        rc = oabe_bytestring_pack_bytestring(*result, ct->encrypted_key);
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
    }
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    if (ct->encrypted_msg) {
        rc = oabe_bytestring_pack_bytestring(*result, ct->encrypted_msg);
    } else {
        rc = oabe_bytestring_pack32(*result, 0);
    }
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    return OABE_SUCCESS;

error:
    oabe_bytestring_free(*result);
    *result = NULL;
    return rc;
}

OABE_ERROR oabe_kp_ct_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                   OABE_KP_Ciphertext **ct) {
    if (!group || !input || !ct) {
        return OABE_ERROR_INVALID_INPUT;
    }

    size_t index = 0;

    *ct = oabe_kp_ct_new(OABE_SCHEME_KP_GPSW);
    if (!*ct) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Read scheme type */
    uint8_t scheme;
    OABE_ERROR rc = oabe_bytestring_unpack8(input, &index, &scheme);
    if (rc != OABE_SUCCESS) {
        goto error;
    }
    (*ct)->scheme = (OABE_Scheme)scheme;

    /* Read number of attributes */
    uint32_t num_attrs;
    rc = oabe_bytestring_unpack32(input, &index, &num_attrs);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    /* Allocate arrays */
    if (num_attrs > 0) {
        (*ct)->attr_names = (char **)oabe_calloc(num_attrs, sizeof(char *));
        (*ct)->attr_elements = (OABE_G1 **)oabe_calloc(num_attrs, sizeof(OABE_G1 *));
        if (!(*ct)->attr_names || !(*ct)->attr_elements) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }
    (*ct)->num_attributes = num_attrs;

    /* Read each attribute and element */
    /* First create the attributes StringVector */
    if (num_attrs > 0) {
        (*ct)->attributes = oabe_strvec_new(num_attrs);
        if (!(*ct)->attributes) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }

    for (size_t i = 0; i < num_attrs; i++) {
        /* Read attribute name */
        uint32_t attr_len;
        rc = oabe_bytestring_unpack32(input, &index, &attr_len);
        if (rc != OABE_SUCCESS) {
            goto error;
        }

        (*ct)->attr_names[i] = (char *)oabe_malloc(attr_len + 1);
        if (!(*ct)->attr_names[i]) {
            rc = OABE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        memcpy((*ct)->attr_names[i], oabe_bytestring_get_const_ptr(input) + index, attr_len);
        (*ct)->attr_names[i][attr_len] = '\0';
        index += attr_len;

        /* Also add to attributes StringVector */
        rc = oabe_strvec_append((*ct)->attributes, (*ct)->attr_names[i]);
        if (rc != OABE_SUCCESS) {
            goto error;
        }

        /* Read element */
        OABE_ByteString *elem_bs = NULL;
        rc = oabe_bytestring_unpack(input, &index, &elem_bs);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
        rc = oabe_g1_deserialize(group, elem_bs, &(*ct)->attr_elements[i]);
        oabe_bytestring_free(elem_bs);
        if (rc != OABE_SUCCESS) {
            goto error;
        }
    }

    /* Read encrypted key and message */
    rc = oabe_bytestring_unpack(input, &index, &(*ct)->encrypted_key);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    rc = oabe_bytestring_unpack(input, &index, &(*ct)->encrypted_msg);
    if (rc != OABE_SUCCESS) {
        goto error;
    }

    return OABE_SUCCESS;

error:
    oabe_kp_ct_free(*ct);
    *ct = NULL;
    return rc;
}

/*============================================================================
 * Generic Ciphertext Implementation
 *============================================================================*/

static void oabe_ct_destroy(void *self) {
    OABE_Ciphertext *ct = (OABE_Ciphertext *)self;
    if (ct) {
        switch (ct->type) {
            case OABE_CT_TYPE_AES_GCM:
                if (ct->data.aes) {
                    oabe_aes_ct_free(ct->data.aes);
                }
                break;
            case OABE_CT_TYPE_CP_ABE:
                if (ct->data.cp) {
                    oabe_cp_ct_free(ct->data.cp);
                }
                break;
            case OABE_CT_TYPE_KP_ABE:
                if (ct->data.kp) {
                    oabe_kp_ct_free(ct->data.kp);
                }
                break;
            default:
                break;
        }
        oabe_free(ct);
    }
}

static const OABE_ObjectVTable g_ct_vtable = {
    .destroy = oabe_ct_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_Ciphertext* oabe_ct_new(OABE_CiphertextType type) {
    OABE_Ciphertext *ct = (OABE_Ciphertext *)oabe_malloc(sizeof(OABE_Ciphertext));
    if (!ct) return NULL;

    memset(ct, 0, sizeof(OABE_Ciphertext));
    ct->base.vtable = &g_ct_vtable;
    ct->base.ref_count = 1;
    ct->type = type;

    switch (type) {
        case OABE_CT_TYPE_AES_GCM:
            ct->data.aes = oabe_aes_ct_new();
            break;
        case OABE_CT_TYPE_CP_ABE:
            ct->data.cp = oabe_cp_ct_new(OABE_SCHEME_CP_WATERS);
            break;
        case OABE_CT_TYPE_KP_ABE:
            ct->data.kp = oabe_kp_ct_new(OABE_SCHEME_KP_GPSW);
            break;
        default:
            break;
    }

    return ct;
}

void oabe_ct_free(OABE_Ciphertext *ct) {
    if (ct) {
        OABE_DEREF(ct);
    }
}

OABE_ERROR oabe_ct_serialize(const OABE_Ciphertext *ct, OABE_ByteString **result) {
    if (!ct || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    switch (ct->type) {
        case OABE_CT_TYPE_AES_GCM:
            return oabe_aes_ct_serialize(ct->data.aes, result);
        case OABE_CT_TYPE_CP_ABE:
            return oabe_cp_ct_serialize(ct->data.cp, result);
        case OABE_CT_TYPE_KP_ABE:
            return oabe_kp_ct_serialize(ct->data.kp, result);
        default:
            return OABE_ERROR_INVALID_CIPHERTEXT;
    }
}

OABE_ERROR oabe_ct_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                 OABE_Ciphertext **ct) {
    if (!input || !ct) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Peek at first byte to determine type */
    uint8_t first_byte = oabe_bytestring_at(input, 0);

    /* This is simplified - in production would read proper header */
    OABE_CiphertextType type;
    if (first_byte == OABE_SCHEME_AES_GCM) {
        type = OABE_CT_TYPE_AES_GCM;
    } else if (first_byte == OABE_SCHEME_CP_WATERS || first_byte == OABE_SCHEME_CP_WATERS_CCA) {
        type = OABE_CT_TYPE_CP_ABE;
    } else {
        type = OABE_CT_TYPE_KP_ABE;
    }

    *ct = oabe_ct_new(type);
    if (!*ct) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ERROR rc;
    switch (type) {
        case OABE_CT_TYPE_AES_GCM:
            rc = oabe_aes_ct_deserialize(input, &(*ct)->data.aes);
            break;
        case OABE_CT_TYPE_CP_ABE:
            rc = oabe_cp_ct_deserialize(group, input, &(*ct)->data.cp);
            break;
        case OABE_CT_TYPE_KP_ABE:
            rc = oabe_kp_ct_deserialize(group, input, &(*ct)->data.kp);
            break;
        default:
            rc = OABE_ERROR_INVALID_CIPHERTEXT;
    }

    if (rc != OABE_SUCCESS) {
        oabe_ct_free(*ct);
        *ct = NULL;
    }

    return rc;
}