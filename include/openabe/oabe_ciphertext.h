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
/// \file   oabe_ciphertext.h
///
/// \brief  Ciphertext structures for OpenABE C implementation.
///

#ifndef OABE_CIPHERTEXT_H
#define OABE_CIPHERTEXT_H

#include "oabe_types.h"
#include "oabe_memory.h"
#include "oabe_bytestring.h"
#include "oabe_zml.h"
#include "oabe_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Ciphertext Types
 *============================================================================*/

/**
 * Ciphertext type enumeration.
 */
typedef enum {
    OABE_CT_TYPE_NONE = 0,
    OABE_CT_TYPE_CP_ABE,       /* CP-ABE ciphertext */
    OABE_CT_TYPE_KP_ABE,       /* KP-ABE ciphertext */
    OABE_CT_TYPE_AES_GCM       /* AES-GCM ciphertext */
} OABE_CiphertextType;

/*============================================================================
 * AES-GCM Ciphertext
 *============================================================================*/

/**
 * AES-GCM ciphertext structure.
 */
typedef struct OABE_AES_Ciphertext {
    OABE_Object base;
    uint8_t iv[16];              /* Initialization vector */
    size_t iv_len;
    OABE_ByteString *ciphertext;  /* Encrypted data */
    uint8_t tag[16];             /* Authentication tag */
} OABE_AES_Ciphertext;

/**
 * Create a new AES ciphertext.
 * @return Ciphertext, or NULL on failure
 */
OABE_AES_Ciphertext* oabe_aes_ct_new(void);

/**
 * Free an AES ciphertext.
 * @param ct Ciphertext
 */
void oabe_aes_ct_free(OABE_AES_Ciphertext *ct);

/**
 * Serialize AES ciphertext.
 * @param ct Ciphertext
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_aes_ct_serialize(const OABE_AES_Ciphertext *ct, OABE_ByteString **result);

/**
 * Deserialize AES ciphertext.
 * @param input Input ByteString
 * @param ct Output ciphertext (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_aes_ct_deserialize(const OABE_ByteString *input, OABE_AES_Ciphertext **ct);

/*============================================================================
 * CP-ABE Ciphertext (Waters '09)
 *============================================================================*/

/**
 * CP-ABE ciphertext component for an attribute.
 */
typedef struct OABE_CP_CiphertextComponent {
    char *attribute;             /* Attribute string */
    OABE_G1 *c1;                 /* Component C1 */
    OABE_G2 *c2;                 /* Component C2 (may be NULL for some schemes) */
} OABE_CP_CiphertextComponent;

/**
 * CP-ABE Waters '09 ciphertext structure.
 *
 * Structure:
 * - C0: GT element (encapsulated key)
 * - C1: G1 element (for Waters '09)
 * - { (C_i, D_i) } for each attribute in policy
 * - Encrypted message using symmetric key
 */
typedef struct OABE_CP_Ciphertext {
    OABE_Object base;
    OABE_Scheme scheme;
    char *policy_string;         /* Original policy string */
    OABE_PolicyTree *policy;      /* Parsed policy tree */

    /* Waters '09 elements */
    OABE_GT *ct;                 /* C_t = e(g,g)^s * M where M is the message key */
    OABE_G1 *c0;                 /* C0 = g^s */

    /* Per-attribute components */
    OABE_CP_CiphertextComponent *components;
    size_t num_components;

    /* Encrypted symmetric key and message */
    OABE_ByteString *encrypted_key;  /* Encapsulated symmetric key */
    OABE_ByteString *encrypted_msg;  /* Encrypted message */
} OABE_CP_Ciphertext;

/**
 * Create a new CP-ABE ciphertext.
 * @param scheme Scheme type
 * @return Ciphertext, or NULL on failure
 */
OABE_CP_Ciphertext* oabe_cp_ct_new(OABE_Scheme scheme);

/**
 * Free a CP-ABE ciphertext.
 * @param ct Ciphertext
 */
void oabe_cp_ct_free(OABE_CP_Ciphertext *ct);

/**
 * Add a component to CP-ABE ciphertext.
 * @param ct Ciphertext
 * @param attribute Attribute string
 * @param c1 G1 component
 * @param c2 G2 component (can be NULL)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_cp_ct_add_component(OABE_CP_Ciphertext *ct, const char *attribute,
                                     OABE_G1 *c1, OABE_G2 *c2);

/**
 * Serialize CP-ABE ciphertext.
 * @param ct Ciphertext
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_cp_ct_serialize(const OABE_CP_Ciphertext *ct, OABE_ByteString **result);

/**
 * Deserialize CP-ABE ciphertext.
 * @param group Group handle
 * @param input Input ByteString
 * @param ct Output ciphertext (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_cp_ct_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                   OABE_CP_Ciphertext **ct);

/*============================================================================
 * KP-ABE Ciphertext (GPSW '06)
 *============================================================================*/

/**
 * KP-ABE GPSW '06 ciphertext structure.
 *
 * Structure:
 * - { (E_i) } for each attribute
 * - Encrypted message using symmetric key
 */
typedef struct OABE_KP_Ciphertext {
    OABE_Object base;
    OABE_Scheme scheme;
    OABE_StringVector *attributes;  /* List of attributes */

    /* GPSW '06 elements - map from attribute to G1 element */
    char **attr_names;               /* Attribute names */
    OABE_G1 **attr_elements;         /* G1 elements for each attribute */
    size_t num_attributes;

    /* Encrypted symmetric key and message */
    OABE_ByteString *encrypted_key;
    OABE_ByteString *encrypted_msg;
} OABE_KP_Ciphertext;

/**
 * Create a new KP-ABE ciphertext.
 * @param scheme Scheme type
 * @return Ciphertext, or NULL on failure
 */
OABE_KP_Ciphertext* oabe_kp_ct_new(OABE_Scheme scheme);

/**
 * Free a KP-ABE ciphertext.
 * @param ct Ciphertext
 */
void oabe_kp_ct_free(OABE_KP_Ciphertext *ct);

/**
 * Add an attribute component to KP-ABE ciphertext.
 * @param ct Ciphertext
 * @param attribute Attribute string
 * @param element G1 element for this attribute
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_kp_ct_add_attribute(OABE_KP_Ciphertext *ct, const char *attribute, OABE_G1 *element);

/**
 * Serialize KP-ABE ciphertext.
 * @param ct Ciphertext
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_kp_ct_serialize(const OABE_KP_Ciphertext *ct, OABE_ByteString **result);

/**
 * Deserialize KP-ABE ciphertext.
 * @param group Group handle
 * @param input Input ByteString
 * @param ct Output ciphertext (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_kp_ct_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                   OABE_KP_Ciphertext **ct);

/*============================================================================
 * Generic Ciphertext Interface
 *============================================================================*/

/**
 * Generic ciphertext wrapper.
 */
typedef struct OABE_Ciphertext {
    OABE_Object base;
    OABE_CiphertextType type;
    union {
        OABE_AES_Ciphertext *aes;
        OABE_CP_Ciphertext *cp;
        OABE_KP_Ciphertext *kp;
    } data;
} OABE_Ciphertext;

/**
 * Create a new ciphertext based on type.
 * @param type Ciphertext type
 * @return Ciphertext, or NULL on failure
 */
OABE_Ciphertext* oabe_ct_new(OABE_CiphertextType type);

/**
 * Free a generic ciphertext.
 * @param ct Ciphertext
 */
void oabe_ct_free(OABE_Ciphertext *ct);

/**
 * Serialize generic ciphertext.
 * @param ct Ciphertext
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_ct_serialize(const OABE_Ciphertext *ct, OABE_ByteString **result);

/**
 * Deserialize generic ciphertext.
 * @param group Group handle (can be NULL for AES)
 * @param input Input ByteString
 * @param ct Output ciphertext (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_ct_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                 OABE_Ciphertext **ct);

#ifdef __cplusplus
}
#endif

#endif /* OABE_CIPHERTEXT_H */