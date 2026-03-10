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
/// \file   oabe_serialize.h
///
/// \brief  Serialization utilities for OpenABE C implementation.
///

#ifndef OABE_SERIALIZE_H
#define OABE_SERIALIZE_H

#include "oabe_types.h"
#include "oabe_bytestring.h"
#include "oabe_zml.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Element Type Tags for Serialization
 *============================================================================*/

#define OABE_TAG_ZP        0x01
#define OABE_TAG_G1        0x02
#define OABE_TAG_G2        0x03
#define OABE_TAG_GT        0x04
#define OABE_TAG_PARAMS    0x10
#define OABE_TAG_SECRET    0x11
#define OABE_TAG_USER_KEY  0x12
#define OABE_TAG_CIPHERTEXT 0x20

/*============================================================================
 * ZP Serialization
 *============================================================================*/

/**
 * Serialize a ZP element to ByteString.
 * @param zp ZP element
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_zp_serialize(const OABE_ZP *zp, OABE_ByteString **result);

/**
 * Deserialize a ZP element from ByteString.
 * @param group Group handle
 * @param input Input ByteString
 * @param zp Output ZP (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_zp_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_ZP **zp);

/*============================================================================
 * G1 Serialization
 *============================================================================*/

/**
 * Serialize a G1 element to ByteString.
 * @param g1 G1 element
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_g1_serialize(const OABE_G1 *g1, OABE_ByteString **result);

/**
 * Deserialize a G1 element from ByteString.
 * @param group Group handle
 * @param input Input ByteString
 * @param g1 Output G1 (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_g1_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_G1 **g1);

/*============================================================================
 * G2 Serialization
 *============================================================================*/

/**
 * Serialize a G2 element to ByteString.
 * @param g2 G2 element
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_g2_serialize(const OABE_G2 *g2, OABE_ByteString **result);

/**
 * Deserialize a G2 element from ByteString.
 * @param group Group handle
 * @param input Input ByteString
 * @param g2 Output G2 (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_g2_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_G2 **g2);

/*============================================================================
 * GT Serialization
 *============================================================================*/

/**
 * Serialize a GT element to ByteString.
 * @param gt GT element
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_gt_serialize(const OABE_GT *gt, OABE_ByteString **result);

/**
 * Deserialize a GT element from ByteString.
 * @param group Group handle
 * @param input Input ByteString
 * @param gt Output GT (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_gt_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_GT **gt);

/*============================================================================
 * Vector Serialization
 *============================================================================*/

/**
 * Serialize an array of ZP elements.
 * @param elements Array of ZP elements
 * @param count Number of elements
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_zp_array_serialize(OABE_ZP **elements, size_t count, OABE_ByteString **result);

/**
 * Deserialize an array of ZP elements.
 * @param group Group handle
 * @param input Input ByteString
 * @param elements Output array (caller must free each element and array)
 * @param count Output count
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_zp_array_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                      OABE_ZP ***elements, size_t *count);

/**
 * Serialize an array of G1 elements.
 * @param elements Array of G1 elements
 * @param count Number of elements
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_g1_array_serialize(OABE_G1 **elements, size_t count, OABE_ByteString **result);

/**
 * Deserialize an array of G1 elements.
 * @param group Group handle
 * @param input Input ByteString
 * @param elements Output array (caller must free each element and array)
 * @param count Output count
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_g1_array_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                      OABE_G1 ***elements, size_t *count);

/**
 * Serialize an array of G2 elements.
 * @param elements Array of G2 elements
 * @param count Number of elements
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_g2_array_serialize(OABE_G2 **elements, size_t count, OABE_ByteString **result);

/**
 * Deserialize an array of G2 elements.
 * @param group Group handle
 * @param input Input ByteString
 * @param elements Output array (caller must free each element and array)
 * @param count Output count
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_g2_array_deserialize(OABE_GroupHandle group, const OABE_ByteString *input,
                                      OABE_G2 ***elements, size_t *count);

#ifdef __cplusplus
}
#endif

#endif /* OABE_SERIALIZE_H */