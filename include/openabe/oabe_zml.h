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
/// \file   oabe_zml.h
///
/// \brief  ZML math types (ZP, G1, G2, GT) for OpenABE C implementation.
///

#ifndef OABE_ZML_H
#define OABE_ZML_H

#include "oabe_types.h"
#include "oabe_bytestring.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Forward Declarations - Opaque Types
 *============================================================================*/

/* Opaque handles - implementation defined */
typedef struct OABE_ZP OABE_ZP;
typedef struct OABE_G1 OABE_G1;
typedef struct OABE_G2 OABE_G2;
typedef struct OABE_GT OABE_GT;

/* Group and RNG handles */
typedef struct OABE_Group *OABE_GroupHandle;
typedef struct OABE_RNG *OABE_RNGHandle;

/*============================================================================
 * Group Management
 *============================================================================*/

/**
 * Create a new bilinear pairing group.
 * @param curve_id Curve identifier
 * @return Group handle, or NULL on failure
 */
OABE_GroupHandle oabe_group_new(OABE_CurveID curve_id);

/**
 * Free a group handle.
 * @param group Group handle
 */
void oabe_group_free(OABE_GroupHandle group);

/**
 * Get the curve ID for a group.
 * @param group Group handle
 * @return Curve ID
 */
OABE_CurveID oabe_group_get_curve_id(OABE_GroupHandle group);

/**
 * Get the order of the group as a ByteString.
 * @param group Group handle
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_group_get_order(OABE_GroupHandle group, OABE_ByteString **result);

/*============================================================================
 * RNG Management
 *============================================================================*/

/**
 * Create a new random number generator.
 * @param seed Optional seed (can be NULL to use system entropy)
 * @param seed_len Length of seed
 * @return RNG handle, or NULL on failure
 */
OABE_RNGHandle oabe_rng_new(const uint8_t *seed, size_t seed_len);

/**
 * Free an RNG handle.
 * @param rng RNG handle
 */
void oabe_rng_free(OABE_RNGHandle rng);

/**
 * Generate random bytes.
 * @param rng RNG handle
 * @param output Output buffer
 * @param len Number of bytes to generate
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_rng_bytes(OABE_RNGHandle rng, uint8_t *output, size_t len);

/*============================================================================
 * ZP Element (Scalar in Z_p)
 *============================================================================*/

OABE_ZP* oabe_zp_new(OABE_GroupHandle group);
void oabe_zp_free(OABE_ZP *zp);
OABE_ZP* oabe_zp_clone(const OABE_ZP *zp);
OABE_GroupHandle oabe_zp_get_group(const OABE_ZP *zp);
OABE_ERROR oabe_zp_set_zero(OABE_ZP *zp);
OABE_ERROR oabe_zp_set_one(OABE_ZP *zp);
OABE_ERROR oabe_zp_copy(OABE_ZP *dst, const OABE_ZP *src);
OABE_ERROR oabe_zp_set_int(OABE_ZP *zp, int value);
OABE_ERROR oabe_zp_set_hex(OABE_ZP *zp, const char *hex);
OABE_ERROR oabe_zp_set_bytes(OABE_ZP *zp, const uint8_t *data, size_t len);
OABE_ERROR oabe_zp_random(OABE_ZP *zp, OABE_RNGHandle rng);
OABE_ERROR oabe_zp_add(OABE_ZP *result, const OABE_ZP *a, const OABE_ZP *b);
OABE_ERROR oabe_zp_sub(OABE_ZP *result, const OABE_ZP *a, const OABE_ZP *b);
OABE_ERROR oabe_zp_mul(OABE_ZP *result, const OABE_ZP *a, const OABE_ZP *b);
OABE_ERROR oabe_zp_div(OABE_ZP *result, const OABE_ZP *a, const OABE_ZP *b);
OABE_ERROR oabe_zp_neg(OABE_ZP *result, const OABE_ZP *a);
OABE_ERROR oabe_zp_inv(OABE_ZP *result, const OABE_ZP *a);
int oabe_zp_cmp(const OABE_ZP *a, const OABE_ZP *b);
bool oabe_zp_is_zero(const OABE_ZP *zp);
bool oabe_zp_is_one(const OABE_ZP *zp);
char* oabe_zp_to_hex(const OABE_ZP *zp);
OABE_ERROR oabe_zp_serialize(const OABE_ZP *zp, OABE_ByteString **result);
OABE_ERROR oabe_zp_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_ZP **zp);

/*============================================================================
 * G1 Element (Group 1 point)
 *============================================================================*/

OABE_G1* oabe_g1_new(OABE_GroupHandle group);
void oabe_g1_free(OABE_G1 *g1);
OABE_G1* oabe_g1_clone(const OABE_G1 *g1);
OABE_ERROR oabe_g1_set_identity(OABE_G1 *g1);
OABE_ERROR oabe_g1_set_generator(OABE_G1 *g1);
OABE_ERROR oabe_g1_random(OABE_G1 *g1, OABE_RNGHandle rng);
OABE_ERROR oabe_g1_hash(OABE_G1 *g1, const uint8_t *msg, size_t len);
OABE_ERROR oabe_g1_add(OABE_G1 *result, const OABE_G1 *a, const OABE_G1 *b);
OABE_ERROR oabe_g1_sub(OABE_G1 *result, const OABE_G1 *a, const OABE_G1 *b);
OABE_ERROR oabe_g1_mul_scalar(OABE_G1 *result, const OABE_G1 *a, const OABE_ZP *scalar);
bool oabe_g1_equals(const OABE_G1 *a, const OABE_G1 *b);
bool oabe_g1_is_identity(const OABE_G1 *g1);
OABE_ERROR oabe_g1_serialize(const OABE_G1 *g1, OABE_ByteString **result);
OABE_ERROR oabe_g1_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_G1 **g1);

/*============================================================================
 * G2 Element (Group 2 point)
 *============================================================================*/

OABE_G2* oabe_g2_new(OABE_GroupHandle group);
void oabe_g2_free(OABE_G2 *g2);
OABE_G2* oabe_g2_clone(const OABE_G2 *g2);
OABE_ERROR oabe_g2_set_identity(OABE_G2 *g2);
OABE_ERROR oabe_g2_set_generator(OABE_G2 *g2);
OABE_ERROR oabe_g2_random(OABE_G2 *g2, OABE_RNGHandle rng);
OABE_ERROR oabe_g2_add(OABE_G2 *result, const OABE_G2 *a, const OABE_G2 *b);
OABE_ERROR oabe_g2_sub(OABE_G2 *result, const OABE_G2 *a, const OABE_G2 *b);
OABE_ERROR oabe_g2_mul_scalar(OABE_G2 *result, const OABE_G2 *a, const OABE_ZP *scalar);
OABE_ERROR oabe_g2_hash(OABE_G2 *g2, const uint8_t *msg, size_t len);
bool oabe_g2_equals(const OABE_G2 *a, const OABE_G2 *b);
bool oabe_g2_is_identity(const OABE_G2 *g2);
OABE_ERROR oabe_g2_serialize(const OABE_G2 *g2, OABE_ByteString **result);
OABE_ERROR oabe_g2_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_G2 **g2);

/*============================================================================
 * GT Element (Target group)
 *============================================================================*/

OABE_GT* oabe_gt_new(OABE_GroupHandle group);
void oabe_gt_free(OABE_GT *gt);
OABE_GT* oabe_gt_clone(const OABE_GT *gt);
OABE_ERROR oabe_gt_set_identity(OABE_GT *gt);
OABE_ERROR oabe_gt_mul(OABE_GT *result, const OABE_GT *a, const OABE_GT *b);
OABE_ERROR oabe_gt_div(OABE_GT *result, const OABE_GT *a, const OABE_GT *b);
OABE_ERROR oabe_gt_exp(OABE_GT *result, const OABE_GT *base, const OABE_ZP *exp);
bool oabe_gt_equals(const OABE_GT *a, const OABE_GT *b);
bool oabe_gt_is_identity(const OABE_GT *gt);
OABE_ERROR oabe_gt_serialize(const OABE_GT *gt, OABE_ByteString **result);
OABE_ERROR oabe_gt_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_GT **gt);

/*============================================================================
 * Pairing Operations
 *============================================================================*/

/**
 * Compute bilinear pairing: result = e(g1, g2).
 * @param result Output GT element
 * @param g1 G1 element
 * @param g2 G2 element
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_pairing(OABE_GT *result, const OABE_G1 *g1, const OABE_G2 *g2);

#ifdef __cplusplus
}
#endif

#endif /* OABE_ZML_H */