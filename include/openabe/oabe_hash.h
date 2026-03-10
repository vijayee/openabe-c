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
/// \file   oabe_hash.h
///
/// \brief  Hash-to-curve functions for ABE attribute hashing.
///

#ifndef OABE_HASH_H
#define OABE_HASH_H

#include "oabe_types.h"
#include "oabe_zml.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Hash-to-Curve Functions
 *============================================================================*/

/**
 * Hash a string to a G1 element using a prefix.
 * The hash is computed as: H(prefix || attr)
 * @param group Group handle
 * @param prefix Prefix string (e.g., "0", "1", "2")
 * @param attr Attribute string
 * @param result Output G1 element (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_hash_to_g1(OABE_GroupHandle group,
                            const char *prefix,
                            const char *attr,
                            OABE_G1 **result);

/**
 * Hash a string to a G2 element using a prefix.
 * The hash is computed as: H(prefix || attr)
 * @param group Group handle
 * @param prefix Prefix string (e.g., "0", "1", "2")
 * @param attr Attribute string
 * @param result Output G2 element (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_hash_to_g2(OABE_GroupHandle group,
                            const char *prefix,
                            const char *attr,
                            OABE_G2 **result);

/**
 * Hash a ZP scalar to G1.
 * Used for mapping secret shares to group elements.
 * @param group Group handle
 * @param prefix Prefix string
 * @param zp ZP scalar value
 * @param result Output G1 element (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_hash_zp_to_g1(OABE_GroupHandle group,
                               const char *prefix,
                               const OABE_ZP *zp,
                               OABE_G1 **result);

/**
 * Hash a ZP scalar to G2.
 * Used for mapping secret shares to group elements.
 * @param group Group handle
 * @param prefix Prefix string
 * @param zp ZP scalar value
 * @param result Output G2 element (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_hash_zp_to_g2(OABE_GroupHandle group,
                               const char *prefix,
                               const OABE_ZP *zp,
                               OABE_G2 **result);

/*============================================================================
 * Attribute Hash Functions (High-Level)
 *============================================================================*/

/**
 * Hash an attribute to G1 for CP-ABE.
 * Uses prefix "0" as per Waters '09 scheme.
 * @param group Group handle
 * @param attr Attribute string
 * @param result Output G1 element (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_hash_attr_to_g1(OABE_GroupHandle group,
                                 const char *attr,
                                 OABE_G1 **result);

/**
 * Hash an attribute to G2 for KP-ABE.
 * Uses prefix "0" as per GPSW '06 scheme.
 * @param group Group handle
 * @param attr Attribute string
 * @param result Output G2 element (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_hash_attr_to_g2(OABE_GroupHandle group,
                                 const char *attr,
                                 OABE_G2 **result);

#ifdef __cplusplus
}
#endif

#endif /* OABE_HASH_H */