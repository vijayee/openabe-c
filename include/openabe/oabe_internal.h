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
/// \file   oabe_internal.h
///
/// \brief  Internal structures for OpenABE C implementation.
///         This header is for internal use only - not part of public API.
///

#ifndef OABE_INTERNAL_H
#define OABE_INTERNAL_H

#include "oabe_types.h"
#include "oabe_zml.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Internal Structure Definitions
 *============================================================================*/

/**
 * Internal structure for OABE_Bignum - wraps OpenSSL BIGNUM
 */
struct OABE_Bignum {
    void *bn;  /* OpenSSL BIGNUM* or RELIC bn_t */
};

/**
 * Internal structure for OABE_Group
 */
struct OABE_Group {
    OABE_Object base;
    OABE_CurveID curve_id;
    void *order;  /* BIGNUM* or bn_t */
    void *params; /* Curve parameters */
};

/**
 * Internal structure for OABE_RNG
 */
struct OABE_RNG {
    OABE_Object base;
    uint8_t seed[32];
    bool initialized;
};

/**
 * Internal structure for OABE_ECPoint
 */
struct OABE_ECPoint {
    void *x;       /* BIGNUM* or bn_t */
    void *y;       /* BIGNUM* or bn_t */
    bool infinity;
};

#ifdef __cplusplus
}
#endif

#endif /* OABE_INTERNAL_H */