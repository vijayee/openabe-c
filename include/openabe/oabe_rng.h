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
/// \file   oabe_rng.h
///
/// \brief  Random Number Generator for OpenABE C implementation.
///

#ifndef OABE_RNG_H
#define OABE_RNG_H

#include "oabe_types.h"
#include "oabe_bytestring.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

#define OABE_CTR_DRBG_BLOCKSIZE         16      /* Cipher Block size */
#define OABE_CTR_DRBG_KEYSIZE_BYTES      32      /* Cipher Key size in bytes */
#define OABE_CTR_DRBG_KEYSIZE_BITS       (OABE_CTR_DRBG_KEYSIZE_BYTES * 8)
#define OABE_CTR_DRBG_SEEDLEN            (OABE_CTR_DRBG_KEYSIZE_BYTES + OABE_CTR_DRBG_BLOCKSIZE)
#define OABE_CTR_DRBG_NONCELEN           16      /* Default nonce length */
#define OABE_CTR_DRBG_ENTROPYLEN          32      /* Amount of entropy used per seed */
#define OABE_CTR_DRBG_RESEED_INTERVAL     10000   /* Interval before re-seed */
#define OABE_CTR_DRBG_MAX_INPUT_LENGTH    256     /* Maximum additional input bytes */
#define OABE_CTR_DRBG_MAX_REQUEST         1024    /* Maximum requested bytes per call */

/*============================================================================
 * RNG Structure
 *============================================================================*/

/**
 * CTR_DRBG state structure.
 */
typedef struct OABE_CtrDrbg {
    uint8_t key[OABE_CTR_DRBG_KEYSIZE_BYTES];
    uint8_t counter[OABE_CTR_DRBG_BLOCKSIZE];
    int reseed_counter;
    int reseed_interval;
    size_t entropy_len;
    bool is_initialized;
} OABE_CtrDrbg;

/**
 * RNG context structure.
 */
typedef struct OABE_RNGCtx {
    OABE_Object base;
    OABE_CtrDrbg drbg;
    bool use_ctr_drbg;
} OABE_RNGCtx;

/*============================================================================
 * RNG Functions
 *============================================================================*/

/**
 * Create a new RNG context using system entropy.
 * @return RNG context, or NULL on failure
 */
OABE_RNGCtx* oabe_rng_new_system(void);

/**
 * Create a new RNG context with a seed.
 * @param seed Seed bytes (can be NULL for system entropy)
 * @param seed_len Length of seed
 * @return RNG context, or NULL on failure
 */
OABE_RNGCtx* oabe_rng_new_seeded(const uint8_t *seed, size_t seed_len);

/**
 * Free an RNG context.
 * @param rng RNG context
 */
void oabe_rng_ctx_free(OABE_RNGCtx *rng);

/**
 * Generate random bytes.
 * @param rng RNG context
 * @param output Output buffer
 * @param output_len Number of bytes to generate
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_rng_ctx_bytes(OABE_RNGCtx *rng, uint8_t *output, size_t output_len);

/**
 * Generate random bytes into a ByteString.
 * @param rng RNG context
 * @param output Output ByteString (appended to)
 * @param output_len Number of bytes to generate
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_rng_bytestring(OABE_RNGCtx *rng, OABE_ByteString *output, size_t output_len);

/**
 * Reseed the RNG.
 * @param rng RNG context
 * @param seed Additional seed bytes (can be NULL)
 * @param seed_len Length of seed
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_rng_reseed(OABE_RNGCtx *rng, const uint8_t *seed, size_t seed_len);

/*============================================================================
 * CTR_DRBG Functions
 *============================================================================*/

/**
 * Initialize CTR_DRBG state.
 * @param ctx CTR_DRBG context
 * @param entropy Initial entropy bytes (32 bytes minimum)
 * @param entropy_len Length of entropy
 * @param personalization Personalization string (can be NULL)
 * @param personalization_len Length of personalization string
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_ctr_drbg_init(OABE_CtrDrbg *ctx, const uint8_t *entropy, size_t entropy_len,
                               const uint8_t *personalization, size_t personalization_len);

/**
 * Generate random bytes using CTR_DRBG.
 * @param ctx CTR_DRBG context
 * @param output Output buffer
 * @param output_len Number of bytes to generate
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_ctr_drbg_generate(OABE_CtrDrbg *ctx, uint8_t *output, size_t output_len);

/**
 * Update CTR_DRBG state.
 * @param ctx CTR_DRBG context
 * @param additional Additional data (can be NULL)
 * @param additional_len Length of additional data
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_ctr_drbg_update(OABE_CtrDrbg *ctx, const uint8_t *additional, size_t additional_len);

#ifdef __cplusplus
}
#endif

#endif /* OABE_RNG_H */