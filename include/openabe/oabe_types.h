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
/// \file   oabe_types.h
///
/// \brief  Core types, error codes, and constants for OpenABE C implementation.
///
/// \author Matthew Green and J. Ayo Akinyele (original C++), C translation
///

#ifndef OABE_TYPES_H
#define OABE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Library Version
 *============================================================================*/

#define OABE_LIBRARY_VERSION    170  /* Library version 1.7 */

/*============================================================================
 * Constants
 *============================================================================*/

#define OABE_MIN_BYTE_LEN           32
#define OABE_DEFAULT_SECURITY_LEVEL 128
#define OABE_DEFAULT_AES_SEC_LEVEL  (OABE_MIN_BYTE_LEN * 8)  /* AES-256 */
#define OABE_SALT_LEN               OABE_MIN_BYTE_LEN        /* 256-bits */
#define OABE_HASH_LEN               OABE_MIN_BYTE_LEN         /* 256-bits */
#define OABE_SEED_LEN               OABE_MIN_BYTE_LEN
#define OABE_UID_LEN                16       /* 128-bit UID length */
#define OABE_DEFAULT_SYM_KEY_BYTES  OABE_MIN_BYTE_LEN  /* 256-bit keys */
#define OABE_DEFAULT_SYM_KEY_BITS   (OABE_DEFAULT_SYM_KEY_BYTES * 8)
#define OABE_SHA256_LEN             32       /* SHA-256 */
#define OABE_KDF_ITERATION_COUNT    10000
#define OABE_MAX_BUFFER_SIZE        512
#define OABE_MAX_INT_BITS           32       /* For numerical attributes */

/*============================================================================
 * Error Codes
 *============================================================================*/

typedef enum {
    OABE_SUCCESS = 0,
    OABE_ERROR_INVALID_CONTEXT = 2,
    OABE_ERROR_INVALID_CIPHERTEXT = 3,
    OABE_ERROR_INVALID_GROUP_PARAMS = 4,
    OABE_ERROR_INVALID_PARAMS = 5,
    OABE_ERROR_INVALID_KEY = 6,
    OABE_ERROR_OUT_OF_MEMORY = 7,
    OABE_ERROR_INVALID_INPUT = 8,
    OABE_ERROR_ENCRYPTION_ERROR = 9,
    OABE_ERROR_UNKNOWN_SCHEME = 10,
    OABE_ERROR_LIBRARY_NOT_INITIALIZED = 11,
    OABE_ERROR_NO_SECRET_PARAMS = 12,
    OABE_ERROR_NO_PUBLIC_PARAMS = 13,
    OABE_ERROR_NOT_IMPLEMENTED = 14,
    OABE_ERROR_BUFFER_TOO_SMALL = 15,
    OABE_ERROR_WRONG_GROUP = 16,
    OABE_ERROR_INVALID_PARAMS_ID = 17,
    OABE_ERROR_ELEMENT_NOT_FOUND = 18,
    OABE_ERROR_SECRET_SHARING_FAILED = 19,
    OABE_ERROR_INVALID_POLICY = 20,
    OABE_ERROR_INVALID_RNG = 21,
    OABE_ERROR_SIGNATURE_FAILED = 22,
    OABE_ERROR_WRONG_USER_PARAM = 23,
    OABE_ERROR_INVALID_LENGTH = 24,
    OABE_ERROR_SERIALIZATION_FAILED = 25,
    OABE_ERROR_INVALID_LIBVERSION = 26,
    OABE_ERROR_RAND_INSUFFICIENT = 27,
    OABE_ERROR_UNEXPECTED_EXTRA_BYTES = 28,
    OABE_ERROR_IN_USE_ALREADY = 29,
    OABE_ERROR_INVALID_KEY_HEADER = 30,
    OABE_ERROR_INVALID_CIPHERTEXT_HEADER = 31,
    OABE_ERROR_DECRYPTION_FAILED = 32,
    OABE_ERROR_VERIFICATION_FAILED = 33,
    OABE_ERROR_DIVIDE_BY_ZERO = 34,
    OABE_ERROR_CTR_DRB_NOT_INITIALIZED = 35,
    OABE_ERROR_ELEMENT_NOT_INITIALIZED = 36,
    OABE_ERROR_DESERIALIZATION_FAILED = 37,
    OABE_ERROR_INVALID_CURVE_ID = 38,
    OABE_ERROR_INVALID_SCHEME_ID = 39,
    OABE_ERROR_INVALID_KEY_BODY = 40,
    OABE_ERROR_INVALID_CIPHERTEXT_BODY = 41,
    OABE_ERROR_SYNTAX_ERROR_IN_PARSER = 42,
    OABE_ERROR_CLASS_NOT_INITIALIZED = 43,
    OABE_ERROR_INVALID_PACK_TYPE = 44,
    OABE_ERROR_INVALID_ATTRIBUTE_STRUCTURE = 45,
    OABE_ERROR_INDEX_OUT_OF_BOUNDS = 46,
    OABE_ERROR_MISSING_SENDER_PUBLIC_KEY = 47,
    OABE_ERROR_MISSING_RECEIVER_PRIVATE_KEY = 48,
    OABE_ERROR_MISSING_RECEIVER_PUBLIC_KEY = 49,
    OABE_ERROR_MISSING_AUTHORITY_ID_IN_ATTR = 50,
    OABE_ERROR_INVALID_ATTRIBUTE_LIST = 51,
    OABE_ERROR_INVALID_RANGE_NUMBERS = 52,
    OABE_ERROR_INVALID_MISMATCH_BITS = 53,
    OABE_ERROR_INVALID_PREFIX_SPECIFIED = 54,
    OABE_ERROR_INVALID_DATE_SPECIFIED = 55,
    OABE_ERROR_INVALID_DATE_BEFORE_EPOCH = 56,
    OABE_ERROR_ORDER_NOT_SPECIFIED = 57,
    OABE_ERROR_INVALID_POLICY_TREE = 58,
    OABE_ERROR_KEYGEN_FAILED = 59,
    OABE_ERROR_NO_PLAINTEXT_SPECIFIED = 60,
    OABE_ERROR_INVALID_TAG_LENGTH = 61,
    OABE_ERROR_RNG_FAILURE = 62,
    OABE_ERROR_MATH_OPERATION_FAILED = 63,
    OABE_ERROR_POLICY_NOT_SATISFIED = 64,
    OABE_ERROR_UNKNOWN = 99,
    OABE_INVALID_INPUT_TYPE = 100
} OABE_ERROR;

/* Get human-readable string for error code */
const char* oabe_error_to_string(OABE_ERROR err);

/*============================================================================
 * Element Types
 *============================================================================*/

typedef enum {
    OABE_ELEMENT_NONE = 0x00,
    OABE_ELEMENT_INT = 0xA1,
    OABE_ELEMENT_ZP = 0xB1,
    OABE_ELEMENT_G1 = 0xB2,
    OABE_ELEMENT_G2 = 0xB3,
    OABE_ELEMENT_GT = 0xB4,
    OABE_ELEMENT_ZP_T = 0xC1,
    OABE_ELEMENT_G_T = 0xC2,
    OABE_ELEMENT_POLICY = 0x7A,
    OABE_ELEMENT_ATTRIBUTES = 0x7C,  /* ATTR_SEP '|' in hex */
    OABE_ELEMENT_BYTESTRING = 0x1D,
} OABE_ElementType;

/*============================================================================
 * Curve Identifiers
 *============================================================================*/

typedef enum {
    OABE_CURVE_NONE = 0x00,
    OABE_CURVE_NIST_P256 = 0x32,
    OABE_CURVE_NIST_P384 = 0x5A,
    OABE_CURVE_NIST_P521 = 0xB7,
    OABE_CURVE_BN_P158 = 0x61,
    OABE_CURVE_BN_P254 = 0x6F,
    OABE_CURVE_BN_P256 = 0x73,
    OABE_CURVE_KSS_508 = 0x3C,
    OABE_CURVE_BN_P382 = 0xE4,
    OABE_CURVE_BN_P638 = 0x8D
} OABE_CurveID;

/*============================================================================
 * Group Types
 *============================================================================*/

typedef enum {
    OABE_GROUP_NONE = 0,
    OABE_GROUP_G1,
    OABE_GROUP_G2,
    OABE_GROUP_GT,
    OABE_GROUP_ZP
} OABE_GroupType;

/*============================================================================
 * Scheme Identifiers
 *============================================================================*/

typedef enum {
    OABE_SCHEME_NONE = 0,
    OABE_SCHEME_PKSIG_ECDSA = 60,
    OABE_SCHEME_AES_GCM = 70,
    OABE_SCHEME_PK_OPDH = 100,
    OABE_SCHEME_CP_WATERS = 101,
    OABE_SCHEME_KP_GPSW = 102,
    OABE_SCHEME_CP_WATERS_CCA = 201,
    OABE_SCHEME_KP_GPSW_CCA = 202
} OABE_Scheme;

/*============================================================================
 * Compression/Encoding Types
 *============================================================================*/

#define OABE_NO_COMPRESS 0
#define OABE_COMPRESS    1
#define OABE_BINARY      2
#define OABE_DEC         10
#define OABE_HEXADECIMAL 16
#define OABE_MAX_BYTES   1024

#define OABE_SHA1_BITLEN  160     /* only used with PBKDF2 */
#define OABE_SHA2_BITLEN  256

/*============================================================================
 * Hash Function Prefixes
 *============================================================================*/

#define OABE_HASH_FUNCTION_STRINGS           "0"
#define OABE_HASH_FUNCTION_STR_TO_ZR_CRH     "1"
#define OABE_HASH_FUNCTION_ZR_TO_G1_ROM      "2"
#define OABE_HASH_FUNCTION_ZR_TO_G2_ROM      "3"

#define OABE_CCA_HASH_FUNCTION_ONE 0x1A
#define OABE_CCA_HASH_FUNCTION_TWO 0x1F
#define OABE_SCHEME_HASH_FUNCTION  0x2A
#define OABE_KDF_HASH_FUNCTION_PREFIX 0x2B

#define OABE_MAX_KDF_BITLENGTH 0xFFFFFFFF

/*============================================================================
 * Pack Types for ByteString serialization
 *============================================================================*/

typedef enum {
    OABE_PACK_NONE = 0x00,
    OABE_PACK_8    = 0xA1,
    OABE_PACK_16   = 0xB2,
    OABE_PACK_32   = 0xC3,
    OABE_PACK_64   = 0xD4
} OABE_PackType;

#define OABE_BYTESTRING_TYPE 0x1D

/*============================================================================
 * ZML Element Type Tags for Serialization
 *============================================================================*/

#define OABE_TAG_ZP  0x01
#define OABE_TAG_G1  0x02
#define OABE_TAG_G2  0x03
#define OABE_TAG_GT  0x04

/*============================================================================
 * Scheme String Identifiers
 *============================================================================*/

#define OABE_EC_DSA_STR "EC-DSA"
#define OABE_PK_ENC_STR "PK-ENC"
#define OABE_CP_ABE_STR "CP-ABE"
#define OABE_KP_ABE_STR "KP-ABE"
#define OABE_MA_ABE_STR "MA-ABE"

/*============================================================================
 * Library State
 *============================================================================*/

typedef enum {
    OABE_STATE_UNINITIALIZED = 0,
    OABE_STATE_ERROR = 1,
    OABE_STATE_READY = 2
} OABE_State;

/*============================================================================
 * Utility Macros
 *============================================================================*/

#define OABE_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Memory allocation checking */
#define OABE_MALLOC_CHECK(ptr) \
    do { \
        if (!(ptr)) { \
            fprintf(stderr, "Out of Memory at %s:%d\n", __FILE__, __LINE__); \
            return OABE_ERROR_OUT_OF_MEMORY; \
        } \
    } while(0)

/* Safe memory zeroization */
void oabe_zeroize(void *ptr, size_t len);

/* Base64 encoding/decoding */
char* oabe_base64_encode(const unsigned char *bytes, unsigned int len);
int oabe_base64_decode(const char *encoded, unsigned char **output, size_t *output_len);

/*============================================================================
 * Forward Declarations for Core Types
 *============================================================================*/

/* ByteString - forward declaration, defined in oabe_bytestring.h */
typedef struct OABE_ByteString OABE_ByteString;

/* Object base - forward declaration, defined in oabe_memory.h */
typedef struct OABE_Object OABE_Object;

/*============================================================================
 * Function Declarations for Type Conversion
 *============================================================================*/

/* Convert curve ID to/from string */
OABE_CurveID oabe_curve_id_from_string(const char *params_id);
const char* oabe_curve_id_to_string(OABE_CurveID id);
OABE_CurveID oabe_get_curve_id(uint8_t id);

/* Convert scheme ID to/from string */
OABE_Scheme oabe_scheme_from_string(const char *id);
const char* oabe_scheme_to_string(OABE_Scheme scheme);
OABE_Scheme oabe_get_scheme_id(uint8_t id);

/* Get library version */
uint32_t oabe_get_library_version(void);

#ifdef __cplusplus
}
#endif

#endif /* OABE_TYPES_H */