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
/// \file   oabe_error.c
///
/// \brief  Error handling implementation for OpenABE C.
///

#include "openabe/oabe_types.h"
#include <string.h>

/**
 * Error code to string mapping.
 */
static const struct {
    OABE_ERROR code;
    const char *message;
} g_error_messages[] = {
    { OABE_SUCCESS, "Success" },
    { OABE_ERROR_INVALID_CONTEXT, "Invalid context" },
    { OABE_ERROR_INVALID_CIPHERTEXT, "Invalid ciphertext" },
    { OABE_ERROR_INVALID_GROUP_PARAMS, "Invalid group parameters" },
    { OABE_ERROR_INVALID_PARAMS, "Invalid parameters" },
    { OABE_ERROR_INVALID_KEY, "Invalid key" },
    { OABE_ERROR_OUT_OF_MEMORY, "Out of memory" },
    { OABE_ERROR_INVALID_INPUT, "Invalid input" },
    { OABE_ERROR_ENCRYPTION_ERROR, "Encryption error" },
    { OABE_ERROR_UNKNOWN_SCHEME, "Unknown scheme" },
    { OABE_ERROR_LIBRARY_NOT_INITIALIZED, "Library not initialized" },
    { OABE_ERROR_NO_SECRET_PARAMS, "No secret parameters" },
    { OABE_ERROR_NO_PUBLIC_PARAMS, "No public parameters" },
    { OABE_ERROR_NOT_IMPLEMENTED, "Not implemented" },
    { OABE_ERROR_BUFFER_TOO_SMALL, "Buffer too small" },
    { OABE_ERROR_WRONG_GROUP, "Wrong group" },
    { OABE_ERROR_INVALID_PARAMS_ID, "Invalid parameter ID" },
    { OABE_ERROR_ELEMENT_NOT_FOUND, "Element not found" },
    { OABE_ERROR_SECRET_SHARING_FAILED, "Secret sharing failed" },
    { OABE_ERROR_INVALID_POLICY, "Invalid policy" },
    { OABE_ERROR_INVALID_RNG, "Invalid RNG" },
    { OABE_ERROR_SIGNATURE_FAILED, "Signature failed" },
    { OABE_ERROR_WRONG_USER_PARAM, "Wrong user parameter" },
    { OABE_ERROR_INVALID_LENGTH, "Invalid length" },
    { OABE_ERROR_SERIALIZATION_FAILED, "Serialization failed" },
    { OABE_ERROR_INVALID_LIBVERSION, "Invalid library version" },
    { OABE_ERROR_RAND_INSUFFICIENT, "Insufficient randomness" },
    { OABE_ERROR_UNEXPECTED_EXTRA_BYTES, "Unexpected extra bytes" },
    { OABE_ERROR_IN_USE_ALREADY, "Already in use" },
    { OABE_ERROR_INVALID_KEY_HEADER, "Invalid key header" },
    { OABE_ERROR_INVALID_CIPHERTEXT_HEADER, "Invalid ciphertext header" },
    { OABE_ERROR_DECRYPTION_FAILED, "Decryption failed" },
    { OABE_ERROR_VERIFICATION_FAILED, "Verification failed" },
    { OABE_ERROR_DIVIDE_BY_ZERO, "Divide by zero" },
    { OABE_ERROR_CTR_DRB_NOT_INITIALIZED, "CTR DRBG not initialized" },
    { OABE_ERROR_ELEMENT_NOT_INITIALIZED, "Element not initialized" },
    { OABE_ERROR_DESERIALIZATION_FAILED, "Deserialization failed" },
    { OABE_ERROR_INVALID_CURVE_ID, "Invalid curve ID" },
    { OABE_ERROR_INVALID_SCHEME_ID, "Invalid scheme ID" },
    { OABE_ERROR_INVALID_KEY_BODY, "Invalid key body" },
    { OABE_ERROR_INVALID_CIPHERTEXT_BODY, "Invalid ciphertext body" },
    { OABE_ERROR_SYNTAX_ERROR_IN_PARSER, "Syntax error in parser" },
    { OABE_ERROR_CLASS_NOT_INITIALIZED, "Class not initialized" },
    { OABE_ERROR_INVALID_PACK_TYPE, "Invalid pack type" },
    { OABE_ERROR_INVALID_ATTRIBUTE_STRUCTURE, "Invalid attribute structure" },
    { OABE_ERROR_INDEX_OUT_OF_BOUNDS, "Index out of bounds" },
    { OABE_ERROR_MISSING_SENDER_PUBLIC_KEY, "Missing sender public key" },
    { OABE_ERROR_MISSING_RECEIVER_PRIVATE_KEY, "Missing receiver private key" },
    { OABE_ERROR_MISSING_RECEIVER_PUBLIC_KEY, "Missing receiver public key" },
    { OABE_ERROR_MISSING_AUTHORITY_ID_IN_ATTR, "Missing authority ID in attribute" },
    { OABE_ERROR_INVALID_ATTRIBUTE_LIST, "Invalid attribute list" },
    { OABE_ERROR_INVALID_RANGE_NUMBERS, "Invalid range of numbers" },
    { OABE_ERROR_INVALID_MISMATCH_BITS, "Invalid mismatch bits" },
    { OABE_ERROR_INVALID_PREFIX_SPECIFIED, "Invalid prefix specified" },
    { OABE_ERROR_INVALID_DATE_SPECIFIED, "Invalid date specified" },
    { OABE_ERROR_INVALID_DATE_BEFORE_EPOCH, "Invalid date before epoch" },
    { OABE_ERROR_ORDER_NOT_SPECIFIED, "Order not specified" },
    { OABE_ERROR_INVALID_POLICY_TREE, "Invalid policy tree" },
    { OABE_ERROR_KEYGEN_FAILED, "Key generation failed" },
    { OABE_ERROR_NO_PLAINTEXT_SPECIFIED, "No plaintext specified" },
    { OABE_ERROR_INVALID_TAG_LENGTH, "Invalid tag length" },
    { OABE_ERROR_POLICY_NOT_SATISFIED, "Policy not satisfied" },
    { OABE_ERROR_UNKNOWN, "Unknown error" },
    { OABE_INVALID_INPUT_TYPE, "Invalid input type" }
};

const char* oabe_error_to_string(OABE_ERROR err) {
    for (size_t i = 0; i < sizeof(g_error_messages) / sizeof(g_error_messages[0]); i++) {
        if (g_error_messages[i].code == err) {
            return g_error_messages[i].message;
        }
    }
    return "Unknown error code";
}