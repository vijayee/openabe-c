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
/// \file   oabe_bytestring.h
///
/// \brief  ByteString container for OpenABE C implementation.
///         Equivalent to OpenABEByteString in C++.
///

#ifndef OABE_BYTESTRING_H
#define OABE_BYTESTRING_H

#include "oabe_types.h"
#include "oabe_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * ByteString Structure
 *============================================================================*/

/**
 * ByteString structure - a dynamic byte array.
 * Can hold arbitrary bytes including null (0) characters.
 */
typedef struct OABE_ByteString {
    OABE_Object base;          /* Base object for reference counting */
    uint8_t *data;              /* Byte data */
    size_t size;                /* Current size */
    size_t capacity;            /* Allocated capacity */
} OABE_ByteString;

/*============================================================================
 * ByteString VTable
 *============================================================================*/

/**
 * Get the vtable for OABE_ByteString.
 */
const OABE_ObjectVTable* oabe_bytestring_vtable(void);

/*============================================================================
 * ByteString Functions
 *============================================================================*/

/**
 * Create a new empty ByteString.
 * @return Pointer to new ByteString, or NULL on failure
 */
OABE_ByteString* oabe_bytestring_new(void);

/**
 * Create a new ByteString with initial capacity.
 * @param initial_capacity Initial capacity in bytes
 * @return Pointer to new ByteString, or NULL on failure
 */
OABE_ByteString* oabe_bytestring_new_with_capacity(size_t initial_capacity);

/**
 * Create a ByteString from existing data.
 * @param data Pointer to data
 * @param len Length of data
 * @return Pointer to new ByteString, or NULL on failure
 */
OABE_ByteString* oabe_bytestring_new_from_data(const uint8_t *data, size_t len);

/**
 * Create a ByteString from a C string.
 * @param str Null-terminated string
 * @return Pointer to new ByteString, or NULL on failure
 */
OABE_ByteString* oabe_bytestring_new_from_string(const char *str);

/**
 * Create a ByteString from hex string.
 * @param hex Hex string (lowercase or uppercase)
 * @return Pointer to new ByteString, or NULL on failure or invalid input
 */
OABE_ByteString* oabe_bytestring_new_from_hex(const char *hex);

/**
 * Free a ByteString (decrements ref count, destroys if zero).
 * @param bs ByteString to dereference
 */
void oabe_bytestring_free(OABE_ByteString *bs);

/**
 * Add a reference to a ByteString.
 * @param bs ByteString
 * @return The same ByteString (for convenience)
 */
OABE_ByteString* oabe_bytestring_addref(OABE_ByteString *bs);

/**
 * Clone a ByteString.
 * @param bs ByteString to clone
 * @return Pointer to cloned ByteString, or NULL on failure
 */
OABE_ByteString* oabe_bytestring_clone(const OABE_ByteString *bs);

/*============================================================================
 * ByteString Modification Functions
 *============================================================================*/

/**
 * Clear a ByteString (sets size to 0, but keeps capacity).
 * @param bs ByteString
 */
void oabe_bytestring_clear(OABE_ByteString *bs);

/**
 * Zeroize and clear a ByteString.
 * Securely zeros memory before clearing.
 * @param bs ByteString
 */
void oabe_bytestring_zeroize(OABE_ByteString *bs);

/**
 * Append a byte to a ByteString.
 * @param bs ByteString
 * @param byte Byte to append
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_append_byte(OABE_ByteString *bs, uint8_t byte);

/**
 * Append data to a ByteString.
 * @param bs ByteString
 * @param data Data to append
 * @param len Length of data
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_append_data(OABE_ByteString *bs, const uint8_t *data, size_t len);

/**
 * Append another ByteString to this one.
 * @param bs ByteString
 * @param other ByteString to append
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_append_bytestring(OABE_ByteString *bs, const OABE_ByteString *other);

/**
 * Append a C string to a ByteString.
 * @param bs ByteString
 * @param str Null-terminated string
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_append_string(OABE_ByteString *bs, const char *str);

/**
 * Prepend a byte to a ByteString.
 * @param bs ByteString
 * @param byte Byte to prepend
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_prepend_byte(OABE_ByteString *bs, uint8_t byte);

/**
 * Insert data at a position.
 * @param bs ByteString
 * @param pos Position to insert at
 * @param data Data to insert
 * @param len Length of data
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_insert(OABE_ByteString *bs, size_t pos, const uint8_t *data, size_t len);

/**
 * XOR two ByteStrings in place (bs ^= other).
 * Both must have the same size.
 * @param bs ByteString (modified)
 * @param other ByteString to XOR with
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_xor(OABE_ByteString *bs, const OABE_ByteString *other);

/*============================================================================
 * ByteString Packing Functions
 *============================================================================*/

/**
 * Pack an 8-bit value.
 * @param bs ByteString
 * @param value Value to pack
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_pack8(OABE_ByteString *bs, uint8_t value);

/**
 * Pack a 16-bit value (big endian).
 * @param bs ByteString
 * @param value Value to pack
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_pack16(OABE_ByteString *bs, uint16_t value);

/**
 * Pack a 32-bit value (big endian).
 * @param bs ByteString
 * @param value Value to pack
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_pack32(OABE_ByteString *bs, uint32_t value);

/**
 * Pack a 64-bit value (big endian).
 * @param bs ByteString
 * @param value Value to pack
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_pack64(OABE_ByteString *bs, uint64_t value);

/**
 * Pack data with length prefix.
 * @param bs ByteString
 * @param data Data to pack
 * @param len Length of data
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_pack_data(OABE_ByteString *bs, const uint8_t *data, size_t len);

/**
 * Pack another ByteString with length prefix.
 * @param bs ByteString
 * @param other ByteString to pack
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_pack_bytestring(OABE_ByteString *bs, const OABE_ByteString *other);

/**
 * Smart pack - uses smallest size for length prefix.
 * @param bs ByteString
 * @param other ByteString to pack
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_smart_pack(OABE_ByteString *bs, const OABE_ByteString *other);

/*============================================================================
 * ByteString Unpacking Functions
 *============================================================================*/

/**
 * Unpack an 8-bit value.
 * @param bs ByteString
 * @param index Pointer to current index (updated)
 * @param value Output value
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_unpack8(const OABE_ByteString *bs, size_t *index, uint8_t *value);

/**
 * Unpack a 16-bit value (big endian).
 * @param bs ByteString
 * @param index Pointer to current index (updated)
 * @param value Output value
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_unpack16(const OABE_ByteString *bs, size_t *index, uint16_t *value);

/**
 * Unpack a 32-bit value (big endian).
 * @param bs ByteString
 * @param index Pointer to current index (updated)
 * @param value Output value
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_unpack32(const OABE_ByteString *bs, size_t *index, uint32_t *value);

/**
 * Unpack a 64-bit value (big endian).
 * @param bs ByteString
 * @param index Pointer to current index (updated)
 * @param value Output value
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_unpack64(const OABE_ByteString *bs, size_t *index, uint64_t *value);

/**
 * Smart unpack - handles PACK_8, PACK_16, PACK_32 prefixes.
 * @param bs ByteString
 * @param index Pointer to current index (updated)
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_smart_unpack(const OABE_ByteString *bs, size_t *index, OABE_ByteString **result);

/**
 * Unpack data with 32-bit length prefix.
 * @param bs ByteString
 * @param index Pointer to current index (updated)
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_unpack(const OABE_ByteString *bs, size_t *index, OABE_ByteString **result);

/*============================================================================
 * ByteString Access Functions
 *============================================================================*/

/**
 * Get a byte at an index.
 * @param bs ByteString
 * @param index Index
 * @return Byte value, or 0 if out of bounds
 */
uint8_t oabe_bytestring_at(const OABE_ByteString *bs, size_t index);

/**
 * Set a byte at an index.
 * @param bs ByteString
 * @param index Index
 * @param value Byte value
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_set(OABE_ByteString *bs, size_t index, uint8_t value);

/**
 * Get internal pointer to data (mutable).
 * @param bs ByteString
 * @return Pointer to data
 */
uint8_t* oabe_bytestring_get_ptr(OABE_ByteString *bs);

/**
 * Get internal pointer to data (const).
 * @param bs ByteString
 * @return Pointer to data
 */
const uint8_t* oabe_bytestring_get_const_ptr(const OABE_ByteString *bs);

/**
 * Get a subset of bytes.
 * @param bs ByteString
 * @param start Starting position
 * @param len Number of bytes
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_get_subset(const OABE_ByteString *bs, size_t start, size_t len, OABE_ByteString **result);

/**
 * Get size of ByteString.
 * @param bs ByteString
 * @return Size in bytes
 */
size_t oabe_bytestring_get_size(const OABE_ByteString *bs);

/**
 * Check if ByteString is empty.
 * @param bs ByteString
 * @return true if empty, false otherwise
 */
bool oabe_bytestring_is_empty(const OABE_ByteString *bs);

/*============================================================================
 * ByteString Conversion Functions
 *============================================================================*/

/**
 * Convert ByteString to hex string.
 * Caller must free returned string.
 * @param bs ByteString
 * @return Hex string (uppercase), or NULL on failure
 */
char* oabe_bytestring_to_hex(const OABE_ByteString *bs);

/**
 * Convert ByteString to lower hex string.
 * Caller must free returned string.
 * @param bs ByteString
 * @return Hex string (lowercase), or NULL on failure
 */
char* oabe_bytestring_to_lower_hex(const OABE_ByteString *bs);

/**
 * Convert ByteString to a C string (null-terminated).
 * Caller must free returned string.
 * @param bs ByteString
 * @return C string, or NULL on failure
 */
char* oabe_bytestring_to_string(const OABE_ByteString *bs);

/**
 * Load ByteString from hex string.
 * @param bs ByteString (modified)
 * @param hex Hex string
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_from_hex(OABE_ByteString *bs, const char *hex);

/**
 * Load ByteString from C string.
 * @param bs ByteString (modified)
 * @param str Null-terminated string
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_from_string(OABE_ByteString *bs, const char *str);

/*============================================================================
 * ByteString Serialization Functions
 *============================================================================*/

/**
 * Serialize ByteString with type header.
 * @param bs ByteString to serialize
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_serialize(const OABE_ByteString *bs, OABE_ByteString **result);

/**
 * Deserialize ByteString with type header.
 * @param bs Input ByteString
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_bytestring_deserialize(const OABE_ByteString *bs, OABE_ByteString **result);

/*============================================================================
 * ByteString Comparison Functions
 *============================================================================*/

/**
 * Compare two ByteStrings (constant time).
 * @param a First ByteString
 * @param b Second ByteString
 * @return true if equal, false otherwise
 */
bool oabe_bytestring_equals(const OABE_ByteString *a, const OABE_ByteString *b);

/**
 * Compare ByteString with data (constant time).
 * @param bs ByteString
 * @param data Data
 * @param len Length of data
 * @return true if equal, false otherwise
 */
bool oabe_bytestring_equals_data(const OABE_ByteString *bs, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* OABE_BYTESTRING_H */