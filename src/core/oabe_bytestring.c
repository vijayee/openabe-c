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
/// \file   oabe_bytestring.c
///
/// \brief  ByteString implementation for OpenABE C.
///

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "openabe/oabe_bytestring.h"

#define OABE_BYTESTRING_DEFAULT_CAPACITY 64
#define HEX_CHARS "0123456789abcdefABCDEF"

/*============================================================================
 * Static VTable Functions
 *============================================================================*/

static void oabe_bytestring_destroy(void *self) {
    OABE_ByteString *bs = (OABE_ByteString *)self;
    if (bs) {
        if (bs->data) {
            oabe_zeroize(bs->data, bs->capacity);
            oabe_free(bs->data);
        }
        oabe_free(bs);
    }
}

static void* oabe_bytestring_clone_impl(const void *self) {
    const OABE_ByteString *bs = (const OABE_ByteString *)self;
    return oabe_bytestring_new_from_data(bs->data, bs->size);
}

static OABE_ERROR oabe_bytestring_serialize_impl(const void *self, OABE_ByteString *result) {
    const OABE_ByteString *bs = (const OABE_ByteString *)self;
    return oabe_bytestring_serialize(bs, &result);
}

static bool oabe_bytestring_is_equal_impl(const void *self, const void *other) {
    const OABE_ByteString *a = (const OABE_ByteString *)self;
    const OABE_ByteString *b = (const OABE_ByteString *)other;
    return oabe_bytestring_equals(a, b);
}

static const OABE_ObjectVTable g_bytestring_vtable = {
    .destroy = oabe_bytestring_destroy,
    .clone = oabe_bytestring_clone_impl,
    .serialize = oabe_bytestring_serialize_impl,
    .is_equal = oabe_bytestring_is_equal_impl
};

const OABE_ObjectVTable* oabe_bytestring_vtable(void) {
    return &g_bytestring_vtable;
}

/*============================================================================
 * ByteString Creation Functions
 *============================================================================*/

OABE_ByteString* oabe_bytestring_new(void) {
    return oabe_bytestring_new_with_capacity(OABE_BYTESTRING_DEFAULT_CAPACITY);
}

OABE_ByteString* oabe_bytestring_new_with_capacity(size_t initial_capacity) {
    OABE_ByteString *bs = (OABE_ByteString *)oabe_malloc(sizeof(OABE_ByteString));
    if (!bs) {
        return NULL;
    }

    if (initial_capacity == 0) {
        initial_capacity = OABE_BYTESTRING_DEFAULT_CAPACITY;
    }

    bs->data = (uint8_t *)oabe_malloc(initial_capacity);
    if (!bs->data) {
        oabe_free(bs);
        return NULL;
    }

    bs->size = 0;
    bs->capacity = initial_capacity;
    bs->base.vtable = &g_bytestring_vtable;
    bs->base.ref_count = 1;

    return bs;
}

OABE_ByteString* oabe_bytestring_new_from_data(const uint8_t *data, size_t len) {
    OABE_ByteString *bs = oabe_bytestring_new_with_capacity(len > 0 ? len : OABE_BYTESTRING_DEFAULT_CAPACITY);
    if (!bs) {
        return NULL;
    }

    if (len > 0 && data) {
        memcpy(bs->data, data, len);
        bs->size = len;
    }

    return bs;
}

OABE_ByteString* oabe_bytestring_new_from_string(const char *str) {
    if (!str) {
        return oabe_bytestring_new();
    }
    size_t len = strlen(str);
    return oabe_bytestring_new_from_data((const uint8_t *)str, len);
}

OABE_ByteString* oabe_bytestring_new_from_hex(const char *hex) {
    if (!hex) {
        return NULL;
    }

    OABE_ByteString *bs = oabe_bytestring_new();
    if (!bs) {
        return NULL;
    }

    OABE_ERROR rc = oabe_bytestring_from_hex(bs, hex);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(bs);
        return NULL;
    }

    return bs;
}

/*============================================================================
 * ByteString Reference Counting
 *============================================================================*/

void oabe_bytestring_free(OABE_ByteString *bs) {
    if (bs) {
        OABE_DEREF(bs);
    }
}

OABE_ByteString* oabe_bytestring_addref(OABE_ByteString *bs) {
    if (bs) {
        OABE_ADDREF(bs);
    }
    return bs;
}

OABE_ByteString* oabe_bytestring_clone(const OABE_ByteString *bs) {
    if (!bs) {
        return NULL;
    }
    return oabe_bytestring_new_from_data(bs->data, bs->size);
}

/*============================================================================
 * ByteString Modification Functions
 *============================================================================*/

static OABE_ERROR oabe_bytestring_ensure_capacity(OABE_ByteString *bs, size_t needed) {
    if (bs->capacity >= needed) {
        return OABE_SUCCESS;
    }

    size_t new_capacity = bs->capacity * 2;
    if (new_capacity < needed) {
        new_capacity = needed;
    }

    uint8_t *new_data = (uint8_t *)oabe_realloc(bs->data, new_capacity);
    if (!new_data) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    bs->data = new_data;
    bs->capacity = new_capacity;
    return OABE_SUCCESS;
}

void oabe_bytestring_clear(OABE_ByteString *bs) {
    if (bs) {
        bs->size = 0;
    }
}

void oabe_bytestring_zeroize(OABE_ByteString *bs) {
    if (bs) {
        if (bs->data && bs->size > 0) {
            oabe_zeroize(bs->data, bs->size);
        }
        bs->size = 0;
    }
}

OABE_ERROR oabe_bytestring_append_byte(OABE_ByteString *bs, uint8_t byte) {
    if (!bs) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ERROR rc = oabe_bytestring_ensure_capacity(bs, bs->size + 1);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    bs->data[bs->size++] = byte;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_append_data(OABE_ByteString *bs, const uint8_t *data, size_t len) {
    if (!bs || (!data && len > 0)) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (len == 0) {
        return OABE_SUCCESS;
    }

    OABE_ERROR rc = oabe_bytestring_ensure_capacity(bs, bs->size + len);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    memcpy(bs->data + bs->size, data, len);
    bs->size += len;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_append_bytestring(OABE_ByteString *bs, const OABE_ByteString *other) {
    if (!bs || !other) {
        return OABE_ERROR_INVALID_INPUT;
    }
    return oabe_bytestring_append_data(bs, other->data, other->size);
}

OABE_ERROR oabe_bytestring_append_string(OABE_ByteString *bs, const char *str) {
    if (!bs || !str) {
        return OABE_ERROR_INVALID_INPUT;
    }
    return oabe_bytestring_append_data(bs, (const uint8_t *)str, strlen(str));
}

OABE_ERROR oabe_bytestring_prepend_byte(OABE_ByteString *bs, uint8_t byte) {
    if (!bs) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ERROR rc = oabe_bytestring_ensure_capacity(bs, bs->size + 1);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    memmove(bs->data + 1, bs->data, bs->size);
    bs->data[0] = byte;
    bs->size++;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_insert(OABE_ByteString *bs, size_t pos, const uint8_t *data, size_t len) {
    if (!bs || (!data && len > 0) || pos > bs->size) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (len == 0) {
        return OABE_SUCCESS;
    }

    OABE_ERROR rc = oabe_bytestring_ensure_capacity(bs, bs->size + len);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    if (pos < bs->size) {
        memmove(bs->data + pos + len, bs->data + pos, bs->size - pos);
    }
    memcpy(bs->data + pos, data, len);
    bs->size += len;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_xor(OABE_ByteString *bs, const OABE_ByteString *other) {
    if (!bs || !other) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (bs->size != other->size) {
        return OABE_ERROR_INVALID_INPUT;
    }

    for (size_t i = 0; i < bs->size; i++) {
        bs->data[i] ^= other->data[i];
    }

    return OABE_SUCCESS;
}

/*============================================================================
 * ByteString Packing Functions
 *============================================================================*/

OABE_ERROR oabe_bytestring_pack8(OABE_ByteString *bs, uint8_t value) {
    return oabe_bytestring_append_byte(bs, value);
}

OABE_ERROR oabe_bytestring_pack16(OABE_ByteString *bs, uint16_t value) {
    uint8_t buf[2];
    buf[0] = (value >> 8) & 0xFF;
    buf[1] = value & 0xFF;
    return oabe_bytestring_append_data(bs, buf, 2);
}

OABE_ERROR oabe_bytestring_pack32(OABE_ByteString *bs, uint32_t value) {
    uint8_t buf[4];
    buf[0] = (value >> 24) & 0xFF;
    buf[1] = (value >> 16) & 0xFF;
    buf[2] = (value >> 8) & 0xFF;
    buf[3] = value & 0xFF;
    return oabe_bytestring_append_data(bs, buf, 4);
}

OABE_ERROR oabe_bytestring_pack64(OABE_ByteString *bs, uint64_t value) {
    uint8_t buf[8];
    buf[0] = (value >> 56) & 0xFF;
    buf[1] = (value >> 48) & 0xFF;
    buf[2] = (value >> 40) & 0xFF;
    buf[3] = (value >> 32) & 0xFF;
    buf[4] = (value >> 24) & 0xFF;
    buf[5] = (value >> 16) & 0xFF;
    buf[6] = (value >> 8) & 0xFF;
    buf[7] = value & 0xFF;
    return oabe_bytestring_append_data(bs, buf, 8);
}

OABE_ERROR oabe_bytestring_pack_data(OABE_ByteString *bs, const uint8_t *data, size_t len) {
    OABE_ERROR rc = oabe_bytestring_pack32(bs, (uint32_t)len);
    if (rc != OABE_SUCCESS) {
        return rc;
    }
    return oabe_bytestring_append_data(bs, data, len);
}

OABE_ERROR oabe_bytestring_pack_bytestring(OABE_ByteString *bs, const OABE_ByteString *other) {
    if (!other) {
        return OABE_ERROR_INVALID_INPUT;
    }
    return oabe_bytestring_pack_data(bs, other->data, other->size);
}

OABE_ERROR oabe_bytestring_smart_pack(OABE_ByteString *bs, const OABE_ByteString *other) {
    if (!bs || !other || other->size == 0) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_ERROR rc;

    if (other->size > UINT16_MAX) {
        /* Pack as 32-bit */
        rc = oabe_bytestring_append_byte(bs, OABE_PACK_32);
        if (rc != OABE_SUCCESS) return rc;
        rc = oabe_bytestring_pack32(bs, (uint32_t)other->size);
    } else if (other->size > UINT8_MAX) {
        /* Pack as 16-bit */
        rc = oabe_bytestring_append_byte(bs, OABE_PACK_16);
        if (rc != OABE_SUCCESS) return rc;
        rc = oabe_bytestring_pack16(bs, (uint16_t)other->size);
    } else {
        /* Pack as 8-bit */
        rc = oabe_bytestring_append_byte(bs, OABE_PACK_8);
        if (rc != OABE_SUCCESS) return rc;
        rc = oabe_bytestring_pack8(bs, (uint8_t)other->size);
    }

    if (rc != OABE_SUCCESS) {
        return rc;
    }

    return oabe_bytestring_append_data(bs, other->data, other->size);
}

/*============================================================================
 * ByteString Unpacking Functions
 *============================================================================*/

OABE_ERROR oabe_bytestring_unpack8(const OABE_ByteString *bs, size_t *index, uint8_t *value) {
    if (!bs || !index || !value) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (*index >= bs->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }
    *value = bs->data[(*index)++];
    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_unpack16(const OABE_ByteString *bs, size_t *index, uint16_t *value) {
    if (!bs || !index || !value) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (*index + 2 > bs->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }
    *value = ((uint16_t)bs->data[*index] << 8) | bs->data[*index + 1];
    *index += 2;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_unpack32(const OABE_ByteString *bs, size_t *index, uint32_t *value) {
    if (!bs || !index || !value) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (*index + 4 > bs->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }
    *value = ((uint32_t)bs->data[*index] << 24) |
             ((uint32_t)bs->data[*index + 1] << 16) |
             ((uint32_t)bs->data[*index + 2] << 8) |
             (uint32_t)bs->data[*index + 3];
    *index += 4;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_unpack64(const OABE_ByteString *bs, size_t *index, uint64_t *value) {
    if (!bs || !index || !value) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (*index + 8 > bs->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }
    *value = ((uint64_t)bs->data[*index] << 56) |
             ((uint64_t)bs->data[*index + 1] << 48) |
             ((uint64_t)bs->data[*index + 2] << 40) |
             ((uint64_t)bs->data[*index + 3] << 32) |
             ((uint64_t)bs->data[*index + 4] << 24) |
             ((uint64_t)bs->data[*index + 5] << 16) |
             ((uint64_t)bs->data[*index + 6] << 8) |
             (uint64_t)bs->data[*index + 7];
    *index += 8;
    return OABE_SUCCESS;
}

static OABE_ERROR unpack_with_len(const OABE_ByteString *bs, size_t *index, size_t len, OABE_ByteString **result) {
    if (!bs || !index || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (*index + len > bs->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }

    *result = oabe_bytestring_new_from_data(bs->data + *index, len);
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    *index += len;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_smart_unpack(const OABE_ByteString *bs, size_t *index, OABE_ByteString **result) {
    if (!bs || !index || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    uint8_t pack_type;
    OABE_ERROR rc = oabe_bytestring_unpack8(bs, index, &pack_type);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    size_t len;
    uint8_t len8;
    uint16_t len16;
    uint32_t len32;

    switch (pack_type) {
        case OABE_PACK_8:
            rc = oabe_bytestring_unpack8(bs, index, &len8);
            len = len8;
            break;
        case OABE_PACK_16:
            rc = oabe_bytestring_unpack16(bs, index, &len16);
            len = len16;
            break;
        case OABE_PACK_32:
            rc = oabe_bytestring_unpack32(bs, index, &len32);
            len = len32;
            break;
        default:
            return OABE_ERROR_INVALID_PACK_TYPE;
    }

    if (rc != OABE_SUCCESS) {
        return rc;
    }

    return unpack_with_len(bs, index, len, result);
}

OABE_ERROR oabe_bytestring_unpack(const OABE_ByteString *bs, size_t *index, OABE_ByteString **result) {
    if (!bs || !index || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    uint32_t len;
    OABE_ERROR rc = oabe_bytestring_unpack32(bs, index, &len);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    return unpack_with_len(bs, index, len, result);
}

/*============================================================================
 * ByteString Access Functions
 *============================================================================*/

uint8_t oabe_bytestring_at(const OABE_ByteString *bs, size_t index) {
    if (!bs || index >= bs->size) {
        return 0;
    }
    return bs->data[index];
}

OABE_ERROR oabe_bytestring_set(OABE_ByteString *bs, size_t index, uint8_t value) {
    if (!bs) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (index >= bs->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }
    bs->data[index] = value;
    return OABE_SUCCESS;
}

uint8_t* oabe_bytestring_get_ptr(OABE_ByteString *bs) {
    return bs ? bs->data : NULL;
}

const uint8_t* oabe_bytestring_get_const_ptr(const OABE_ByteString *bs) {
    return bs ? bs->data : NULL;
}

OABE_ERROR oabe_bytestring_get_subset(const OABE_ByteString *bs, size_t start, size_t len, OABE_ByteString **result) {
    if (!bs || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }
    if (start + len > bs->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }

    *result = oabe_bytestring_new_from_data(bs->data + start, len);
    return *result ? OABE_SUCCESS : OABE_ERROR_OUT_OF_MEMORY;
}

size_t oabe_bytestring_get_size(const OABE_ByteString *bs) {
    return bs ? bs->size : 0;
}

bool oabe_bytestring_is_empty(const OABE_ByteString *bs) {
    return bs ? (bs->size == 0) : true;
}

/*============================================================================
 * ByteString Conversion Functions
 *============================================================================*/

char* oabe_bytestring_to_hex(const OABE_ByteString *bs) {
    if (!bs) {
        return NULL;
    }

    char *hex = (char *)oabe_malloc(bs->size * 2 + 1);
    if (!hex) {
        return NULL;
    }

    for (size_t i = 0; i < bs->size; i++) {
        sprintf(hex + i * 2, "%02X", bs->data[i]);
    }
    hex[bs->size * 2] = '\0';

    return hex;
}

char* oabe_bytestring_to_lower_hex(const OABE_ByteString *bs) {
    if (!bs) {
        return NULL;
    }

    char *hex = (char *)oabe_malloc(bs->size * 2 + 1);
    if (!hex) {
        return NULL;
    }

    for (size_t i = 0; i < bs->size; i++) {
        sprintf(hex + i * 2, "%02x", bs->data[i]);
    }
    hex[bs->size * 2] = '\0';

    return hex;
}

char* oabe_bytestring_to_string(const OABE_ByteString *bs) {
    if (!bs) {
        return NULL;
    }

    char *str = (char *)oabe_malloc(bs->size + 1);
    if (!str) {
        return NULL;
    }

    memcpy(str, bs->data, bs->size);
    str[bs->size] = '\0';

    return str;
}

OABE_ERROR oabe_bytestring_from_hex(OABE_ByteString *bs, const char *hex) {
    if (!bs || !hex) {
        return OABE_ERROR_INVALID_INPUT;
    }

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Check for invalid characters */
    for (size_t i = 0; i < hex_len; i++) {
        if (!isxdigit((unsigned char)hex[i])) {
            return OABE_ERROR_INVALID_INPUT;
        }
    }

    size_t len = hex_len / 2;
    OABE_ERROR rc = oabe_bytestring_ensure_capacity(bs, len);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    bs->size = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return OABE_ERROR_INVALID_INPUT;
        }
        bs->data[bs->size++] = (uint8_t)byte;
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_from_string(OABE_ByteString *bs, const char *str) {
    if (!bs || !str) {
        return OABE_ERROR_INVALID_INPUT;
    }

    size_t len = strlen(str);
    OABE_ERROR rc = oabe_bytestring_ensure_capacity(bs, len);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    memcpy(bs->data, str, len);
    bs->size = len;

    return OABE_SUCCESS;
}

/*============================================================================
 * ByteString Serialization Functions
 *============================================================================*/

OABE_ERROR oabe_bytestring_serialize(const OABE_ByteString *bs, OABE_ByteString **result) {
    if (!bs || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_bytestring_new();
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ERROR rc = oabe_bytestring_pack32(*result, (uint32_t)bs->size);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    rc = oabe_bytestring_prepend_byte(*result, OABE_BYTESTRING_TYPE);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    rc = oabe_bytestring_append_data(*result, bs->data, bs->size);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_bytestring_deserialize(const OABE_ByteString *bs, OABE_ByteString **result) {
    if (!bs || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    size_t index = 0;
    uint8_t type;

    OABE_ERROR rc = oabe_bytestring_unpack8(bs, &index, &type);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    if (type != OABE_BYTESTRING_TYPE) {
        return OABE_ERROR_DESERIALIZATION_FAILED;
    }

    uint32_t len;
    rc = oabe_bytestring_unpack32(bs, &index, &len);
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    if (index + len != bs->size) {
        return OABE_ERROR_DESERIALIZATION_FAILED;
    }

    *result = oabe_bytestring_new_from_data(bs->data + index, len);
    return *result ? OABE_SUCCESS : OABE_ERROR_OUT_OF_MEMORY;
}

/*============================================================================
 * ByteString Comparison Functions
 *============================================================================*/

bool oabe_bytestring_equals(const OABE_ByteString *a, const OABE_ByteString *b) {
    if (!a || !b) {
        return a == b;  /* Both NULL -> true, one NULL -> false */
    }

    if (a->size != b->size) {
        return false;
    }

    /* Constant time comparison */
    uint8_t rc = 0;
    for (size_t i = 0; i < a->size; i++) {
        rc |= (a->data[i] ^ b->data[i]);
    }

    return rc == 0;
}

bool oabe_bytestring_equals_data(const OABE_ByteString *bs, const uint8_t *data, size_t len) {
    if (!bs || !data) {
        return false;
    }

    if (bs->size != len) {
        return false;
    }

    /* Constant time comparison */
    uint8_t rc = 0;
    for (size_t i = 0; i < bs->size; i++) {
        rc |= (bs->data[i] ^ data[i]);
    }

    return rc == 0;
}