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
/// \file   example_cp_abe.c
///
/// \brief  CP-ABE example for OpenABE C implementation.
///

#include <stdio.h>
#include <string.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_memory.h"
#include "openabe/oabe_bytestring.h"
#include "openabe/oabe_zml.h"
#include "openabe/oabe_crypto.h"

/* Helper function to print hex data */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Helper function to print ByteString */
static void print_bytestring(const char *label, const OABE_ByteString *bs) {
    char *hex = oabe_bytestring_to_hex(bs);
    if (hex) {
        printf("%s: %s\n", label, hex);
        oabe_free(hex);
    }
}

int main(void) {
    printf("OpenABE C Library - CP-ABE Example\n");
    printf("==================================\n\n");

    /* Initialize the library */
    printf("1. Initializing library...\n");
    if (oabe_init() != OABE_SUCCESS) {
        fprintf(stderr, "Failed to initialize OpenABE library\n");
        return 1;
    }
    printf("   Library initialized successfully\n");
    printf("   Version: %s\n\n", oabe_get_library_version_string());

    /* Test ByteString operations */
    printf("2. Testing ByteString operations...\n");
    {
        /* Create a ByteString from a string */
        OABE_ByteString *bs = oabe_bytestring_new_from_string("Hello, OpenABE!");
        if (!bs) {
            fprintf(stderr, "Failed to create ByteString\n");
            oabe_shutdown();
            return 1;
        }

        printf("   Created ByteString: size=%zu\n", oabe_bytestring_get_size(bs));

        /* Convert to hex */
        char *hex = oabe_bytestring_to_hex(bs);
        printf("   Hex: %s\n", hex);
        oabe_free(hex);

        /* Clone the ByteString */
        OABE_ByteString *clone = oabe_bytestring_clone(bs);
        if (clone) {
            printf("   Cloned ByteString successfully\n");
            printf("   Original equals clone: %s\n",
                   oabe_bytestring_equals(bs, clone) ? "true" : "false");
            oabe_bytestring_free(clone);
        }

        /* Test packing */
        oabe_bytestring_pack32(bs, 0xDEADBEEF);
        printf("   After packing: size=%zu\n", oabe_bytestring_get_size(bs));

        oabe_bytestring_free(bs);
    }
    printf("\n");

    /* Test string vector operations */
    printf("3. Testing StringVector operations...\n");
    {
        OABE_StringVector *vec = oabe_strvec_new(0);
        if (!vec) {
            fprintf(stderr, "Failed to create StringVector\n");
            oabe_shutdown();
            return 1;
        }

        oabe_strvec_append(vec, "attribute1");
        oabe_strvec_append(vec, "attribute2");
        oabe_strvec_append(vec, "attribute3");

        printf("   Created StringVector with %zu elements\n", vec->size);
        for (size_t i = 0; i < vec->size; i++) {
            printf("   [%zu]: %s\n", i, oabe_strvec_get(vec, i));
        }

        oabe_strvec_free(vec);
    }
    printf("\n");

    /* Test string map operations */
    printf("4. Testing StringMap operations...\n");
    {
        OABE_StringMap *map = oabe_strmap_new(0);
        if (!map) {
            fprintf(stderr, "Failed to create StringMap\n");
            oabe_shutdown();
            return 1;
        }

        int value1 = 42, value2 = 100;
        oabe_strmap_insert(map, "key1", &value1);
        oabe_strmap_insert(map, "key2", &value2);

        printf("   Created StringMap with %zu entries\n", map->size);
        printf("   key1 -> %d\n", *(int*)oabe_strmap_get(map, "key1"));
        printf("   key2 -> %d\n", *(int*)oabe_strmap_get(map, "key2"));
        printf("   Contains 'key1': %s\n", oabe_strmap_contains(map, "key1") ? "true" : "false");
        printf("   Contains 'unknown': %s\n", oabe_strmap_contains(map, "unknown") ? "true" : "false");

        oabe_strmap_free(map);
    }
    printf("\n");

    /* Test type conversions */
    printf("5. Testing type conversions...\n");
    {
        printf("   Curve NIST_P256 -> string: %s\n", oabe_curve_id_to_string(OABE_CURVE_NIST_P256));
        printf("   Curve BN_P254 -> string: %s\n", oabe_curve_id_to_string(OABE_CURVE_BN_P254));
        printf("   String 'NIST_P256' -> curve: %d\n", oabe_curve_id_from_string("NIST_P256"));
        printf("   Scheme CP_WATERS -> string: %s\n", oabe_scheme_to_string(OABE_SCHEME_CP_WATERS));
        printf("   String 'KP_GPSW' -> scheme: %d\n", oabe_scheme_from_string("KP_GPSW"));
    }
    printf("\n");

    /* Test error messages */
    printf("6. Testing error messages...\n");
    {
        printf("   OABE_SUCCESS: %s\n", oabe_error_to_string(OABE_SUCCESS));
        printf("   OABE_ERROR_INVALID_INPUT: %s\n", oabe_error_to_string(OABE_ERROR_INVALID_INPUT));
        printf("   OABE_ERROR_OUT_OF_MEMORY: %s\n", oabe_error_to_string(OABE_ERROR_OUT_OF_MEMORY));
        printf("   OABE_ERROR_DECRYPTION_FAILED: %s\n", oabe_error_to_string(OABE_ERROR_DECRYPTION_FAILED));
    }
    printf("\n");

    /* Test ByteString serialization */
    printf("7. Testing ByteString serialization...\n");
    {
        OABE_ByteString *original = oabe_bytestring_new_from_string("Test data for serialization");
        OABE_ByteString *serialized = NULL;
        OABE_ByteString *deserialized = NULL;

        if (oabe_bytestring_serialize(original, &serialized) == OABE_SUCCESS) {
            printf("   Serialized size: %zu\n", oabe_bytestring_get_size(serialized));

            if (oabe_bytestring_deserialize(serialized, &deserialized) == OABE_SUCCESS) {
                printf("   Deserialized equals original: %s\n",
                       oabe_bytestring_equals(original, deserialized) ? "true" : "false");
                oabe_bytestring_free(deserialized);
            }
            oabe_bytestring_free(serialized);
        }
        oabe_bytestring_free(original);
    }
    printf("\n");

    /* Test reference counting */
    printf("8. Testing reference counting...\n");
    {
        OABE_ByteString *bs = oabe_bytestring_new();
        printf("   Initial refcount: %u\n", oabe_get_refcount(bs));

        oabe_bytestring_addref(bs);
        printf("   After addref: %u\n", oabe_get_refcount(bs));

        oabe_bytestring_free(bs);  /* Decrements refcount */
        printf("   After free (once): %u\n", oabe_get_refcount(bs));

        oabe_bytestring_free(bs);  /* Actually frees */
        printf("   After free (twice): object freed\n");
    }
    printf("\n");

    /* Cleanup */
    printf("9. Shutting down library...\n");
    oabe_shutdown();
    printf("   Library shut down successfully\n\n");

    printf("Example completed successfully!\n");
    return 0;
}