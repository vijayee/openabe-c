///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// OpenABE C Example: ByteString Basics
///
/// This example demonstrates the fundamental ByteString operations:
/// - Creating ByteStrings
/// - Appending data
/// - Pack/unpack operations
/// - Hex encoding/decoding
/// - Cloning and comparison
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_bytestring.h"

int main(void) {
    printf("=== OpenABE C Example: ByteString Basics ===\n\n");

    /* Initialize the library */
    OABE_ERROR rc = oabe_init();
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to initialize library: %s\n", oabe_error_to_string(rc));
        return 1;
    }

    /*------------------------------------------------------------------------
     * Example 1: Creating ByteStrings
     *------------------------------------------------------------------------*/
    printf("1. Creating ByteStrings:\n");

    /* Create an empty ByteString */
    OABE_ByteString *bs1 = oabe_bytestring_new();
    if (!bs1) {
        fprintf(stderr, "Failed to create ByteString\n");
        oabe_shutdown();
        return 1;
    }
    printf("   Created empty ByteString, size: %zu\n", oabe_bytestring_get_size(bs1));

    /* Create from a C string */
    OABE_ByteString *bs2 = oabe_bytestring_new_from_string("Hello, OpenABE!");
    printf("   Created from string: \"%s\" (size: %zu)\n",
           "Hello, OpenABE!", oabe_bytestring_get_size(bs2));

    /* Create from raw bytes */
    uint8_t raw_data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    OABE_ByteString *bs3 = oabe_bytestring_new_from_data(raw_data, sizeof(raw_data));
    printf("   Created from raw data, size: %zu\n", oabe_bytestring_get_size(bs3));

    /*------------------------------------------------------------------------
     * Example 2: Appending data
     *------------------------------------------------------------------------*/
    printf("\n2. Appending data:\n");

    /* Append a string */
    rc = oabe_bytestring_append_string(bs1, "OpenABE");
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Append failed: %s\n", oabe_error_to_string(rc));
    }
    printf("   After append string: size = %zu\n", oabe_bytestring_get_size(bs1));

    /* Append raw bytes */
    uint8_t extra[] = {0x00, 0x01, 0x02};
    rc = oabe_bytestring_append_data(bs1, extra, sizeof(extra));
    printf("   After append data: size = %zu\n", oabe_bytestring_get_size(bs1));

    /* Append another ByteString */
    rc = oabe_bytestring_append_bytestring(bs1, bs2);
    printf("   After append ByteString: size = %zu\n", oabe_bytestring_get_size(bs1));

    /*------------------------------------------------------------------------
     * Example 3: Pack/Unpack operations
     *------------------------------------------------------------------------*/
    printf("\n3. Pack/Unpack operations:\n");

    OABE_ByteString *packed = oabe_bytestring_new();

    /* Pack various integer types (big-endian) */
    oabe_bytestring_pack8(packed, 0xAB);
    oabe_bytestring_pack16(packed, 0x1234);
    oabe_bytestring_pack32(packed, 0xDEADBEEF);
    oabe_bytestring_pack64(packed, 0x0123456789ABCDEFULL);

    printf("   Packed size: %zu bytes\n", oabe_bytestring_get_size(packed));
    printf("   Packed data: ");
    char *hex = oabe_bytestring_to_hex(packed);
    printf("%s\n", hex);
    oabe_free(hex);

    /* Unpack the values */
    size_t index = 0;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    oabe_bytestring_unpack8(packed, &index, &u8);
    oabe_bytestring_unpack16(packed, &index, &u16);
    oabe_bytestring_unpack32(packed, &index, &u32);
    oabe_bytestring_unpack64(packed, &index, &u64);

    printf("   Unpacked: u8=0x%02X, u16=0x%04X, u32=0x%08X, u64=0x%016llX\n",
           u8, u16, u32, (unsigned long long)u64);

    oabe_bytestring_free(packed);

    /*------------------------------------------------------------------------
     * Example 4: Hex encoding
     *------------------------------------------------------------------------*/
    printf("\n4. Hex encoding/decoding:\n");

    /* Convert to hex (uppercase) */
    char *hex_upper = oabe_bytestring_to_hex(bs3);
    printf("   Uppercase hex: %s\n", hex_upper);

    /* Convert to hex (lowercase) */
    char *hex_lower = oabe_bytestring_to_lower_hex(bs3);
    printf("   Lowercase hex: %s\n", hex_lower);

    /* Create from hex string */
    OABE_ByteString *from_hex = oabe_bytestring_new_from_hex("CAFEBABE42");
    char *hex_result = oabe_bytestring_to_hex(from_hex);
    printf("   From hex string 'CAFEBABE42': %s\n", hex_result);

    oabe_free(hex_upper);
    oabe_free(hex_lower);
    oabe_free(hex_result);
    oabe_bytestring_free(from_hex);

    /*------------------------------------------------------------------------
     * Example 5: Cloning and comparison
     *------------------------------------------------------------------------*/
    printf("\n5. Cloning and comparison:\n");

    /* Clone a ByteString */
    OABE_ByteString *bs2_clone = oabe_bytestring_clone(bs2);
    printf("   Original size: %zu, Clone size: %zu\n",
           oabe_bytestring_get_size(bs2), oabe_bytestring_get_size(bs2_clone));

    /* Compare ByteStrings */
    bool equal = oabe_bytestring_equals(bs2, bs2_clone);
    printf("   Clone equals original: %s\n", equal ? "true" : "false");

    /* Modify clone and compare again */
    oabe_bytestring_append_byte(bs2_clone, 0x00);
    equal = oabe_bytestring_equals(bs2, bs2_clone);
    printf("   After modification, equals: %s\n", equal ? "true" : "false");

    /*------------------------------------------------------------------------
     * Example 6: Getting data and subsets
     *------------------------------------------------------------------------*/
    printf("\n6. Accessing data:\n");

    /* Get pointer to internal data */
    const uint8_t *ptr = oabe_bytestring_get_const_ptr(bs2);
    printf("   First 5 bytes of bs2: ");
    for (size_t i = 0; i < 5 && i < oabe_bytestring_get_size(bs2); i++) {
        printf("%02X ", ptr[i]);
    }
    printf("\n");

    /* Get a subset */
    OABE_ByteString *subset = NULL;
    rc = oabe_bytestring_get_subset(bs2, 0, 5, &subset);
    if (rc == OABE_SUCCESS && subset) {
        char *subset_hex = oabe_bytestring_to_hex(subset);
        printf("   Subset (first 5 bytes): %s\n", subset_hex);
        oabe_free(subset_hex);
        oabe_bytestring_free(subset);
    }

    /*------------------------------------------------------------------------
     * Cleanup
     *------------------------------------------------------------------------*/
    printf("\n7. Cleanup:\n");

    oabe_bytestring_free(bs1);
    oabe_bytestring_free(bs2);
    oabe_bytestring_free(bs2_clone);
    oabe_bytestring_free(bs3);

    printf("   All ByteStrings freed.\n");

    /* Shutdown library */
    oabe_shutdown();
    printf("   Library shutdown complete.\n");

    printf("\n=== Example completed successfully ===\n");
    return 0;
}