///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// OpenABE C Example: AES-GCM Symmetric Encryption
///
/// This example demonstrates AES-GCM symmetric key encryption:
/// - Key generation
/// - Encryption with authentication
/// - Decryption and verification
/// - IV handling
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_context.h"
#include "openabe/oabe_zml.h"

int main(void) {
    printf("=== OpenABE C Example: AES-GCM Symmetric Encryption ===\n\n");

    /* Initialize the library */
    OABE_ERROR rc = oabe_init();
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to initialize library: %s\n", oabe_error_to_string(rc));
        return 1;
    }

    /*------------------------------------------------------------------------
     * Example 1: Creating AES context
     *------------------------------------------------------------------------*/
    printf("1. Creating AES-GCM context:\n");

    OABE_ContextAES *ctx = oabe_context_aes_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create AES context\n");
        oabe_shutdown();
        return 1;
    }
    printf("   Created AES-GCM context\n");

    /*------------------------------------------------------------------------
     * Example 2: Key generation
     *------------------------------------------------------------------------*/
    printf("\n2. Key generation:\n");

    /* Create RNG */
    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    if (!rng) {
        fprintf(stderr, "Failed to create RNG\n");
        oabe_context_aes_free(ctx);
        oabe_shutdown();
        return 1;
    }

    /* Generate a random 256-bit (32-byte) AES key */
    OABE_SymKey *key = oabe_symkey_new(32, rng);
    if (!key) {
        fprintf(stderr, "Failed to generate key\n");
        oabe_rng_free(rng);
        oabe_context_aes_free(ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Generated 256-bit AES key\n");

    /* Set the key in the context */
    rc = oabe_context_aes_set_key(ctx, key->key_bytes, key->key_len);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to set key: %s\n", oabe_error_to_string(rc));
        oabe_symkey_free(key);
        oabe_rng_free(rng);
        oabe_context_aes_free(ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Key set in context (%zu bytes)\n", key->key_len);

    /*------------------------------------------------------------------------
     * Example 3: Encryption
     *------------------------------------------------------------------------*/
    printf("\n3. Encryption:\n");

    /* Plaintext message */
    const char *plaintext = "This is a secret message for AES-GCM encryption!";
    size_t plaintext_len = strlen(plaintext);
    printf("   Plaintext: \"%s\"\n", plaintext);
    printf("   Plaintext length: %zu bytes\n", plaintext_len);

    /* Generate a random IV (12 bytes recommended for GCM) */
    uint8_t iv[12];
    rc = oabe_rng_bytes(rng, iv, sizeof(iv));
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate IV: %s\n", oabe_error_to_string(rc));
        oabe_symkey_free(key);
        oabe_rng_free(rng);
        oabe_context_aes_free(ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Generated 12-byte IV\n");

    /* Encrypt */
    OABE_ByteString *ciphertext = NULL;
    uint8_t tag[16];  /* GCM authentication tag */

    rc = oabe_context_aes_encrypt(ctx,
                                   (const uint8_t *)plaintext, plaintext_len,
                                   iv, sizeof(iv),
                                   &ciphertext, tag);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Encryption failed: %s\n", oabe_error_to_string(rc));
        oabe_symkey_free(key);
        oabe_rng_free(rng);
        oabe_context_aes_free(ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Encryption successful!\n");
    printf("   Ciphertext length: %zu bytes\n", oabe_bytestring_get_size(ciphertext));
    printf("   Authentication tag: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X", tag[i]);
    }
    printf("\n");

    /*------------------------------------------------------------------------
     * Example 4: Decryption
     *------------------------------------------------------------------------*/
    printf("\n4. Decryption:\n");

    /* Decrypt the ciphertext */
    uint8_t decrypted[256];
    size_t decrypted_len = sizeof(decrypted);

    rc = oabe_context_aes_decrypt(ctx,
                                   oabe_bytestring_get_const_ptr(ciphertext),
                                   oabe_bytestring_get_size(ciphertext),
                                   iv, sizeof(iv),
                                   tag,
                                   decrypted, &decrypted_len);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Decryption failed: %s\n", oabe_error_to_string(rc));
        oabe_bytestring_free(ciphertext);
        oabe_symkey_free(key);
        oabe_rng_free(rng);
        oabe_context_aes_free(ctx);
        oabe_shutdown();
        return 1;
    }

    /* Null-terminate for printing */
    decrypted[decrypted_len] = '\0';
    printf("   Decryption successful!\n");
    printf("   Decrypted text: \"%s\"\n", (char *)decrypted);
    printf("   Decrypted length: %zu bytes\n", decrypted_len);

    /* Verify correctness */
    if (decrypted_len == plaintext_len &&
        memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("   Verification: Plaintext matches decrypted text!\n");
    } else {
        printf("   Verification FAILED: Plaintext does not match!\n");
    }

    /*------------------------------------------------------------------------
     * Example 5: Authentication verification
     *------------------------------------------------------------------------*/
    printf("\n5. Authentication verification (tampered tag):\n");

    /* Tamper with the authentication tag */
    uint8_t tampered_tag[16];
    memcpy(tampered_tag, tag, 16);
    tampered_tag[0] ^= 0xFF;  /* Flip some bits */

    /* Try to decrypt with tampered tag */
    rc = oabe_context_aes_decrypt(ctx,
                                   oabe_bytestring_get_const_ptr(ciphertext),
                                   oabe_bytestring_get_size(ciphertext),
                                   iv, sizeof(iv),
                                   tampered_tag,
                                   decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        printf("   WARNING: Decryption succeeded with tampered tag!\n");
    } else {
        printf("   Decryption correctly rejected tampered tag: %s\n",
               oabe_error_to_string(rc));
    }

    /*------------------------------------------------------------------------
     * Example 6: Different key sizes
     *------------------------------------------------------------------------*/
    printf("\n6. Different AES key sizes:\n");

    /* Test AES-128 (16 bytes) */
    OABE_SymKey *key128 = oabe_symkey_new(16, rng);
    rc = oabe_context_aes_set_key(ctx, key128->key_bytes, key128->key_len);
    if (rc == OABE_SUCCESS) {
        printf("   AES-128 key set successfully (16 bytes)\n");
    }
    oabe_symkey_free(key128);

    /* Test AES-192 (24 bytes) */
    OABE_SymKey *key192 = oabe_symkey_new(24, rng);
    rc = oabe_context_aes_set_key(ctx, key192->key_bytes, key192->key_len);
    if (rc == OABE_SUCCESS) {
        printf("   AES-192 key set successfully (24 bytes)\n");
    }
    oabe_symkey_free(key192);

    /* Test AES-256 (32 bytes) - already tested above */
    printf("   AES-256 key tested above (32 bytes)\n");

    /*------------------------------------------------------------------------
     * Example 7: Key serialization
     *------------------------------------------------------------------------*/
    printf("\n7. Key serialization:\n");

    OABE_ByteString *key_serialized = NULL;
    rc = oabe_symkey_serialize(key, &key_serialized);
    if (rc == OABE_SUCCESS) {
        printf("   Key serialized, size: %zu bytes\n",
               oabe_bytestring_get_size(key_serialized));

        /* Deserialize */
        OABE_SymKey *key_restored = NULL;
        rc = oabe_symkey_deserialize(key_serialized, &key_restored);
        if (rc == OABE_SUCCESS) {
            printf("   Key deserialized successfully\n");

            /* Verify key matches */
            if (key_restored->key_len == key->key_len &&
                memcmp(key_restored->key_bytes, key->key_bytes, key->key_len) == 0) {
                printf("   Deserialized key matches original!\n");
            }
            oabe_symkey_free(key_restored);
        }
        oabe_bytestring_free(key_serialized);
    }

    /*------------------------------------------------------------------------
     * Cleanup
     *------------------------------------------------------------------------*/
    printf("\n8. Cleanup:\n");

    oabe_bytestring_free(ciphertext);
    oabe_symkey_free(key);
    oabe_rng_free(rng);
    oabe_context_aes_free(ctx);
    printf("   All resources freed.\n");

    oabe_shutdown();
    printf("   Library shutdown complete.\n");

    printf("\n=== Example completed successfully ===\n");
    return 0;
}