///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// OpenABE C Example: Key Management and Serialization
///
/// This example demonstrates:
/// - Key store usage for managing multiple keys
/// - Serializing keys to files for persistent storage
/// - Loading keys from serialized data
/// - Key store operations
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_context.h"
#include "openabe/oabe_key.h"
#include "openabe/oabe_bytestring.h"
#include "openabe/oabe_zml.h"

/* Helper function to write ByteString to file */
static int write_bytestring_to_file(const char *filename, const OABE_ByteString *bs) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        return -1;
    }

    const uint8_t *data = oabe_bytestring_get_const_ptr(bs);
    size_t size = oabe_bytestring_get_size(bs);

    /* Write size first (4 bytes) */
    uint32_t size32 = (uint32_t)size;
    if (fwrite(&size32, sizeof(size32), 1, f) != 1) {
        fclose(f);
        return -1;
    }

    /* Write data */
    if (fwrite(data, 1, size, f) != size) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/* Helper function to read ByteString from file */
static OABE_ByteString* read_bytestring_from_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s for reading\n", filename);
        return NULL;
    }

    /* Read size */
    uint32_t size;
    if (fread(&size, sizeof(size), 1, f) != 1) {
        fclose(f);
        return NULL;
    }

    /* Allocate and read data */
    uint8_t *data = malloc(size);
    if (!data) {
        fclose(f);
        return NULL;
    }

    if (fread(data, 1, size, f) != size) {
        free(data);
        fclose(f);
        return NULL;
    }

    fclose(f);

    OABE_ByteString *bs = oabe_bytestring_new_from_data(data, size);
    free(data);
    return bs;
}

int main(void) {
    printf("=== OpenABE C Example: Key Management ===\n\n");

    OABE_ERROR rc = oabe_init();
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to initialize: %s\n", oabe_error_to_string(rc));
        return 1;
    }

    /*------------------------------------------------------------------------
     * Example 1: Using the Key Store
     *------------------------------------------------------------------------*/
    printf("1. Key Store Operations:\n");

    /* Create a key store */
    OABE_KeyStore *keystore = oabe_keystore_new();
    if (!keystore) {
        fprintf(stderr, "Failed to create key store\n");
        oabe_shutdown();
        return 1;
    }
    printf("   Created key store\n");

    /* Create RNG and group for key generation */
    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);

    /* Create public parameters */
    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    if (params) {
        /* Add to keystore */
        rc = oabe_keystore_add_public(keystore, "auth1", params);
        if (rc == OABE_SUCCESS) {
            printf("   Added public params with ID 'auth1'\n");
        }

        /* Check if exists */
        if (oabe_keystore_has_user_key(keystore, "nonexistent") == false) {
            printf("   Key 'nonexistent' correctly not found\n");
        }

        /* Create user keys */
        OABE_ABEUserKey *user_key1 = oabe_user_key_new("user1", params);
        OABE_ABEUserKey *user_key2 = oabe_user_key_new("user2", params);

        if (user_key1 && user_key2) {
            /* Add user keys to keystore */
            oabe_keystore_add_user_key(keystore, "user1", user_key1);
            oabe_keystore_add_user_key(keystore, "user2", user_key2);
            printf("   Added %zu user keys to keystore\n",
                   oabe_keystore_get_user_key_count(keystore));

            /* Retrieve a key */
            OABE_ABEUserKey *retrieved = oabe_keystore_get_user_key(keystore, "user1");
            if (retrieved) {
                printf("   Retrieved key for 'user1'\n");
            }

            /* Remove a key */
            oabe_keystore_remove_user_key(keystore, "user2");
            printf("   Removed 'user2', now have %zu keys\n",
                   oabe_keystore_get_user_key_count(keystore));
        }

        oabe_params_free(params);
    }

    oabe_keystore_free(keystore);
    printf("   Key store freed\n");

    /*------------------------------------------------------------------------
     * Example 2: Key Serialization to ByteString
     *------------------------------------------------------------------------*/
    printf("\n2. Key Serialization:\n");

    /* Create CP-ABE context and generate keys */
    OABE_ContextCP *ctx = oabe_context_cp_new();
    rc = oabe_context_cp_generate_params(ctx, "serialize_test");
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate params\n");
        oabe_rng_free(rng);
        oabe_group_free(group);
        oabe_context_cp_free(ctx);
        oabe_shutdown();
        return 1;
    }

    /* Generate a user key */
    rc = oabe_context_cp_keygen(ctx, "test_user", "attr1|attr2|attr3");
    if (rc == OABE_SUCCESS) {
        printf("   Generated user key with attributes: attr1|attr2|attr3\n");
    }

    /* Export and serialize the public parameters */
    OABE_ByteString *public_params = NULL;
    rc = oabe_context_cp_get_public_params(ctx, &public_params);
    if (rc == OABE_SUCCESS) {
        printf("   Exported public params: %zu bytes\n",
               oabe_bytestring_get_size(public_params));

        /* Convert to hex for storage/transmission */
        char *hex = oabe_bytestring_to_hex(public_params);
        printf("   Public params (hex, first 64 chars): %.64s...\n", hex);
        oabe_free(hex);
    }

    /* Export and serialize the master secret key */
    OABE_ByteString *secret_key = NULL;
    rc = oabe_context_cp_get_secret_key(ctx, &secret_key);
    if (rc == OABE_SUCCESS) {
        printf("   Exported secret key: %zu bytes\n",
               oabe_bytestring_get_size(secret_key));
    }

    /* Export and serialize a user key */
    OABE_ByteString *user_key_data = NULL;
    rc = oabe_context_cp_export_key(ctx, "test_user", &user_key_data);
    if (rc == OABE_SUCCESS) {
        printf("   Exported user key: %zu bytes\n",
               oabe_bytestring_get_size(user_key_data));
    }

    /*------------------------------------------------------------------------
     * Example 3: File Persistence (simulated)
     *------------------------------------------------------------------------*/
    printf("\n3. File Persistence:\n");

    /* Write keys to files */
    if (public_params && user_key_data) {
        /* Write public params */
        if (write_bytestring_to_file("/tmp/openabe_public_params.bin", public_params) == 0) {
            printf("   Wrote public params to /tmp/openabe_public_params.bin\n");
        }

        /* Write user key */
        if (write_bytestring_to_file("/tmp/openabe_user_key.bin", user_key_data) == 0) {
            printf("   Wrote user key to /tmp/openabe_user_key.bin\n");
        }

        /* Read back and verify */
        OABE_ByteString *loaded_params = read_bytestring_from_file("/tmp/openabe_public_params.bin");
        OABE_ByteString *loaded_key = read_bytestring_from_file("/tmp/openabe_user_key.bin");

        if (loaded_params && loaded_key) {
            printf("   Loaded public params: %zu bytes\n",
                   oabe_bytestring_get_size(loaded_params));
            printf("   Loaded user key: %zu bytes\n",
                   oabe_bytestring_get_size(loaded_key));

            /* Verify the loaded data matches */
            if (oabe_bytestring_equals(public_params, loaded_params)) {
                printf("   Public params verified: MATCH\n");
            }
            if (oabe_bytestring_equals(user_key_data, loaded_key)) {
                printf("   User key verified: MATCH\n");
            }

            oabe_bytestring_free(loaded_params);
            oabe_bytestring_free(loaded_key);
        }
    }

    /*------------------------------------------------------------------------
     * Example 4: Key Restoration and Use
     *------------------------------------------------------------------------*/
    printf("\n4. Key Restoration and Use:\n");

    /* Create a new context and restore keys */
    OABE_ContextCP *restored_ctx = oabe_context_cp_new();

    /* Load public params from file */
    OABE_ByteString *restored_params = read_bytestring_from_file("/tmp/openabe_public_params.bin");
    if (restored_params) {
        rc = oabe_context_cp_set_public_params(restored_ctx, restored_params);
        if (rc == OABE_SUCCESS) {
            printf("   Restored public params into new context\n");
        }
        oabe_bytestring_free(restored_params);
    }

    /* Load user key from file */
    OABE_ByteString *restored_key = read_bytestring_from_file("/tmp/openabe_user_key.bin");
    if (restored_key) {
        rc = oabe_context_cp_import_key(restored_ctx, "restored_user", restored_key);
        if (rc == OABE_SUCCESS) {
            printf("   Restored user key as 'restored_user'\n");

            /* Verify the restored context can encrypt/decrypt */
            const char *test_msg = "Test message for restored keys";
            const char *policy = "attr1";

            OABE_ByteString *ciphertext = NULL;
            rc = oabe_context_cp_encrypt(restored_ctx, policy,
                                          (const uint8_t *)test_msg, strlen(test_msg),
                                          &ciphertext);
            if (rc == OABE_SUCCESS) {
                printf("   Encryption with restored context: SUCCESS\n");

                /* Decrypt with restored key */
                uint8_t decrypted[256];
                size_t dec_len = sizeof(decrypted);
                rc = oabe_context_cp_decrypt(restored_ctx, "restored_user",
                                              ciphertext, decrypted, &dec_len);
                if (rc == OABE_SUCCESS) {
                    decrypted[dec_len] = '\0';
                    printf("   Decryption with restored key: SUCCESS\n");
                    printf("   Decrypted: \"%s\"\n", (char *)decrypted);
                }
                oabe_bytestring_free(ciphertext);
            }
        }
        oabe_bytestring_free(restored_key);
    }

    /*------------------------------------------------------------------------
     * Example 5: Symmetric Key Serialization
     *------------------------------------------------------------------------*/
    printf("\n5. Symmetric Key Serialization:\n");

    /* Generate a symmetric key */
    OABE_SymKey *sym_key = oabe_symkey_new(32, rng);
    if (sym_key) {
        printf("   Generated AES-256 key\n");

        /* Serialize to ByteString */
        OABE_ByteString *serialized = NULL;
        rc = oabe_symkey_serialize(sym_key, &serialized);
        if (rc == OABE_SUCCESS) {
            printf("   Serialized key: %zu bytes\n",
                   oabe_bytestring_get_size(serialized));

            /* Deserialize */
            OABE_SymKey *deserialized = NULL;
            rc = oabe_symkey_deserialize(serialized, &deserialized);
            if (rc == OABE_SUCCESS) {
                printf("   Deserialized key successfully\n");

                /* Verify */
                if (deserialized->key_len == sym_key->key_len &&
                    memcmp(deserialized->key_bytes, sym_key->key_bytes, sym_key->key_len) == 0) {
                    printf("   Key verification: MATCH\n");
                }
                oabe_symkey_free(deserialized);
            }
            oabe_bytestring_free(serialized);
        }
        oabe_symkey_free(sym_key);
    }

    /*------------------------------------------------------------------------
     * Cleanup
     *------------------------------------------------------------------------*/
    printf("\n6. Cleanup:\n");

    /* Clean up temporary files */
    remove("/tmp/openabe_public_params.bin");
    remove("/tmp/openabe_user_key.bin");
    printf("   Cleaned up temporary files\n");

    oabe_bytestring_free(public_params);
    oabe_bytestring_free(secret_key);
    oabe_bytestring_free(user_key_data);
    oabe_context_cp_free(ctx);
    oabe_context_cp_free(restored_ctx);
    oabe_rng_free(rng);
    oabe_group_free(group);

    printf("   All resources freed.\n");
    oabe_shutdown();

    printf("\n=== Example completed successfully ===\n");
    return 0;
}