///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// OpenABE C Example: Hybrid Encryption (ABE + AES)
///
/// In practice, ABE is often used in a hybrid encryption scheme:
/// 1. Generate a random symmetric key (for AES)
/// 2. Encrypt the large data with AES using this key
/// 3. Encrypt the symmetric key with ABE (the ABE "ciphertext" is small)
///
/// This approach is efficient for large data and follows best practices.
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_context.h"
#include "openabe/oabe_key.h"
#include "openabe/oabe_zml.h"
#include "openabe/oabe_bytestring.h"

/* Helper to print hex data */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("   %s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02X", data[i]);
    }
    if (len > 32) printf("...");
    printf(" (%zu bytes)\n", len);
}

int main(void) {
    printf("=== OpenABE C Example: Hybrid Encryption (ABE + AES) ===\n\n");

    OABE_ERROR rc = oabe_init();
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to initialize: %s\n", oabe_error_to_string(rc));
        return 1;
    }

    /* Create RNG for key generation */
    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    if (!rng) {
        fprintf(stderr, "Failed to create RNG\n");
        oabe_shutdown();
        return 1;
    }

    /*------------------------------------------------------------------------
     * Step 1: Setup ABE (CP-ABE in this example)
     *------------------------------------------------------------------------*/
    printf("1. ABE Setup:\n");

    OABE_ContextCP *abe_ctx = oabe_context_cp_new();
    rc = oabe_context_cp_generate_params(abe_ctx, "hybrid_auth");
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate ABE params: %s\n", oabe_error_to_string(rc));
        oabe_rng_free(rng);
        oabe_context_cp_free(abe_ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Generated ABE parameters\n");

    /* Generate user keys */
    rc = oabe_context_cp_keygen(abe_ctx, "user1", "admin|level3|departmentA");
    printf("   Generated key for user1: admin|level3|departmentA\n");

    rc = oabe_context_cp_keygen(abe_ctx, "user2", "user|level1|departmentB");
    printf("   Generated key for user2: user|level1|departmentB\n");

    /* Export public params for encryptor */
    OABE_ByteString *public_params = NULL;
    oabe_context_cp_get_public_params(abe_ctx, &public_params);

    /*------------------------------------------------------------------------
     * Step 2: Create AES key and encrypt large data
     *------------------------------------------------------------------------*/
    printf("\n2. Symmetric Key Generation and Data Encryption:\n");

    /* Generate random AES-256 key */
    OABE_SymKey *aes_key = oabe_symkey_new(32, rng);
    if (!aes_key) {
        fprintf(stderr, "Failed to generate AES key\n");
        oabe_bytestring_free(public_params);
        oabe_rng_free(rng);
        oabe_context_cp_free(abe_ctx);
        oabe_shutdown();
        return 1;
    }
    print_hex("AES-256 key", aes_key->key_bytes, aes_key->key_len);

    /* Create AES context and set key */
    OABE_ContextAES *aes_ctx = oabe_context_aes_new();
    rc = oabe_context_aes_set_key(aes_ctx, aes_key->key_bytes, aes_key->key_len);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to set AES key: %s\n", oabe_error_to_string(rc));
        oabe_symkey_free(aes_key);
        oabe_context_aes_free(aes_ctx);
        oabe_bytestring_free(public_params);
        oabe_rng_free(rng);
        oabe_context_cp_free(abe_ctx);
        oabe_shutdown();
        return 1;
    }

    /* Generate IV */
    uint8_t iv[12];
    oabe_rng_bytes(rng, iv, sizeof(iv));
    print_hex("IV (nonce)", iv, sizeof(iv));

    /* Encrypt large data with AES-GCM */
    const char *large_data = "This is a large document that would be inefficient "
                            "to encrypt directly with ABE. In practice, this could "
                            "be a file of any size - documents, videos, databases, etc. "
                            "ABE is used only to protect the symmetric key.";
    size_t data_len = strlen(large_data);
    printf("   Data to encrypt: %zu bytes\n", data_len);

    OABE_ByteString *encrypted_data = NULL;
    uint8_t auth_tag[16];

    rc = oabe_context_aes_encrypt(aes_ctx, (const uint8_t *)large_data, data_len,
                                   iv, sizeof(iv), &encrypted_data, auth_tag);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "AES encryption failed: %s\n", oabe_error_to_string(rc));
        oabe_symkey_free(aes_key);
        oabe_context_aes_free(aes_ctx);
        oabe_bytestring_free(public_params);
        oabe_rng_free(rng);
        oabe_context_cp_free(abe_ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   AES-GCM encryption complete: %zu bytes ciphertext\n",
           oabe_bytestring_get_size(encrypted_data));
    print_hex("Auth tag", auth_tag, 16);

    /*------------------------------------------------------------------------
     * Step 3: Encrypt the AES key with ABE
     *------------------------------------------------------------------------*/
    printf("\n3. Encrypt AES Key with ABE:\n");

    /* Create encryptor context */
    OABE_ContextCP *encryptor = oabe_context_cp_new();
    oabe_context_cp_set_public_params(encryptor, public_params);

    /* Define policy: only admin AND level3 can decrypt */
    const char *policy = "(admin and level3)";

    /* Encrypt the AES key with ABE */
    OABE_ByteString *encrypted_key = NULL;
    rc = oabe_context_cp_encrypt(encryptor, policy,
                                  aes_key->key_bytes, aes_key->key_len,
                                  &encrypted_key);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "ABE encryption of key failed: %s\n", oabe_error_to_string(rc));
        oabe_bytestring_free(encrypted_data);
        oabe_symkey_free(aes_key);
        oabe_context_aes_free(aes_ctx);
        oabe_context_cp_free(encryptor);
        oabe_bytestring_free(public_params);
        oabe_rng_free(rng);
        oabe_context_cp_free(abe_ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   ABE policy: %s\n", policy);
    printf("   ABE-encrypted key: %zu bytes\n", oabe_bytestring_get_size(encrypted_key));

    /* Now we can clear the plaintext AES key from memory */
    oabe_symkey_free(aes_key);
    oabe_context_aes_free(aes_ctx);
    printf("   Plaintext AES key cleared from memory\n");

    /*------------------------------------------------------------------------
     * Step 4: Decryption (authorized user - user1)
     *------------------------------------------------------------------------*/
    printf("\n4. Decryption by Authorized User (user1):\n");

    /* Decrypt AES key with ABE */
    uint8_t recovered_key[32];
    size_t key_len = sizeof(recovered_key);

    rc = oabe_context_cp_decrypt(abe_ctx, "user1", encrypted_key,
                                  recovered_key, &key_len);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "   ABE key decryption failed: %s\n", oabe_error_to_string(rc));
        printf("   (User does not satisfy the policy)\n");
    } else {
        printf("   ABE key decryption successful!\n");
        print_hex("   Recovered AES key", recovered_key, key_len);

        /* Create AES context with recovered key */
        OABE_ContextAES *decrypt_aes = oabe_context_aes_new();
        oabe_context_aes_set_key(decrypt_aes, recovered_key, key_len);

        /* Decrypt data */
        uint8_t decrypted_data[1024];
        size_t dec_len = sizeof(decrypted_data);

        rc = oabe_context_aes_decrypt(decrypt_aes,
                                       oabe_bytestring_get_const_ptr(encrypted_data),
                                       oabe_bytestring_get_size(encrypted_data),
                                       iv, sizeof(iv), auth_tag,
                                       decrypted_data, &dec_len);
        if (rc == OABE_SUCCESS) {
            decrypted_data[dec_len] = '\0';
            printf("   Data decryption successful!\n");
            printf("   Decrypted: \"%s\"\n", (char *)decrypted_data);
        } else {
            fprintf(stderr, "   AES decryption failed: %s\n", oabe_error_to_string(rc));
        }

        oabe_context_aes_free(decrypt_aes);
    }

    /*------------------------------------------------------------------------
     * Step 5: Decryption Attempt (unauthorized user - user2)
     *------------------------------------------------------------------------*/
    printf("\n5. Decryption Attempt by Unauthorized User (user2):\n");

    key_len = sizeof(recovered_key);
    rc = oabe_context_cp_decrypt(abe_ctx, "user2", encrypted_key,
                                  recovered_key, &key_len);
    if (rc != OABE_SUCCESS) {
        printf("   ABE key decryption failed (expected): %s\n", oabe_error_to_string(rc));
        printf("   User2 lacks required attributes (admin AND level3)\n");
    } else {
        printf("   WARNING: Unexpected success - policy not enforced!\n");
    }

    /*------------------------------------------------------------------------
     * Cleanup
     *------------------------------------------------------------------------*/
    printf("\n6. Cleanup:\n");

    oabe_bytestring_free(encrypted_key);
    oabe_bytestring_free(encrypted_data);
    oabe_bytestring_free(public_params);
    oabe_context_cp_free(encryptor);
    oabe_rng_free(rng);
    oabe_context_cp_free(abe_ctx);

    printf("   All resources freed.\n");
    oabe_shutdown();

    printf("\n=== Example completed successfully ===\n");
    return 0;
}