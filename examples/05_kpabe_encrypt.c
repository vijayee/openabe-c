///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// OpenABE C Example: KP-ABE (Key-Policy Attribute-Based Encryption)
///
/// KP-ABE is the dual of CP-ABE. In KP-ABE:
/// - Ciphertexts are encrypted with a set of attributes
/// - Users receive secret keys with embedded access policies
/// - Decryption succeeds if the ciphertext attributes satisfy the user's policy
///
/// This example demonstrates:
/// - Setup (generating public parameters and master key)
/// - Key generation with access policies
/// - Encryption with attributes
/// - Decryption based on policy satisfaction
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_context.h"
#include "openabe/oabe_key.h"
#include "openabe/oabe_bytestring.h"

int main(void) {
    printf("=== OpenABE C Example: KP-ABE Encryption ===\n\n");

    /* Initialize the library */
    OABE_ERROR rc = oabe_init();
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to initialize library: %s\n", oabe_error_to_string(rc));
        return 1;
    }

    /*------------------------------------------------------------------------
     * Example 1: Authority Setup
     *------------------------------------------------------------------------*/
    printf("1. Authority Setup:\n");

    OABE_ContextKP *authority_ctx = oabe_context_kp_new();
    if (!authority_ctx) {
        fprintf(stderr, "Failed to create KP-ABE context\n");
        oabe_shutdown();
        return 1;
    }

    rc = oabe_context_kp_generate_params(authority_ctx, "kp_authority");
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate params: %s\n", oabe_error_to_string(rc));
        oabe_context_kp_free(authority_ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Generated KP-ABE public parameters and master key\n");

    /* Export public parameters */
    OABE_ByteString *public_params = NULL;
    rc = oabe_context_kp_get_public_params(authority_ctx, &public_params);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to export public params: %s\n", oabe_error_to_string(rc));
        oabe_context_kp_free(authority_ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Exported public params (%zu bytes)\n", oabe_bytestring_get_size(public_params));

    /*------------------------------------------------------------------------
     * Example 2: Key Generation with Policies
     *
     * In KP-ABE, users receive keys with embedded access policies.
     *------------------------------------------------------------------------*/
    printf("\n2. Key Generation with Policies:\n");

    /* Alice's key: Can decrypt documents tagged with BOTH 'confidential' AND 'medical' */
    const char *alice_policy = "(confidential and medical)";
    rc = oabe_context_kp_keygen(authority_ctx, "alice", alice_policy);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate key for Alice: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Generated key for Alice with policy: %s\n", alice_policy);
    }

    /* Bob's key: Can decrypt documents tagged with 'public' OR 'internal' */
    const char *bob_policy = "(public or internal)";
    rc = oabe_context_kp_keygen(authority_ctx, "bob", bob_policy);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate key for Bob: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Generated key for Bob with policy: %s\n", bob_policy);
    }

    /* Charlie's key: Complex policy requiring specific attribute combinations */
    const char *charlie_policy = "((secret and finance) or (public and medical))";
    rc = oabe_context_kp_keygen(authority_ctx, "charlie", charlie_policy);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate key for Charlie: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Generated key for Charlie with policy: %s\n", charlie_policy);
    }

    /*------------------------------------------------------------------------
     * Example 3: Encryption with Attributes
     *
     * In KP-ABE, ciphertexts are tagged with attributes, not policies.
     *------------------------------------------------------------------------*/
    printf("\n3. Encryption with Attributes:\n");

    /* Create encryptor context */
    OABE_ContextKP *encryptor_ctx = oabe_context_kp_new();
    rc = oabe_context_kp_set_public_params(encryptor_ctx, public_params);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to set public params: %s\n", oabe_error_to_string(rc));
    }

    /* Encrypt a confidential medical document */
    const char *attributes1 = "confidential|medical|hospital";
    const char *message1 = "Patient medical record: Jane Smith";

    printf("   Encrypting with attributes: %s\n", attributes1);

    OABE_ByteString *ciphertext1 = NULL;
    rc = oabe_context_kp_encrypt(encryptor_ctx, attributes1,
                                  (const uint8_t *)message1, strlen(message1),
                                  &ciphertext1);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Encryption failed: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Encrypted message (%zu bytes)\n", oabe_bytestring_get_size(ciphertext1));
    }

    /* Encrypt a public document */
    const char *attributes2 = "public|internal";
    const char *message2 = "Company newsletter: Q1 results";

    printf("   Encrypting with attributes: %s\n", attributes2);

    OABE_ByteString *ciphertext2 = NULL;
    rc = oabe_context_kp_encrypt(encryptor_ctx, attributes2,
                                  (const uint8_t *)message2, strlen(message2),
                                  &ciphertext2);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Encryption failed: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Encrypted message (%zu bytes)\n", oabe_bytestring_get_size(ciphertext2));
    }

    /* Encrypt a secret finance document */
    const char *attributes3 = "secret|finance";
    const char *message3 = "Financial report: Q4 earnings";

    printf("   Encrypting with attributes: %s\n", attributes3);

    OABE_ByteString *ciphertext3 = NULL;
    rc = oabe_context_kp_encrypt(encryptor_ctx, attributes3,
                                  (const uint8_t *)message3, strlen(message3),
                                  &ciphertext3);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Encryption failed: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Encrypted message (%zu bytes)\n", oabe_bytestring_get_size(ciphertext3));
    }

    /*------------------------------------------------------------------------
     * Example 4: Decryption
     *
     * Decryption succeeds if ciphertext attributes satisfy the user's policy.
     *------------------------------------------------------------------------*/
    printf("\n4. Decryption Tests:\n");

    uint8_t decrypted[256];
    size_t decrypted_len;

    /* Test Alice with confidential|medical document */
    /* Alice's policy: (confidential AND medical)
     * Ciphertext attributes: confidential|medical|hospital
     * Result: Should succeed (has both confidential and medical) */
    printf("   Alice decrypting confidential|medical document:\n");
    decrypted_len = sizeof(decrypted);
    rc = oabe_context_kp_decrypt(authority_ctx, "alice", ciphertext1, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS: \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED: %s\n", oabe_error_to_string(rc));
    }

    /* Test Alice with public|internal document */
    /* Alice's policy requires (confidential AND medical), but document has public|internal
     * Result: Should fail */
    printf("   Alice decrypting public|internal document:\n");
    decrypted_len = sizeof(decrypted);
    rc = oabe_context_kp_decrypt(authority_ctx, "alice", ciphertext2, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS (unexpected): \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED (expected): %s\n", oabe_error_to_string(rc));
    }

    /* Test Bob with public|internal document */
    /* Bob's policy: (public OR internal)
     * Ciphertext attributes: public|internal
     * Result: Should succeed */
    printf("   Bob decrypting public|internal document:\n");
    decrypted_len = sizeof(decrypted);
    rc = oabe_context_kp_decrypt(authority_ctx, "bob", ciphertext2, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS: \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED: %s\n", oabe_error_to_string(rc));
    }

    /* Test Bob with confidential|medical document */
    /* Bob's policy requires (public OR internal), but document has confidential|medical
     * Result: Should fail */
    printf("   Bob decrypting confidential|medical document:\n");
    decrypted_len = sizeof(decrypted);
    rc = oabe_context_kp_decrypt(authority_ctx, "bob", ciphertext1, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS (unexpected): \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED (expected): %s\n", oabe_error_to_string(rc));
    }

    /* Test Charlie with secret|finance document */
    /* Charlie's policy: ((secret AND finance) OR (public AND medical))
     * Ciphertext attributes: secret|finance
     * Result: Should succeed (has both secret and finance) */
    printf("   Charlie decrypting secret|finance document:\n");
    decrypted_len = sizeof(decrypted);
    rc = oabe_context_kp_decrypt(authority_ctx, "charlie", ciphertext3, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS: \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED: %s\n", oabe_error_to_string(rc));
    }

    /* Test Charlie with confidential|medical document */
    /* Charlie's policy: ((secret AND finance) OR (public AND medical))
     * Ciphertext attributes: confidential|medical|hospital
     * Result: Should fail (doesn't satisfy either branch of the policy) */
    printf("   Charlie decrypting confidential|medical document:\n");
    decrypted_len = sizeof(decrypted);
    rc = oabe_context_kp_decrypt(authority_ctx, "charlie", ciphertext1, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS (unexpected): \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED (expected): %s\n", oabe_error_to_string(rc));
    }

    /*------------------------------------------------------------------------
     * Example 5: Key Export/Import
     *------------------------------------------------------------------------*/
    printf("\n5. Key Export/Import:\n");

    /* Export Alice's key */
    OABE_ByteString *alice_key = NULL;
    rc = oabe_context_kp_export_key(authority_ctx, "alice", &alice_key);
    if (rc == OABE_SUCCESS) {
        printf("   Exported Alice's key (%zu bytes)\n", oabe_bytestring_get_size(alice_key));

        /* Import on a new context */
        OABE_ContextKP *new_ctx = oabe_context_kp_new();
        rc = oabe_context_kp_set_public_params(new_ctx, public_params);
        if (rc == OABE_SUCCESS) {
            rc = oabe_context_kp_import_key(new_ctx, "alice_imported", alice_key);
            if (rc == OABE_SUCCESS) {
                printf("   Key imported successfully on new context\n");

                /* Test decryption with imported key */
                decrypted_len = sizeof(decrypted);
                rc = oabe_context_kp_decrypt(new_ctx, "alice_imported", ciphertext1,
                                              decrypted, &decrypted_len);
                if (rc == OABE_SUCCESS) {
                    decrypted[decrypted_len] = '\0';
                    printf("   Decryption with imported key: SUCCESS\n");
                }
            }
        }
        oabe_context_kp_free(new_ctx);
        oabe_bytestring_free(alice_key);
    }

    /*------------------------------------------------------------------------
     * Cleanup
     *------------------------------------------------------------------------*/
    printf("\n6. Cleanup:\n");

    oabe_bytestring_free(public_params);
    oabe_bytestring_free(ciphertext1);
    oabe_bytestring_free(ciphertext2);
    oabe_bytestring_free(ciphertext3);

    oabe_context_kp_free(authority_ctx);
    oabe_context_kp_free(encryptor_ctx);

    printf("   All resources freed.\n");

    oabe_shutdown();
    printf("   Library shutdown complete.\n");

    printf("\n=== Example completed successfully ===\n");
    return 0;
}