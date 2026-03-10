///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// OpenABE C Example: CP-ABE (Ciphertext-Policy Attribute-Based Encryption)
///
/// CP-ABE allows encryption based on an access policy (ciphertext policy).
/// Users receive secret keys for their attributes. A user can decrypt
/// ciphertext if and only if their attributes satisfy the policy.
///
/// This example demonstrates:
/// - Setup (generating public parameters and master key)
/// - Key generation for users with attributes
/// - Encryption with an access policy
/// - Decryption with user keys
/// - Key serialization for storage/transmission
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_context.h"
#include "openabe/oabe_key.h"
#include "openabe/oabe_bytestring.h"

int main(void) {
    printf("=== OpenABE C Example: CP-ABE Encryption ===\n\n");

    /* Initialize the library */
    OABE_ERROR rc = oabe_init();
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to initialize library: %s\n", oabe_error_to_string(rc));
        return 1;
    }

    /*------------------------------------------------------------------------
     * Example 1: Authority Setup
     *
     * The authority generates public parameters (used for encryption)
     * and a master secret key (used for generating user keys).
     *------------------------------------------------------------------------*/
    printf("1. Authority Setup:\n");

    OABE_ContextCP *authority_ctx = oabe_context_cp_new();
    if (!authority_ctx) {
        fprintf(stderr, "Failed to create CP-ABE context\n");
        oabe_shutdown();
        return 1;
    }

    /* Generate parameters with a unique authority ID */
    rc = oabe_context_cp_generate_params(authority_ctx, "my_authority");
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate params: %s\n", oabe_error_to_string(rc));
        oabe_context_cp_free(authority_ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Generated public parameters and master secret key\n");
    printf("   Authority ID: \"my_authority\"\n");

    /* Export public parameters for distribution */
    OABE_ByteString *public_params = NULL;
    rc = oabe_context_cp_get_public_params(authority_ctx, &public_params);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to export public params: %s\n", oabe_error_to_string(rc));
        oabe_context_cp_free(authority_ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Exported public params (%zu bytes)\n", oabe_bytestring_get_size(public_params));

    /* Export master secret key (keep this secure!) */
    OABE_ByteString *master_secret = NULL;
    rc = oabe_context_cp_get_secret_key(authority_ctx, &master_secret);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to export master secret: %s\n", oabe_error_to_string(rc));
        oabe_bytestring_free(public_params);
        oabe_context_cp_free(authority_ctx);
        oabe_shutdown();
        return 1;
    }
    printf("   Exported master secret key (%zu bytes) - KEEP THIS SECURE!\n",
           oabe_bytestring_get_size(master_secret));

    /*------------------------------------------------------------------------
     * Example 2: User Key Generation
     *
     * Generate secret keys for users based on their attributes.
     * Attributes are separated by the '|' character.
     *------------------------------------------------------------------------*/
    printf("\n2. User Key Generation:\n");

    /* User Alice: Has doctor and hospital attributes */
    rc = oabe_context_cp_keygen(authority_ctx, "alice", "doctor|hospital");
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate key for Alice: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Generated key for Alice with attributes: doctor|hospital\n");
    }

    /* User Bob: Has nurse and hospital attributes */
    rc = oabe_context_cp_keygen(authority_ctx, "bob", "nurse|hospital");
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate key for Bob: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Generated key for Bob with attributes: nurse|hospital\n");
    }

    /* User Charlie: Has researcher attribute only */
    rc = oabe_context_cp_keygen(authority_ctx, "charlie", "researcher");
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to generate key for Charlie: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Generated key for Charlie with attributes: researcher\n");
    }

    /* Export Alice's key for her to use */
    OABE_ByteString *alice_key = NULL;
    rc = oabe_context_cp_export_key(authority_ctx, "alice", &alice_key);
    if (rc == OABE_SUCCESS) {
        printf("   Exported Alice's key (%zu bytes)\n", oabe_bytestring_get_size(alice_key));
    }

    /*------------------------------------------------------------------------
     * Example 3: Encryption with Access Policy
     *
     * Anyone with the public parameters can encrypt data with a policy.
     * The policy specifies who can decrypt.
     *------------------------------------------------------------------------*/
    printf("\n3. Encryption with Access Policy:\n");

    /* Create an encryptor context with only public parameters */
    OABE_ContextCP *encryptor_ctx = oabe_context_cp_new();
    rc = oabe_context_cp_set_public_params(encryptor_ctx, public_params);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to set public params: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Created encryptor context with public params\n");
    }

    /* Policy: (doctor AND hospital) OR nurse
     * This means: user must be either (doctor at hospital) or (nurse) */
    const char *policy = "(doctor and hospital) or nurse";
    const char *message = "Confidential patient record: John Doe, DOB 1980-05-15";

    printf("   Policy: %s\n", policy);
    printf("   Message: \"%s\"\n", message);

    OABE_ByteString *ciphertext = NULL;
    rc = oabe_context_cp_encrypt(encryptor_ctx, policy,
                                  (const uint8_t *)message, strlen(message),
                                  &ciphertext);
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Encryption failed: %s\n", oabe_error_to_string(rc));
    } else {
        printf("   Encryption successful! Ciphertext size: %zu bytes\n",
               oabe_bytestring_get_size(ciphertext));
    }

    /*------------------------------------------------------------------------
     * Example 4: Decryption
     *
     * Users can decrypt if their attributes satisfy the policy.
     *------------------------------------------------------------------------*/
    printf("\n4. Decryption:\n");

    /* Test decryption with Alice (doctor AND hospital) */
    printf("   Testing Alice (attributes: doctor|hospital):\n");
    uint8_t decrypted[256];
    size_t decrypted_len = sizeof(decrypted);

    rc = oabe_context_cp_decrypt(authority_ctx, "alice", ciphertext, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS: Decrypted message: \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED: %s\n", oabe_error_to_string(rc));
    }

    /* Test decryption with Bob (nurse) */
    printf("   Testing Bob (attributes: nurse|hospital):\n");
    decrypted_len = sizeof(decrypted);

    rc = oabe_context_cp_decrypt(authority_ctx, "bob", ciphertext, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS: Decrypted message: \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED: %s\n", oabe_error_to_string(rc));
    }

    /* Test decryption with Charlie (researcher only - doesn't satisfy policy) */
    printf("   Testing Charlie (attributes: researcher):\n");
    decrypted_len = sizeof(decrypted);

    rc = oabe_context_cp_decrypt(authority_ctx, "charlie", ciphertext, decrypted, &decrypted_len);
    if (rc == OABE_SUCCESS) {
        decrypted[decrypted_len] = '\0';
        printf("      SUCCESS (unexpected): Decrypted message: \"%s\"\n", (char *)decrypted);
    } else {
        printf("      FAILED (expected): %s\n", oabe_error_to_string(rc));
    }

    /*------------------------------------------------------------------------
     * Example 5: Complex Policy
     *------------------------------------------------------------------------*/
    printf("\n5. Complex Access Policy:\n");

    /* Policy: doctor AND (hospital OR clinic) AND NOT researcher */
    const char *complex_policy = "doctor and (hospital or clinic) and not researcher";
    const char *complex_message = "More restrictive confidential data";

    printf("   Policy: %s\n", complex_policy);

    OABE_ByteString *complex_ciphertext = NULL;
    rc = oabe_context_cp_encrypt(encryptor_ctx, complex_policy,
                                  (const uint8_t *)complex_message, strlen(complex_message),
                                  &complex_ciphertext);
    if (rc == OABE_SUCCESS) {
        printf("   Encrypted with complex policy (%zu bytes)\n",
               oabe_bytestring_get_size(complex_ciphertext));

        /* Test with Alice (doctor|hospital, no researcher) - should succeed */
        decrypted_len = sizeof(decrypted);
        rc = oabe_context_cp_decrypt(authority_ctx, "alice", complex_ciphertext,
                                      decrypted, &decrypted_len);
        if (rc == OABE_SUCCESS) {
            printf("   Alice can decrypt: SUCCESS\n");
        } else {
            printf("   Alice can decrypt: FAILED (%s)\n", oabe_error_to_string(rc));
        }

        oabe_bytestring_free(complex_ciphertext);
    } else {
        printf("   Encryption failed: %s\n", oabe_error_to_string(rc));
    }

    /*------------------------------------------------------------------------
     * Example 6: Key Import/Export (for key distribution)
     *------------------------------------------------------------------------*/
    printf("\n6. Key Import/Export:\n");

    /* Simulate giving Alice her key on a separate device */
    OABE_ContextCP *alice_device = oabe_context_cp_new();

    /* Set public parameters on Alice's device */
    rc = oabe_context_cp_set_public_params(alice_device, public_params);
    if (rc == OABE_SUCCESS) {
        printf("   Public params loaded on Alice's device\n");
    }

    /* Import Alice's key on her device */
    rc = oabe_context_cp_import_key(alice_device, "alice_key", alice_key);
    if (rc == OABE_SUCCESS) {
        printf("   Alice's key imported successfully\n");

        /* Alice can now decrypt on her own device */
        decrypted_len = sizeof(decrypted);
        rc = oabe_context_cp_decrypt(alice_device, "alice_key", ciphertext,
                                       decrypted, &decrypted_len);
        if (rc == OABE_SUCCESS) {
            decrypted[decrypted_len] = '\0';
            printf("   Alice decrypted on her device: \"%s\"\n", (char *)decrypted);
        }
    }

    /*------------------------------------------------------------------------
     * Cleanup
     *------------------------------------------------------------------------*/
    printf("\n7. Cleanup:\n");

    oabe_bytestring_free(ciphertext);
    oabe_bytestring_free(public_params);
    oabe_bytestring_free(master_secret);
    oabe_bytestring_free(alice_key);

    oabe_context_cp_free(authority_ctx);
    oabe_context_cp_free(encryptor_ctx);
    oabe_context_cp_free(alice_device);

    printf("   All resources freed.\n");

    oabe_shutdown();
    printf("   Library shutdown complete.\n");

    printf("\n=== Example completed successfully ===\n");
    return 0;
}