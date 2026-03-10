///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// OpenABE C Example: ZML Math Operations
///
/// This example demonstrates the mathematical operations on:
/// - ZP: Scalars in the field Z_p (integers modulo the curve order)
/// - G1: Points on the first elliptic curve group
/// - G2: Points on the second elliptic curve group
/// - GT: Points in the target group (pairing result)
///
/// These operations form the foundation of pairing-based cryptography.
///

#include <stdio.h>
#include <stdlib.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_zml.h"

int main(void) {
    printf("=== OpenABE C Example: ZML Math Operations ===\n\n");

    /* Initialize the library */
    OABE_ERROR rc = oabe_init();
    if (rc != OABE_SUCCESS) {
        fprintf(stderr, "Failed to initialize library: %s\n", oabe_error_to_string(rc));
        return 1;
    }

    /*------------------------------------------------------------------------
     * Example 1: Creating a pairing group
     *------------------------------------------------------------------------*/
    printf("1. Creating pairing group:\n");

    /* Create a pairing group using BN-254 curve */
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);
    if (!group) {
        fprintf(stderr, "Failed to create group\n");
        oabe_shutdown();
        return 1;
    }
    printf("   Created BN-254 pairing group\n");

    /* Get the order (p) of the group */
    OABE_ByteString *order = NULL;
    rc = oabe_group_get_order(group, &order);
    if (rc == OABE_SUCCESS) {
        printf("   Group order obtained (%zu bytes)\n", oabe_bytestring_get_size(order));
        oabe_bytestring_free(order);
    }

    /*------------------------------------------------------------------------
     * Example 2: RNG (Random Number Generator)
     *------------------------------------------------------------------------*/
    printf("\n2. Creating RNG:\n");

    /* Create a random number generator with system entropy */
    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    if (!rng) {
        fprintf(stderr, "Failed to create RNG\n");
        oabe_group_free(group);
        oabe_shutdown();
        return 1;
    }
    printf("   Created RNG with system entropy\n");

    /*------------------------------------------------------------------------
     * Example 3: ZP (Scalar) operations
     *------------------------------------------------------------------------*/
    printf("\n3. ZP (Scalar) operations:\n");

    /* Create scalars */
    OABE_ZP *zp1 = oabe_zp_new(group);
    OABE_ZP *zp2 = oabe_zp_new(group);
    OABE_ZP *zp_result = oabe_zp_new(group);

    /* Set random values */
    oabe_zp_random(zp1, rng);
    oabe_zp_random(zp2, rng);
    printf("   Created two random scalars\n");

    /* Addition: result = zp1 + zp2 */
    rc = oabe_zp_add(zp_result, zp1, zp2);
    if (rc == OABE_SUCCESS) {
        printf("   Addition: zp1 + zp2 = [computed]\n");
    }

    /* Subtraction: result = zp1 - zp2 */
    rc = oabe_zp_sub(zp_result, zp1, zp2);
    if (rc == OABE_SUCCESS) {
        printf("   Subtraction: zp1 - zp2 = [computed]\n");
    }

    /* Multiplication: result = zp1 * zp2 */
    rc = oabe_zp_mul(zp_result, zp1, zp2);
    if (rc == OABE_SUCCESS) {
        printf("   Multiplication: zp1 * zp2 = [computed]\n");
    }

    /* Negation: result = -zp1 */
    rc = oabe_zp_neg(zp_result, zp1);
    if (rc == OABE_SUCCESS) {
        printf("   Negation: -zp1 = [computed]\n");
    }

    /* Inverse: result = 1/zp1 */
    rc = oabe_zp_inv(zp_result, zp1);
    if (rc == OABE_SUCCESS) {
        printf("   Inverse: 1/zp1 = [computed]\n");
    }

    /* Set to specific value */
    rc = oabe_zp_set_int(zp1, 42);
    if (rc == OABE_SUCCESS) {
        printf("   Set zp1 to integer value 42\n");
    }

    /* Clone */
    OABE_ZP *zp_clone = oabe_zp_clone(zp1);
    printf("   Cloned zp1\n");

    /* Compare */
    int cmp_result = oabe_zp_cmp(zp1, zp_clone);
    printf("   Clone equals original: %s\n", cmp_result == 0 ? "true" : "false");

    oabe_zp_free(zp1);
    oabe_zp_free(zp2);
    oabe_zp_free(zp_result);
    oabe_zp_free(zp_clone);

    /*------------------------------------------------------------------------
     * Example 4: G1 (First group) operations
     *------------------------------------------------------------------------*/
    printf("\n4. G1 (First group) operations:\n");

    /* Create G1 points */
    OABE_G1 *g1_a = oabe_g1_new(group);
    OABE_G1 *g1_b = oabe_g1_new(group);
    OABE_G1 *g1_result = oabe_g1_new(group);

    /* Get the generator */
    rc = oabe_g1_set_generator(g1_a);
    if (rc == OABE_SUCCESS) {
        printf("   Set G1 generator\n");
    }

    /* Set random point */
    oabe_g1_random(g1_b, rng);
    printf("   Created random G1 point\n");

    /* Addition: result = g1_a + g1_b */
    rc = oabe_g1_add(g1_result, g1_a, g1_b);
    if (rc == OABE_SUCCESS) {
        printf("   Point addition: G1_a + G1_b\n");
    }

    /* Subtraction: result = g1_a - g1_b */
    rc = oabe_g1_sub(g1_result, g1_a, g1_b);
    if (rc == OABE_SUCCESS) {
        printf("   Point subtraction: G1_a - G1_b\n");
    }

    /* Scalar multiplication: result = scalar * g1_a */
    OABE_ZP *scalar = oabe_zp_new(group);
    oabe_zp_random(scalar, rng);
    rc = oabe_g1_mul_scalar(g1_result, g1_a, scalar);
    if (rc == OABE_SUCCESS) {
        printf("   Scalar multiplication: scalar * G1_a\n");
    }

    /* Serialization */
    OABE_ByteString *g1_serialized = NULL;
    rc = oabe_g1_serialize(g1_a, &g1_serialized);
    if (rc == OABE_SUCCESS) {
        printf("   Serialized G1 point, size: %zu bytes\n",
               oabe_bytestring_get_size(g1_serialized));

        /* Deserialize */
        OABE_G1 *g1_deserialized = NULL;
        rc = oabe_g1_deserialize(group, g1_serialized, &g1_deserialized);
        if (rc == OABE_SUCCESS) {
            printf("   Deserialized G1 point successfully\n");
            oabe_g1_free(g1_deserialized);
        }
        oabe_bytestring_free(g1_serialized);
    }

    oabe_zp_free(scalar);
    oabe_g1_free(g1_a);
    oabe_g1_free(g1_b);
    oabe_g1_free(g1_result);

    /*------------------------------------------------------------------------
     * Example 5: G2 (Second group) operations
     *------------------------------------------------------------------------*/
    printf("\n5. G2 (Second group) operations:\n");

    /* Create G2 points */
    OABE_G2 *g2_a = oabe_g2_new(group);
    OABE_G2 *g2_b = oabe_g2_new(group);
    OABE_G2 *g2_result = oabe_g2_new(group);

    /* Get the generator */
    rc = oabe_g2_set_generator(g2_a);
    if (rc == OABE_SUCCESS) {
        printf("   Set G2 generator\n");
    }

    /* Set random point */
    oabe_g2_random(g2_b, rng);
    printf("   Created random G2 point\n");

    /* Scalar multiplication */
    scalar = oabe_zp_new(group);
    oabe_zp_set_int(scalar, 12345);
    rc = oabe_g2_mul_scalar(g2_result, g2_a, scalar);
    if (rc == OABE_SUCCESS) {
        printf("   Scalar multiplication: 12345 * G2_generator\n");
    }

    oabe_zp_free(scalar);
    oabe_g2_free(g2_a);
    oabe_g2_free(g2_b);
    oabe_g2_free(g2_result);

    /*------------------------------------------------------------------------
     * Example 6: Pairing operation (G1 x G2 -> GT)
     *------------------------------------------------------------------------*/
    printf("\n6. Pairing operation:\n");

    /* Create points */
    OABE_G1 *g1 = oabe_g1_new(group);
    OABE_G2 *g2 = oabe_g2_new(group);
    OABE_GT *gt = oabe_gt_new(group);

    /* Get generators */
    oabe_g1_set_generator(g1);
    oabe_g2_set_generator(g2);
    printf("   Created G1 and G2 generators\n");

    /* Compute pairing: e(g1, g2) */
    rc = oabe_pairing(gt, g1, g2);
    if (rc == OABE_SUCCESS) {
        printf("   Computed pairing: e(G1, G2) -> GT\n");
    }

    /* Bilinear property: e(a*P, b*Q) = e(P,Q)^(a*b) */
    OABE_ZP *a = oabe_zp_new(group);
    OABE_ZP *b = oabe_zp_new(group);
    oabe_zp_set_int(a, 5);
    oabe_zp_set_int(b, 7);

    OABE_G1 *aP = oabe_g1_new(group);
    OABE_G2 *bQ = oabe_g2_new(group);
    oabe_g1_mul_scalar(aP, g1, a);  /* aP = a * P */
    oabe_g2_mul_scalar(bQ, g2, b);  /* bQ = b * Q */

    OABE_GT *pairing_ab = oabe_gt_new(group);
    oabe_pairing(pairing_ab, aP, bQ);  /* e(aP, bQ) */

    /* GT exponentiation for comparison: e(P,Q)^(a*b) */
    OABE_ZP *ab = oabe_zp_new(group);
    oabe_zp_mul(ab, a, b);  /* ab = a * b */

    OABE_GT *gt_ab = oabe_gt_new(group);
    oabe_gt_exp(gt_ab, gt, ab);  /* gt_ab = gt^(a*b) */

    printf("   Bilinear property test: e(5P, 7Q) == e(P,Q)^35\n");
    bool bilinear_ok = oabe_gt_equals(pairing_ab, gt_ab);
    printf("   Result: %s\n", bilinear_ok ? "PASS" : "FAIL");

    oabe_zp_free(a);
    oabe_zp_free(b);
    oabe_zp_free(ab);
    oabe_g1_free(g1);
    oabe_g2_free(g2);
    oabe_g1_free(aP);
    oabe_g2_free(bQ);
    oabe_gt_free(gt);
    oabe_gt_free(pairing_ab);
    oabe_gt_free(gt_ab);

    /*------------------------------------------------------------------------
     * Cleanup
     *------------------------------------------------------------------------*/
    printf("\n7. Cleanup:\n");

    oabe_rng_free(rng);
    oabe_group_free(group);
    printf("   RNG and group freed.\n");

    oabe_shutdown();
    printf("   Library shutdown complete.\n");

    printf("\n=== Example completed successfully ===\n");
    return 0;
}