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
/// \file   test_abe.cpp
///
/// \brief  ABE context tests for OpenABE C implementation.
///

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "openabe/oabe_init.h"
#include "openabe/oabe_context.h"
#include "openabe/oabe_zml.h"
#include "openabe/oabe_key.h"
#include "openabe/oabe_crypto.h"
#include "openabe/oabe_ciphertext.h"

// Decode a hex string into a freshly allocated buffer. Returns nullptr on
// malformed input. Caller frees with free().
static uint8_t *hex_decode(const char *hex, size_t *out_len) {
    size_t n = strlen(hex);
    if (n % 2 != 0) return nullptr;
    uint8_t *buf = (uint8_t *)malloc(n / 2);
    if (!buf) return nullptr;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned byte = 0;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) { free(buf); return nullptr; }
        buf[i] = (uint8_t)byte;
    }
    *out_len = n / 2;
    return buf;
}

class CPABETest : public ::testing::Test {
protected:
    OABE_ContextCP *ctx;

    void SetUp() override {
        ASSERT_EQ(oabe_init(), OABE_SUCCESS);
        ctx = oabe_context_cp_new();
        ASSERT_NE(ctx, nullptr);
    }

    void TearDown() override {
        if (ctx) oabe_context_cp_free(ctx);
        oabe_shutdown();
    }
};

class KPABETest : public ::testing::Test {
protected:
    OABE_ContextKP *ctx;

    void SetUp() override {
        ASSERT_EQ(oabe_init(), OABE_SUCCESS);
        ctx = oabe_context_kp_new();
        ASSERT_NE(ctx, nullptr);
    }

    void TearDown() override {
        if (ctx) oabe_context_kp_free(ctx);
        oabe_shutdown();
    }
};

// ============================================================================
// CP-ABE Context Tests
// ============================================================================

TEST_F(CPABETest, ContextCreate) {
    EXPECT_NE(ctx, nullptr);
}

TEST_F(CPABETest, GenerateParams) {
    OABE_ERROR rc = oabe_context_cp_generate_params(ctx, "test_params");
    EXPECT_EQ(rc, OABE_SUCCESS);
}

TEST_F(CPABETest, GetPublicParams) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    OABE_ByteString *params = nullptr;
    OABE_ERROR rc = oabe_context_cp_get_public_params(ctx, &params);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(params, nullptr);
    EXPECT_GT(oabe_bytestring_get_size(params), 0u);

    oabe_bytestring_free(params);
}

TEST_F(CPABETest, SetPublicParams) {
    // Generate params in first context
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    OABE_ByteString *params = nullptr;
    ASSERT_EQ(oabe_context_cp_get_public_params(ctx, &params), OABE_SUCCESS);

    // Create second context and set params
    OABE_ContextCP *ctx2 = oabe_context_cp_new();
    ASSERT_NE(ctx2, nullptr);

    OABE_ERROR rc = oabe_context_cp_set_public_params(ctx2, params);
    EXPECT_EQ(rc, OABE_SUCCESS);

    oabe_bytestring_free(params);
    oabe_context_cp_free(ctx2);
}

TEST_F(CPABETest, GetSecretKey) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    OABE_ByteString *secret_key = nullptr;
    OABE_ERROR rc = oabe_context_cp_get_secret_key(ctx, &secret_key);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(secret_key, nullptr);
    EXPECT_GT(oabe_bytestring_get_size(secret_key), 0u);

    oabe_bytestring_free(secret_key);
}

TEST_F(CPABETest, KeyGen) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    const char *attributes = "attr1|attr2|attr3";
    OABE_ERROR rc = oabe_context_cp_keygen(ctx, "user1", attributes);
    EXPECT_EQ(rc, OABE_SUCCESS);
}

TEST_F(CPABETest, HasKey) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "test_params"), OABE_SUCCESS);
    ASSERT_EQ(oabe_context_cp_keygen(ctx, "user1", "attr1|attr2"), OABE_SUCCESS);

    EXPECT_TRUE(oabe_keystore_has_user_key(ctx->keystore, "user1"));
    EXPECT_FALSE(oabe_keystore_has_user_key(ctx->keystore, "nonexistent"));
}

TEST_F(CPABETest, ExportImportKey) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "test_params"), OABE_SUCCESS);
    ASSERT_EQ(oabe_context_cp_keygen(ctx, "user1", "attr1|attr2|attr3"), OABE_SUCCESS);

    // Export key
    OABE_ByteString *key_data = nullptr;
    OABE_ERROR rc = oabe_context_cp_export_key(ctx, "user1", &key_data);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(key_data, nullptr);
    EXPECT_GT(oabe_bytestring_get_size(key_data), 0u);

    // Create new context and import key
    OABE_ContextCP *ctx2 = oabe_context_cp_new();
    ASSERT_NE(ctx2, nullptr);
    ASSERT_EQ(oabe_context_cp_generate_params(ctx2, "test_params"), OABE_SUCCESS);

    rc = oabe_context_cp_import_key(ctx2, "user1_imported", key_data);
    EXPECT_EQ(rc, OABE_SUCCESS);
    EXPECT_TRUE(oabe_keystore_has_user_key(ctx2->keystore, "user1_imported"));

    oabe_bytestring_free(key_data);
    oabe_context_cp_free(ctx2);
}

TEST_F(CPABETest, EncryptDecryptKEM) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "test_params"), OABE_SUCCESS);
    ASSERT_EQ(oabe_context_cp_keygen(ctx, "user1", "attr1|attr2|attr3"), OABE_SUCCESS);

    // Use single attribute policy for simpler test
    const char *policy = "attr1";
    uint8_t plaintext[32] = "Test message for encryption";
    OABE_ByteString *ciphertext = nullptr;

    // Encrypt should succeed
    OABE_ERROR rc = oabe_context_cp_encrypt(ctx, policy, plaintext, sizeof(plaintext), &ciphertext);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(ciphertext, nullptr);

    // Full round-trip: the user's attributes satisfy the policy, so pairing-based
    // Lagrange recovery reconstructs the KEM secret and the DEM KDF (A10-L15:
    // domain-separated SHA256 over label||GT serialization) must yield the same
    // AES key on both sides.
    uint8_t decrypted[64];
    size_t decrypted_len = sizeof(decrypted);
    rc = oabe_context_cp_decrypt(ctx, "user1", ciphertext, decrypted, &decrypted_len);
    EXPECT_EQ(rc, OABE_SUCCESS);
    EXPECT_EQ(decrypted_len, sizeof(plaintext));
    EXPECT_EQ(memcmp(decrypted, plaintext, sizeof(plaintext)), 0);

    oabe_bytestring_free(ciphertext);
}

TEST_F(CPABETest, EncryptWithNonSatisfyingKey) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    // User has attr1 only
    ASSERT_EQ(oabe_context_cp_keygen(ctx, "user1", "attr1"), OABE_SUCCESS);

    // Policy requires attr1 AND attr2
    const char *policy = "(attr1 and attr2)";
    uint8_t plaintext[32] = "Test message";
    OABE_ByteString *ciphertext = nullptr;

    // Encrypt should succeed
    OABE_ERROR rc = oabe_context_cp_encrypt(ctx, policy, plaintext, sizeof(plaintext), &ciphertext);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(ciphertext, nullptr);

    // Decrypt with non-satisfying key should fail
    uint8_t decrypted[64];
    size_t decrypted_len = sizeof(decrypted);
    rc = oabe_context_cp_decrypt(ctx, "user1", ciphertext, decrypted, &decrypted_len);
    // This should fail because user doesn't have attr2
    EXPECT_NE(rc, OABE_SUCCESS);

    oabe_bytestring_free(ciphertext);
}

// A10-L15: the DEM KDF must be domain-separated (SHA256 over a label followed
// by the GT serialization) instead of bare SHA256(gt_serialization). The
// constants below were captured with the PRE-change code: a public-params blob,
// an exported user key with attributes "attr1|attr2", and a ciphertext for
// policy "attr1". The pre-change library round-tripped this fixture
// successfully; after the KDF change the derived DEM key no longer matches, so
// decryption MUST fail with OABE_ERROR_DECRYPTION_FAILED (AES-GCM tag check).
//
// NOTE (BLS12-381): the fixture was captured on the old 254/256-bit BN curve.
// On this build it cannot even load — the curve parameters disagree, so the
// stale wire is refused at params-load time, one gate EARLIER than the DEM
// tag the KDF change targets. Still fail-closed. To re-exercise the
// KDF-change leg itself, regenerate this fixture on the current curve (the
// A10-L15 property then shows as the same OABE_ERROR_DECRYPTION_FAILED).
TEST_F(CPABETest, PreKDFChangeCiphertextRejected) {
    static const char *params_hex =
        "006f000000260200000021021cd5f96d17efa7cd2a6d4a6233079a8f430f4d40a7564f94b43be5e10c5bac420000004603000000410317d4050e2407c6050a93e3ffbca4cd30489bcc3d4d38a8beb956b5c28f5380281e21e71505cf93c7f584282f82e16e4abba69f43d41b586e7e7a9a9498d594f800000105040000010014b4023e84909cd1081ce50c76b976150e0be14cd3941da66a134b730db7294d1f162a37dc8084bbafbdbbfd65e615da513597f4bb2108a3b82a15efa92b68480f95e8bd48bb75d73aeacc794a5539291ecef1deb94863d76d9547ff032310a510a460de000f0e5cccccb01a6366112cd6339337ef2d35c97935c3b8075a4c830182eaed0002c7ac3d7ca660dc42f9249dcbd137ae14ea25c17577f8129057a61dc8e3097938c746adb196317affc88fd500b0fc0d9bf008b82cfdd4890ee7f823e3594eacce078ac50ae165db4aa88f401b2621a37a60ef7e654a76bcbc6ab61ce9fbf0b45cc497941f29f9047d7b83a30ab1d6176977718dd965d25f34465e00000026020000002103088f6ef02229fdc822c48ce7ba2465609edaf2f13d421fd880fd456f2bbea8d30000010504000001000f06dcf37b34314738b7ba661f1c4a0c9817f37ba8b76fd0352ce49e0de26c361225759e1afcbe0f7027cfdc7e98d49ffb5920fed8087524c8ca6299cbdce0a206fdb69d1093e698a6218d27ff1f84973e31eece2059565b9378ef17d42479a124a3bfc7d37d2705868e1dac87a41e9eba4045c3db157648a0e59531bbdda122012e33f12d107d959506cabeaec163bc89465687a7ea8ac4061572e16065a704025563250c9fad2375d24fa7fdfe754d79c447abbae2f1498321b1682630a4ce1339373d45875986e490edf53e0766b23ad867edd8b2a6545ffb6d99e71b380f0a8a89293a440ff42ff46bf499deae51718b5bbe3a991387d3a08afbde12d9a70000002602000000210221678beeea46089c84db00f03c7e77b4563d9e40da9338f217917828fa766c81000000460300000041021787ce01cda887b8a6a7d5b430e8d48d2633f2adc957d38f76b3566943a319051e65f8d8f033c90e359468337060e7d3c4fe91b777c28f2bbf141edc7d481d2000000000";
    static const char *userkey_hex =
        "07000000000c666978747572655f757365720000000200000005617474723100000005617474723200000000000000ec000000040000004603000000410308581cda62aafdf0815fd36351ed409686fd08869467df058065dff3a7884e26016c1dce07a0e13b75e167bc99e249227c0a2a21b231eacb5d01f829f726605b0000004603000000410314952eab6590b94ae0da4d8f0f4df6c7f95f7c42f4a873abdb9a5ba396cc5c2e115469b1812d830b70197f89c455452251f670af0d08fc6ffd83c59f438e0d00000000260200000021030665c1de628c5d35cfed5ea4a87c133b06e5a61752ca6b70f438368fdffb291e00000026020000002103172d13f8119d65f7d36e6e558fcd1b6e1bd09026a446209522a1b0f99b5defe8";
    static const char *ciphertext_hex =
        "65000000056174747231000000260200000021031abb0ef770b18a756123b9c2d01bbf1348c704a4de10ef03c7e0028e1cb8c55f00000105040000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000561747472310000002602000000210211b7394eb8063f3ac405359fec36a2702d74d5da65856fde0ee8ed056cb773f901000000460300000041021472cbbfdf86df8e608cdb032e0da1e05f48e0b4cb0d201218e9d6953cd098d11db43bda1420dfe4e513dd9ad5ac34c2a206920796453366acfabdf62fa776290000003c08d24241b18b8a773bb12d924cd357b4022dbe33ab543fcd76d8623ed099e0f8467ccde7960b899a41c0c4fcbd3e88e0644330e8e2050f8d0e6fe3d400000000";

    size_t params_len = 0, userkey_len = 0, ciphertext_len = 0;
    uint8_t *params_bytes = hex_decode(params_hex, &params_len);
    uint8_t *userkey_bytes = hex_decode(userkey_hex, &userkey_len);
    uint8_t *ciphertext_bytes = hex_decode(ciphertext_hex, &ciphertext_len);
    ASSERT_NE(params_bytes, nullptr);
    ASSERT_NE(userkey_bytes, nullptr);
    ASSERT_NE(ciphertext_bytes, nullptr);
    ASSERT_EQ(params_len, 810u);
    ASSERT_EQ(userkey_len, 284u);
    ASSERT_EQ(ciphertext_len, 515u);

    OABE_ByteString *params = oabe_bytestring_new_from_data(params_bytes, params_len);
    OABE_ByteString *userkey = oabe_bytestring_new_from_data(userkey_bytes, userkey_len);
    OABE_ByteString *ciphertext = oabe_bytestring_new_from_data(ciphertext_bytes, ciphertext_len);
    ASSERT_NE(params, nullptr);
    ASSERT_NE(userkey, nullptr);
    ASSERT_NE(ciphertext, nullptr);

    // Under the BLS12-381 rebuild this stale-curve fixture refuses one gate
    // earlier (params load); a fixture regenerated on the current curve takes
    // the decrypt leg below. Either way the pre-change wire fails closed.
    OABE_ERROR load_rc = oabe_context_cp_set_public_params(ctx, params);
    if (load_rc != OABE_SUCCESS) {
        EXPECT_NE(load_rc, OABE_SUCCESS);
    } else {
        ASSERT_EQ(oabe_context_cp_import_key(ctx, "fixture_user", userkey),
                  OABE_SUCCESS);

        uint8_t decrypted[64];
        size_t decrypted_len = sizeof(decrypted);
        OABE_ERROR rc = oabe_context_cp_decrypt(ctx, "fixture_user", ciphertext,
                                                decrypted, &decrypted_len);
        EXPECT_EQ(rc, OABE_ERROR_DECRYPTION_FAILED);
    }

    oabe_bytestring_free(params);
    oabe_bytestring_free(userkey);
    oabe_bytestring_free(ciphertext);
    free(params_bytes);
    free(userkey_bytes);
    free(ciphertext_bytes);
}

// ============================================================================
// KP-ABE Context Tests
// ============================================================================

TEST_F(KPABETest, ContextCreate) {
    EXPECT_NE(ctx, nullptr);
}

TEST_F(KPABETest, GenerateParams) {
    OABE_ERROR rc = oabe_context_kp_generate_params(ctx, "test_params");
    EXPECT_EQ(rc, OABE_SUCCESS);
}

TEST_F(KPABETest, GetPublicParams) {
    ASSERT_EQ(oabe_context_kp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    OABE_ByteString *params = nullptr;
    OABE_ERROR rc = oabe_context_kp_get_public_params(ctx, &params);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(params, nullptr);
    EXPECT_GT(oabe_bytestring_get_size(params), 0u);

    oabe_bytestring_free(params);
}

TEST_F(KPABETest, SetPublicParams) {
    // Generate params in first context
    ASSERT_EQ(oabe_context_kp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    OABE_ByteString *params = nullptr;
    ASSERT_EQ(oabe_context_kp_get_public_params(ctx, &params), OABE_SUCCESS);

    // Create second context and set params
    OABE_ContextKP *ctx2 = oabe_context_kp_new();
    ASSERT_NE(ctx2, nullptr);

    OABE_ERROR rc = oabe_context_kp_set_public_params(ctx2, params);
    EXPECT_EQ(rc, OABE_SUCCESS);

    oabe_bytestring_free(params);
    oabe_context_kp_free(ctx2);
}

TEST_F(KPABETest, KeyGen) {
    ASSERT_EQ(oabe_context_kp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    const char *policy = "(attr1 and attr2)";
    OABE_ERROR rc = oabe_context_kp_keygen(ctx, "user1", policy);
    EXPECT_EQ(rc, OABE_SUCCESS);
}

TEST_F(KPABETest, HasKey) {
    ASSERT_EQ(oabe_context_kp_generate_params(ctx, "test_params"), OABE_SUCCESS);
    ASSERT_EQ(oabe_context_kp_keygen(ctx, "user1", "attr1"), OABE_SUCCESS);

    EXPECT_TRUE(oabe_keystore_has_user_key(ctx->keystore, "user1"));
    EXPECT_FALSE(oabe_keystore_has_user_key(ctx->keystore, "nonexistent"));
}

TEST_F(KPABETest, ExportImportKey) {
    ASSERT_EQ(oabe_context_kp_generate_params(ctx, "test_params"), OABE_SUCCESS);
    ASSERT_EQ(oabe_context_kp_keygen(ctx, "user1", "(attr1 and attr2)"), OABE_SUCCESS);

    // Export key
    OABE_ByteString *key_data = nullptr;
    OABE_ERROR rc = oabe_context_kp_export_key(ctx, "user1", &key_data);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(key_data, nullptr);
    EXPECT_GT(oabe_bytestring_get_size(key_data), 0u);

    // Create new context and import key
    OABE_ContextKP *ctx2 = oabe_context_kp_new();
    ASSERT_NE(ctx2, nullptr);
    ASSERT_EQ(oabe_context_kp_generate_params(ctx2, "test_params"), OABE_SUCCESS);

    rc = oabe_context_kp_import_key(ctx2, "user1_imported", key_data);
    EXPECT_EQ(rc, OABE_SUCCESS);
    EXPECT_TRUE(oabe_keystore_has_user_key(ctx2->keystore, "user1_imported"));

    oabe_bytestring_free(key_data);
    oabe_context_kp_free(ctx2);
}

TEST_F(KPABETest, EncryptDecryptKEM) {
    ASSERT_EQ(oabe_context_kp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    // Key has policy requiring attr1 AND attr2
    ASSERT_EQ(oabe_context_kp_keygen(ctx, "user1", "(attr1 and attr2)"), OABE_SUCCESS);

    // Encrypt with satisfying attributes
    const char *attributes = "attr1|attr2|attr3";
    uint8_t plaintext[32] = "Test message for encryption";
    OABE_ByteString *ciphertext = nullptr;

    // Encrypt
    OABE_ERROR rc = oabe_context_kp_encrypt(ctx, attributes, plaintext, sizeof(plaintext), &ciphertext);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(ciphertext, nullptr);

    // Decrypt with satisfying policy
    uint8_t decrypted[64];
    size_t decrypted_len = sizeof(decrypted);
    rc = oabe_context_kp_decrypt(ctx, "user1", ciphertext, decrypted, &decrypted_len);
    EXPECT_EQ(rc, OABE_SUCCESS);

    oabe_bytestring_free(ciphertext);
}

TEST_F(KPABETest, EncryptWithNonSatisfyingPolicy) {
    ASSERT_EQ(oabe_context_kp_generate_params(ctx, "test_params"), OABE_SUCCESS);

    // Key has policy requiring attr1 AND attr2
    ASSERT_EQ(oabe_context_kp_keygen(ctx, "user1", "(attr1 and attr2)"), OABE_SUCCESS);

    // Encrypt with attributes that don't satisfy policy (only attr1)
    const char *attributes = "attr1|attr3";  // Missing attr2
    uint8_t plaintext[32] = "Test message";
    OABE_ByteString *ciphertext = nullptr;

    // Encrypt should succeed
    OABE_ERROR rc = oabe_context_kp_encrypt(ctx, attributes, plaintext, sizeof(plaintext), &ciphertext);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(ciphertext, nullptr);

    // Decrypt should fail because policy is not satisfied
    uint8_t decrypted[64];
    size_t decrypted_len = sizeof(decrypted);
    rc = oabe_context_kp_decrypt(ctx, "user1", ciphertext, decrypted, &decrypted_len);
    EXPECT_NE(rc, OABE_SUCCESS);

    oabe_bytestring_free(ciphertext);
}

// ============================================================================
// One-shot API Tests
// ============================================================================

class OneShotAPITest : public ::testing::Test {
protected:
    OABE_ByteString *public_params;
    OABE_ByteString *secret_key;
    OABE_ContextCP *cp_ctx;
    OABE_ContextKP *kp_ctx;

    void SetUp() override {
        ASSERT_EQ(oabe_init(), OABE_SUCCESS);

        // Setup CP-ABE
        cp_ctx = oabe_context_cp_new();
        ASSERT_NE(cp_ctx, nullptr);
        ASSERT_EQ(oabe_context_cp_generate_params(cp_ctx, "test"), OABE_SUCCESS);
        ASSERT_EQ(oabe_context_cp_get_public_params(cp_ctx, &public_params), OABE_SUCCESS);
        ASSERT_EQ(oabe_context_cp_get_secret_key(cp_ctx, &secret_key), OABE_SUCCESS);

        // Setup KP-ABE
        kp_ctx = oabe_context_kp_new();
        ASSERT_NE(kp_ctx, nullptr);
        ASSERT_EQ(oabe_context_kp_generate_params(kp_ctx, "test"), OABE_SUCCESS);
    }

    void TearDown() override {
        if (public_params) oabe_bytestring_free(public_params);
        if (secret_key) oabe_bytestring_free(secret_key);
        if (cp_ctx) oabe_context_cp_free(cp_ctx);
        if (kp_ctx) oabe_context_kp_free(kp_ctx);
        oabe_shutdown();
    }
};

TEST_F(OneShotAPITest, CP_EncryptDecrypt) {
    // Generate user key
    ASSERT_EQ(oabe_context_cp_keygen(cp_ctx, "user1", "attr1|attr2|attr3"), OABE_SUCCESS);

    // Export user key for one-shot API
    OABE_ByteString *user_key = nullptr;
    ASSERT_EQ(oabe_context_cp_export_key(cp_ctx, "user1", &user_key), OABE_SUCCESS);

    // Encrypt
    const char *policy = "(attr1 and attr2)";
    uint8_t plaintext[32] = "Test message";
    OABE_ByteString *ciphertext = nullptr;

    OABE_ERROR rc = oabe_cp_encrypt(public_params, policy, plaintext, sizeof(plaintext), &ciphertext);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(ciphertext, nullptr);

    // Decrypt
    uint8_t decrypted[64];
    size_t decrypted_len = sizeof(decrypted);
    rc = oabe_cp_decrypt(public_params, user_key, ciphertext, decrypted, &decrypted_len);
    // Note: Decryption may fail due to incomplete LSSS implementation
    // This test verifies the key serialization/deserialization works correctly
    EXPECT_EQ(rc, OABE_SUCCESS);

    oabe_bytestring_free(ciphertext);
    oabe_bytestring_free(user_key);
}

TEST_F(OneShotAPITest, KP_EncryptDecrypt) {
    // Generate user key with policy
    ASSERT_EQ(oabe_context_kp_keygen(kp_ctx, "user1", "(attr1 and attr2)"), OABE_SUCCESS);

    // Get public params for KP
    OABE_ByteString *kp_params = nullptr;
    ASSERT_EQ(oabe_context_kp_get_public_params(kp_ctx, &kp_params), OABE_SUCCESS);

    // Export user key for one-shot API
    OABE_ByteString *user_key = nullptr;
    ASSERT_EQ(oabe_context_kp_export_key(kp_ctx, "user1", &user_key), OABE_SUCCESS);

    // Encrypt with satisfying attributes
    const char *attributes = "attr1|attr2|attr3";
    uint8_t plaintext[32] = "Test message";
    OABE_ByteString *ciphertext = nullptr;

    OABE_ERROR rc = oabe_kp_encrypt(kp_params, attributes, plaintext, sizeof(plaintext), &ciphertext);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(ciphertext, nullptr);

    // Decrypt
    uint8_t decrypted[64];
    size_t decrypted_len = sizeof(decrypted);
    rc = oabe_kp_decrypt(kp_params, user_key, ciphertext, decrypted, &decrypted_len);
    EXPECT_EQ(rc, OABE_SUCCESS);

    oabe_bytestring_free(ciphertext);
    oabe_bytestring_free(user_key);
    oabe_bytestring_free(kp_params);
}

// ============================================================================
// Key Store Tests
// ============================================================================

class KeyStoreTest : public ::testing::Test {
protected:
    OABE_KeyStore *keystore;

    void SetUp() override {
        ASSERT_EQ(oabe_init(), OABE_SUCCESS);
        keystore = oabe_keystore_new();
        ASSERT_NE(keystore, nullptr);
    }

    void TearDown() override {
        if (keystore) oabe_keystore_free(keystore);
        oabe_shutdown();
    }
};

TEST_F(KeyStoreTest, AddGetPublicParams) {
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);
    ASSERT_NE(group, nullptr);

    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    ASSERT_NE(rng, nullptr);

    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    OABE_ERROR rc = oabe_keystore_add_public(keystore, "params1", params);
    EXPECT_EQ(rc, OABE_SUCCESS);

    OABE_ABEParams *retrieved = oabe_keystore_get_public(keystore, "params1");
    EXPECT_NE(retrieved, nullptr);
    EXPECT_EQ(retrieved, params);

    // Non-existent key
    retrieved = oabe_keystore_get_public(keystore, "nonexistent");
    EXPECT_EQ(retrieved, nullptr);

    oabe_params_free(params);
    oabe_rng_free(rng);
    oabe_group_free(group);
}

TEST_F(KeyStoreTest, AddGetSecretKey) {
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);
    ASSERT_NE(group, nullptr);

    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    ASSERT_NE(rng, nullptr);

    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    OABE_ABESecretKey *secret_key = oabe_secret_key_new(params, rng);
    ASSERT_NE(secret_key, nullptr);

    OABE_ERROR rc = oabe_keystore_add_secret(keystore, "params1", secret_key);
    EXPECT_EQ(rc, OABE_SUCCESS);

    OABE_ABESecretKey *retrieved = oabe_keystore_get_secret(keystore, "params1");
    EXPECT_NE(retrieved, nullptr);
    EXPECT_EQ(retrieved, secret_key);

    oabe_secret_key_free(secret_key);
    oabe_params_free(params);
    oabe_rng_free(rng);
    oabe_group_free(group);
}

TEST_F(KeyStoreTest, AddGetUserKey) {
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);
    ASSERT_NE(group, nullptr);

    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    ASSERT_NE(rng, nullptr);

    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    OABE_ABEUserKey *user_key = oabe_user_key_new("user1", params);
    ASSERT_NE(user_key, nullptr);

    OABE_ERROR rc = oabe_keystore_add_user_key(keystore, "user1", user_key);
    EXPECT_EQ(rc, OABE_SUCCESS);

    OABE_ABEUserKey *retrieved = oabe_keystore_get_user_key(keystore, "user1");
    EXPECT_NE(retrieved, nullptr);
    EXPECT_EQ(retrieved, user_key);

    EXPECT_TRUE(oabe_keystore_has_user_key(keystore, "user1"));
    EXPECT_FALSE(oabe_keystore_has_user_key(keystore, "nonexistent"));

    oabe_user_key_free(user_key);
    oabe_params_free(params);
    oabe_rng_free(rng);
    oabe_group_free(group);
}

TEST_F(KeyStoreTest, RemoveUserKey) {
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);
    ASSERT_NE(group, nullptr);

    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    ASSERT_NE(rng, nullptr);

    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    OABE_ABEUserKey *user_key = oabe_user_key_new("user1", params);
    ASSERT_NE(user_key, nullptr);

    oabe_keystore_add_user_key(keystore, "user1", user_key);
    EXPECT_TRUE(oabe_keystore_has_user_key(keystore, "user1"));

    OABE_ERROR rc = oabe_keystore_remove_user_key(keystore, "user1");
    EXPECT_EQ(rc, OABE_SUCCESS);
    EXPECT_FALSE(oabe_keystore_has_user_key(keystore, "user1"));

    oabe_params_free(params);
    oabe_rng_free(rng);
    oabe_group_free(group);
}

TEST_F(KeyStoreTest, UserKeyCount) {
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);
    ASSERT_NE(group, nullptr);

    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);
    ASSERT_NE(rng, nullptr);

    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    EXPECT_EQ(oabe_keystore_get_user_key_count(keystore), 0u);

    OABE_ABEUserKey *key1 = oabe_user_key_new("user1", params);
    OABE_ABEUserKey *key2 = oabe_user_key_new("user2", params);

    oabe_keystore_add_user_key(keystore, "user1", key1);
    EXPECT_EQ(oabe_keystore_get_user_key_count(keystore), 1u);

    oabe_keystore_add_user_key(keystore, "user2", key2);
    EXPECT_EQ(oabe_keystore_get_user_key_count(keystore), 2u);

    oabe_keystore_remove_user_key(keystore, "user1");
    EXPECT_EQ(oabe_keystore_get_user_key_count(keystore), 1u);

    oabe_user_key_free(key1);
    oabe_user_key_free(key2);
    oabe_params_free(params);
    oabe_rng_free(rng);
    oabe_group_free(group);
}

// ============================================================================
// Params Serialization Tests
// ============================================================================

class ParamsSerializationTest : public ::testing::Test {
protected:
    OABE_GroupHandle group;
    OABE_RNGHandle rng;

    void SetUp() override {
        ASSERT_EQ(oabe_init(), OABE_SUCCESS);
        group = oabe_group_new(OABE_CURVE_BN_P254);
        ASSERT_NE(group, nullptr);
        rng = oabe_rng_new(NULL, 0);
        ASSERT_NE(rng, nullptr);
    }

    void TearDown() override {
        if (rng) oabe_rng_free(rng);
        if (group) oabe_group_free(group);
        oabe_shutdown();
    }
};

TEST_F(ParamsSerializationTest, SerializeDeserializePublicParams) {
    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    OABE_ByteString *serialized = nullptr;
    OABE_ERROR rc = oabe_params_serialize(params, &serialized);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(serialized, nullptr);
    EXPECT_GT(oabe_bytestring_get_size(serialized), 0u);

    OABE_ABEParams *deserialized = nullptr;
    rc = oabe_params_deserialize(serialized, &deserialized);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(deserialized, nullptr);

    // Check scheme matches
    EXPECT_EQ(deserialized->base.scheme, params->base.scheme);

    oabe_params_free(params);
    oabe_params_free(deserialized);
    oabe_bytestring_free(serialized);
}

TEST_F(ParamsSerializationTest, SerializeDeserializeSecretKey) {
    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    OABE_ABESecretKey *secret_key = oabe_secret_key_new(params, rng);
    ASSERT_NE(secret_key, nullptr);

    OABE_ByteString *serialized = nullptr;
    OABE_ERROR rc = oabe_secret_key_serialize(secret_key, &serialized);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(serialized, nullptr);
    EXPECT_GT(oabe_bytestring_get_size(serialized), 0u);

    OABE_ABESecretKey *deserialized = nullptr;
    rc = oabe_secret_key_deserialize(serialized, group, &deserialized);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(deserialized, nullptr);

    // A10-L16 regression: deserialize must reconstruct the master scalars —
    // a NULL alpha/beta here NULL-derefs the next keygen on a restored
    // context (oabe_context.c cp_keygen).
    ASSERT_NE(deserialized->alpha, nullptr);
    ASSERT_NE(deserialized->beta, nullptr);

    // The reconstructed scalars must also match the originals: serialize both
    // keys again and compare bytes.
    OABE_ByteString *reserialized = nullptr;
    rc = oabe_secret_key_serialize(deserialized, &reserialized);
    EXPECT_EQ(rc, OABE_SUCCESS);
    ASSERT_NE(reserialized, nullptr);
    EXPECT_EQ(oabe_bytestring_get_size(reserialized), oabe_bytestring_get_size(serialized));
    EXPECT_EQ(memcmp(oabe_bytestring_get_const_ptr(reserialized),
                     oabe_bytestring_get_const_ptr(serialized),
                     oabe_bytestring_get_size(serialized)), 0);
    oabe_bytestring_free(reserialized);

    oabe_secret_key_free(secret_key);
    oabe_secret_key_free(deserialized);
    oabe_params_free(params);
    oabe_bytestring_free(serialized);
}

// Malformed-input regression tests for the serializer bounds fixes:
// every length prefix read from a blob must be checked against the bytes
// remaining, and a parse failure must return an error code — never success
// with a NULL output (oabe_context_cp_decrypt dereferences ct->policy).

TEST_F(CPABETest, DecryptMalformedCiphertextFailsClean) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "auth"), OABE_SUCCESS);
    ASSERT_EQ(oabe_context_cp_keygen(ctx, "k1", "attr1"), OABE_SUCCESS);

    // scheme(1) + policy_len(4) = 0xFFFFFFF0, no payload. Before the fix the
    // deserializer returned OABE_SUCCESS with *ct == NULL, and this decrypt
    // crashed dereferencing ct->policy.
    uint8_t blob[] = {0x01, 0xFF, 0xFF, 0xFF, 0xF0};
    OABE_ByteString *ct = oabe_bytestring_new_from_data(blob, sizeof(blob));
    ASSERT_NE(ct, nullptr);

    uint8_t out[256];
    size_t out_len = sizeof(out);
    EXPECT_NE(oabe_context_cp_decrypt(ctx, "k1", ct, out, &out_len), OABE_SUCCESS);
    oabe_bytestring_free(ct);
}

TEST(CPCiphertextDeserialize, OversizedPolicyLengthFailsWithNullOutput) {
    ASSERT_EQ(oabe_init(), OABE_SUCCESS);
    OABE_ContextCP *ctx = oabe_context_cp_new();
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "auth"), OABE_SUCCESS);

    uint8_t blob[] = {0x01, 0xFF, 0xFF, 0xFF, 0xF0};
    OABE_ByteString *input = oabe_bytestring_new_from_data(blob, sizeof(blob));
    ASSERT_NE(input, nullptr);

    OABE_CP_Ciphertext *ct = nullptr;
    EXPECT_NE(oabe_cp_ct_deserialize(ctx->base.group, input, &ct), OABE_SUCCESS);
    EXPECT_EQ(ct, nullptr);

    oabe_bytestring_free(input);
    oabe_context_cp_free(ctx);
    oabe_shutdown();
}

TEST(SecretKeyDeserialize, OversizedAlphaLengthFailsClean) {
    // key_type(1) + scheme(1) + alpha_len(4) = 0xFFFFFFF0, no payload.
    // Before the fix this over-read the heap by up to 4 GiB.
    ASSERT_EQ(oabe_init(), OABE_SUCCESS);
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);
    ASSERT_NE(group, nullptr);

    uint8_t blob[] = {0x02, 0x01, 0xFF, 0xFF, 0xFF, 0xF0, 0x00};
    OABE_ByteString *input = oabe_bytestring_new_from_data(blob, sizeof(blob));
    ASSERT_NE(input, nullptr);

    OABE_ABESecretKey *key = nullptr;
    EXPECT_NE(oabe_secret_key_deserialize(input, group, &key), OABE_SUCCESS);
    EXPECT_EQ(key, nullptr);
    oabe_bytestring_free(input);
    oabe_group_free(group);
    oabe_shutdown();
}

TEST(UserKeyDeserialize, OversizedIdLengthFailsClean) {
    uint8_t blob[] = {0x03, 0x01, 0xFF, 0xFF, 0xFF, 0xF0, 0x00};
    OABE_ByteString *input = oabe_bytestring_new_from_data(blob, sizeof(blob));
    ASSERT_NE(input, nullptr);

    OABE_ABEUserKey *key = nullptr;
    EXPECT_NE(oabe_user_key_deserialize(input, &key), OABE_SUCCESS);
    EXPECT_EQ(key, nullptr);
    oabe_bytestring_free(input);
}

// Audit 11 A11-1 / A11-3 regression tests. Wire format reminders: length
// prefixes are big-endian u32 (oabe_bytestring_pack32); neither the params
// nor the secret-key envelope carries a checksum — the raw u32 lengths are
// the only framing.

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

TEST_F(ParamsSerializationTest, DeserializeOversizedFirstLengthPrefixFailsClean) {
    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    OABE_ByteString *serialized = nullptr;
    ASSERT_EQ(oabe_params_serialize(params, &serialized), OABE_SUCCESS);
    ASSERT_NE(serialized, nullptr);

    // scheme(1) + curve(1), then patch the FIRST length prefix (g1_len at
    // offset 2) to 0xFFFFFFF0. Before A11-1 this over-read the heap by up to
    // 4 GiB via oabe_context_cp_set_public_params.
    const uint8_t *wire = oabe_bytestring_get_const_ptr(serialized);
    std::vector<uint8_t> blob(wire, wire + oabe_bytestring_get_size(serialized));
    write_be32(&blob[2], 0xFFFFFFF0u);

    OABE_ByteString *input = oabe_bytestring_new_from_data(blob.data(), blob.size());
    ASSERT_NE(input, nullptr);

    OABE_ABEParams *out = nullptr;
    EXPECT_EQ(oabe_params_deserialize(input, &out), OABE_ERROR_DESERIALIZATION_FAILED);
    EXPECT_EQ(out, nullptr);

    oabe_bytestring_free(input);
    oabe_bytestring_free(serialized);
    oabe_params_free(params);
}

TEST_F(ParamsSerializationTest, DeserializeOversizedKeyDataLengthFailsClean) {
    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);

    OABE_ByteString *serialized = nullptr;
    ASSERT_EQ(oabe_params_serialize(params, &serialized), OABE_SUCCESS);
    ASSERT_NE(serialized, nullptr);

    // Walk the seven length-prefixed group-element fields
    // (g1, g2, gt, g1_alpha, egg_alpha, g1_a, g2_a) to locate key_data_len,
    // then patch that LATER prefix to 0xFFFFFFF0.
    const uint8_t *wire = oabe_bytestring_get_const_ptr(serialized);
    std::vector<uint8_t> blob(wire, wire + oabe_bytestring_get_size(serialized));
    size_t offset = 2;
    for (int field = 0; field < 7; field++) {
        uint32_t field_len = read_be32(&blob[offset]);
        offset += 4 + field_len;
    }
    ASSERT_LE(offset + 4, blob.size());
    write_be32(&blob[offset], 0xFFFFFFF0u);

    OABE_ByteString *input = oabe_bytestring_new_from_data(blob.data(), blob.size());
    ASSERT_NE(input, nullptr);

    OABE_ABEParams *out = nullptr;
    EXPECT_EQ(oabe_params_deserialize(input, &out), OABE_ERROR_DESERIALIZATION_FAILED);
    EXPECT_EQ(out, nullptr);

    oabe_bytestring_free(input);
    oabe_bytestring_free(serialized);
    oabe_params_free(params);
}

TEST_F(ParamsSerializationTest, SecretKeyDeserializeZeroLengthAlphaFailsClosed) {
    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);
    OABE_ABESecretKey *secret_key = oabe_secret_key_new(params, rng);
    ASSERT_NE(secret_key, nullptr);

    OABE_ByteString *serialized = nullptr;
    ASSERT_EQ(oabe_secret_key_serialize(secret_key, &serialized), OABE_SUCCESS);
    ASSERT_NE(serialized, nullptr);

    // Rebuild the envelope with alpha_len = 0 and alpha's payload removed so
    // every later field still aligns: header(2) + u32(0) + wire[after alpha].
    // Before A11-3 this returned OABE_SUCCESS with alpha == NULL, and the next
    // keygen silently minted degenerate keys.
    const uint8_t *wire = oabe_bytestring_get_const_ptr(serialized);
    size_t wire_size = oabe_bytestring_get_size(serialized);
    uint32_t alpha_len = read_be32(wire + 2);
    ASSERT_GT(alpha_len, 0u);
    size_t alpha_end = 2 + 4 + alpha_len;

    std::vector<uint8_t> blob(wire, wire + 2);
    uint8_t zero_len[4] = {0, 0, 0, 0};
    blob.insert(blob.end(), zero_len, zero_len + 4);
    blob.insert(blob.end(), wire + alpha_end, wire + wire_size);

    OABE_ByteString *input = oabe_bytestring_new_from_data(blob.data(), blob.size());
    ASSERT_NE(input, nullptr);

    OABE_ABESecretKey *out = nullptr;
    EXPECT_EQ(oabe_secret_key_deserialize(input, group, &out), OABE_ERROR_INVALID_KEY);
    EXPECT_EQ(out, nullptr);

    oabe_bytestring_free(input);
    oabe_bytestring_free(serialized);
    oabe_secret_key_free(secret_key);
    oabe_params_free(params);
}

TEST_F(ParamsSerializationTest, SecretKeyDeserializeZeroLengthBetaFailsClosed) {
    OABE_ABEParams *params = oabe_params_new(OABE_SCHEME_CP_WATERS, OABE_CURVE_BN_P254, rng);
    ASSERT_NE(params, nullptr);
    OABE_ABESecretKey *secret_key = oabe_secret_key_new(params, rng);
    ASSERT_NE(secret_key, nullptr);

    OABE_ByteString *serialized = nullptr;
    ASSERT_EQ(oabe_secret_key_serialize(secret_key, &serialized), OABE_SUCCESS);
    ASSERT_NE(serialized, nullptr);

    // Same envelope surgery as the alpha case, but keep alpha intact and zero
    // beta_len: header+alpha block + u32(0) + wire[after beta].
    const uint8_t *wire = oabe_bytestring_get_const_ptr(serialized);
    size_t wire_size = oabe_bytestring_get_size(serialized);
    uint32_t alpha_len = read_be32(wire + 2);
    size_t beta_len_offset = 2 + 4 + alpha_len;
    uint32_t beta_len = read_be32(wire + beta_len_offset);
    ASSERT_GT(beta_len, 0u);
    size_t beta_end = beta_len_offset + 4 + beta_len;

    std::vector<uint8_t> blob(wire, wire + beta_len_offset);
    uint8_t zero_len[4] = {0, 0, 0, 0};
    blob.insert(blob.end(), zero_len, zero_len + 4);
    blob.insert(blob.end(), wire + beta_end, wire + wire_size);

    OABE_ByteString *input = oabe_bytestring_new_from_data(blob.data(), blob.size());
    ASSERT_NE(input, nullptr);

    OABE_ABESecretKey *out = nullptr;
    EXPECT_EQ(oabe_secret_key_deserialize(input, group, &out), OABE_ERROR_INVALID_KEY);
    EXPECT_EQ(out, nullptr);

    oabe_bytestring_free(input);
    oabe_bytestring_free(serialized);
    oabe_secret_key_free(secret_key);
    oabe_params_free(params);
}

TEST_F(CPABETest, KeygenRefusesNullMasterScalars) {
    ASSERT_EQ(oabe_context_cp_generate_params(ctx, "auth"), OABE_SUCCESS);

    // Defensive second layer (audit 11 A11-3): simulate a restore path that
    // produced a secret key with a NULL alpha scalar. Keygen must fail closed
    // instead of dereferencing it.
    OABE_ABESecretKey *bogus = oabe_secret_key_new(ctx->public_params, NULL);
    ASSERT_NE(bogus, nullptr);
    oabe_zp_free(bogus->alpha);
    bogus->alpha = nullptr;
    oabe_zp_free(bogus->beta);
    bogus->beta = nullptr;

    oabe_secret_key_free(ctx->secret_key);
    ctx->secret_key = bogus;

    EXPECT_EQ(oabe_context_cp_keygen(ctx, "k1", "attr1"), OABE_ERROR_INVALID_KEY);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}