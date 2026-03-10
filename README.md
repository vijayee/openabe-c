# OpenABE C Implementation

Pure C implementation of the OpenABE (Attribute-Based Encryption) library.

## Overview

This is a C translation of the original OpenABE C++ library. It provides:

- **CP-ABE (Ciphertext-Policy Attribute-Based Encryption)**: Waters '09 scheme
- **KP-ABE (Key-Policy Attribute-Based Encryption)**: GPSW '06 scheme
- **Symmetric Key Encryption**: AES-GCM
- **Mathematical Operations**: ZML layer for pairing-based cryptography

## Directory Structure

```
openabe-c/
├── include/openabe/     # Public header files
│   ├── oabe_types.h     # Core types, error codes, constants
│   ├── oabe_memory.h    # Memory management, reference counting
│   ├── oabe_bytestring.h # ByteString container
│   ├── oabe_init.h      # Library initialization
│   ├── oabe_zml.h       # ZML math types (ZP, G1, G2, GT)
│   ├── oabe_policy.h    # Policy parsing, LSSS
│   └── oabe_crypto.h    # High-level cryptographic API
├── src/
│   ├── core/            # Core functionality
│   ├── zml/             # Math layer
│   ├── utils/           # Utility functions
│   ├── keys/            # Key management
│   ├── abe/             # ABE schemes
│   ├── ske/             # Symmetric key encryption
│   └── api/             # Public API implementation
├── tests/               # Test files (gtest)
├── examples/            # Example programs
├── deps/                # Dependencies
└── Makefile             # Build system
```

## Building

### Prerequisites

- GCC or Clang with C11 support
- GNU Make
- OpenSSL or RELIC (for pairing operations)
- GMP (GNU Multiple Precision Arithmetic Library)
- Google Test (for tests)

### Compile

```bash
# Default build (uses RELIC)
make

# Use OpenSSL for pairing operations
make BP_WITH_OPENSSL=1

# Debug build
make DEBUG=1

# Build tests
make tests

# Run tests
make test

# Build examples
make examples

# Install (requires PREFIX to be set)
make install PREFIX=/usr/local
```

## Usage Example

### CP-ABE Encryption

```c
#include <stdio.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_crypto.h"

int main(void) {
    // Initialize library
    oabe_init();

    // Create CP-ABE context
    OABE_Context *ctx = oabe_context_cp_waters_new();

    // Generate parameters
    oabe_context_generate_params(ctx, "auth1");

    // Generate key for user with attributes
    OABE_ByteString *secret_key = NULL;
    oabe_context_keygen(ctx, "user1", "attr1|attr2|attr3", &secret_key);

    // Encrypt with policy
    const char *plaintext = "Secret message";
    OABE_ByteString *ciphertext = NULL;
    oabe_context_encrypt(ctx, "(attr1 and attr2) or attr3",
                        (const uint8_t*)plaintext, strlen(plaintext),
                        &ciphertext);

    // Decrypt
    uint8_t buffer[1024];
    size_t buffer_len = sizeof(buffer);
    oabe_context_decrypt(ctx, "user1", ciphertext, buffer, &buffer_len);

    // Cleanup
    oabe_bytestring_free(secret_key);
    oabe_bytestring_free(ciphertext);
    oabe_context_free(ctx);
    oabe_shutdown();

    return 0;
}
```

### ByteString Operations

```c
#include "openabe/oabe_bytestring.h"

void example_bytestring(void) {
    // Create ByteString from string
    OABE_ByteString *bs = oabe_bytestring_new_from_string("Hello");

    // Append data
    oabe_bytestring_append_string(bs, ", World!");

    // Pack values
    oabe_bytestring_pack32(bs, 0xDEADBEEF);

    // Convert to hex
    char *hex = oabe_bytestring_to_hex(bs);
    printf("Hex: %s\n", hex);
    oabe_free(hex);

    // Clone
    OABE_ByteString *clone = oabe_bytestring_clone(bs);
    printf("Equals: %s\n", oabe_bytestring_equals(bs, clone) ? "true" : "false");

    // Cleanup
    oabe_bytestring_free(bs);
    oabe_bytestring_free(clone);
}
```

### ZML Math Operations

```c
#include "openabe/oabe_zml.h"

void example_zml(void) {
    // Create pairing group
    OABE_GroupHandle group = oabe_group_new(OABE_CURVE_BN_P254);

    // Create RNG
    OABE_RNGHandle rng = oabe_rng_new(NULL, 0);

    // Create random scalar
    OABE_ZP *zp = oabe_zp_new(group);
    oabe_zp_random(zp, rng);

    // Create random G1 point
    OABE_G1 *g1 = oabe_g1_new(group);
    oabe_g1_random(g1, rng);

    // Scalar multiplication
    OABE_G1 *result = oabe_g1_new(group);
    oabe_g1_mul_scalar(result, g1, zp);

    // Cleanup
    oabe_zp_free(zp);
    oabe_g1_free(g1);
    oabe_g1_free(result);
    oabe_rng_free(rng);
    oabe_group_free(group);
}
```

## API Reference

### Core Types

- `OABE_ByteString`: Byte container for arbitrary data
- `OABE_Vector`: Generic vector for pointers
- `OABE_StringVector`: Vector for strings
- `OABE_StringMap`: Map from string to pointer

### Error Codes

All functions return `OABE_ERROR`:
- `OABE_SUCCESS` (0): Success
- `OABE_ERROR_INVALID_INPUT`: Invalid input parameters
- `OABE_ERROR_OUT_OF_MEMORY`: Memory allocation failure
- See `oabe_types.h` for complete list

### Memory Management

Objects use reference counting:
- `OABE_ADDREF(obj)`: Increment reference count
- `OABE_DEREF(obj)`: Decrement reference count (free if zero)
- Use `*_new()` to create and `*_free()` to release

## Supported Curves

- `OABE_CURVE_BN_P254`: BN-254 pairing-friendly curve
- `OABE_CURVE_BN_P256`: BN-256 curve
- `OABE_CURVE_NIST_P256`: NIST P-256 EC curve
- `OABE_CURVE_NIST_P384`: NIST P-384 EC curve
- `OABE_CURVE_NIST_P521`: NIST P-521 EC curve

## License

GNU Affero General Public License v3.0

For commercial licensing, contact: http://www.zeutro.com

## References

- Waters, B. (2009). Ciphertext-Policy Attribute-Based Encryption
- Goyal, V., et al. (2006). Attribute-Based Encryption for Fine-Grained Access Control
- Original OpenABE: https://github.com/zeutro/openabe