# OpenABE C Examples

This directory contains example programs demonstrating the OpenABE C API.

## Building

Build all examples with:

```bash
cd openabe-c
make examples
```

Or build a specific example:

```bash
gcc -std=c11 -Wall -I./include -I./deps/relic/include -I./deps/relic/build/include \
    examples/01_bytestring_basics.c -o bytestring_basics \
    -L./build -loabe_c -L./deps/relic/build/lib -lrelic_s -lgmp -lssl -lcrypto
```

## Running

After building, executables are in `build/examples/`:

```bash
./build/examples/01_bytestring_basics
./build/examples/02_zml_math
./build/examples/03_aes_gcm
./build/examples/04_cpabe_encrypt
./build/examples/05_kpabe_encrypt
./build/examples/06_hybrid_encryption
./build/examples/07_key_management
```

## Example Descriptions

### 01_bytestring_basics.c

Demonstrates fundamental ByteString operations:
- Creating ByteStrings from strings and raw data
- Appending and manipulating data
- Pack/unpack operations for integers
- Hex encoding/decoding
- Cloning and comparison

### 02_zml_math.c

Shows the ZML mathematical layer for pairing-based cryptography:
- Creating pairing groups (BN-254 curve)
- ZP scalar operations (add, multiply, invert)
- G1 and G2 group operations
- Pairing computation (G1 x G2 → GT)
- Point serialization/deserialization

### 03_aes_gcm.c

Demonstrates AES-GCM symmetric encryption:
- Key generation (AES-128/192/256)
- Encryption with authentication tag
- Decryption and verification
- Tamper detection
- Key serialization

### 04_cpabe_encrypt.c

CP-ABE (Ciphertext-Policy Attribute-Based Encryption):
- Authority setup (public params and master key)
- User key generation with attributes
- Encryption with access policies
- Decryption based on attribute satisfaction
- Key export/import for distribution
- Complex policy expressions

### 05_kpabe_encrypt.c

KP-ABE (Key-Policy Attribute-Based Encryption):
- Authority setup
- Key generation with embedded policies
- Encryption with attributes
- Decryption based on policy satisfaction
- Comparison with CP-ABE approach

### 06_hybrid_encryption.c

Hybrid encryption (ABE + AES):
- Why use hybrid encryption
- Generating random symmetric keys
- Encrypting large data with AES
- Encrypting the key with ABE
- Decryption workflow

### 07_key_management.c

Key management and persistence:
- Key store operations
- Serializing keys to ByteStrings
- Saving keys to files
- Loading and restoring keys
- Verifying key integrity

## Attribute-Based Encryption Concepts

### CP-ABE vs KP-ABE

**CP-ABE (Ciphertext-Policy):**
- Ciphertext contains the access policy
- Users have attribute-based keys
- User can decrypt if their attributes satisfy the policy
- Use case: Data owner controls access policy

**KP-ABE (Key-Policy):**
- User keys contain access policies
- Ciphertext has attributes
- User can decrypt if ciphertext attributes satisfy their policy
- Use case: User controls what they can access

### Policy Syntax

Policies use boolean expressions:
- `attr1` - single attribute
- `attr1 and attr2` - both required
- `attr1 or attr2` - either required
- `(attr1 and attr2) or attr3` - complex policies
- `not attr1` - negation

Attributes are pipe-separated (`|`) for encryption in KP-ABE.

## Error Handling

All functions return `OABE_ERROR`. Check for `OABE_SUCCESS`:

```c
OABE_ERROR rc = oabe_context_cp_generate_params(ctx, "auth");
if (rc != OABE_SUCCESS) {
    fprintf(stderr, "Error: %s\n", oabe_error_to_string(rc));
    // handle error
}
```

## Memory Management

- Use `*_new()` functions to create objects
- Use `*_free()` functions to release them
- ByteString uses reference counting internally
- Always call `oabe_init()` before and `oabe_shutdown()` after

## Thread Safety

- Each context should be used by a single thread
- For multi-threaded applications, create separate contexts
- The library initialization is thread-safe

## License

GNU Affero General Public License v3.0

For commercial licensing, contact: http://www.zeutro.com