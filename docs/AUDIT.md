# Security & Correctness Audit — openabe-c

**Date:** 2026-07-31
**Scope:** Full `openabe-c` source tree (`src/` — core, api, abe, keys, utils, zml; `deps/` excluded), reviewed as a pairing-based attribute-based encryption library. CP-ABE (Waters '09) round-trip was validated end-to-end via the CRABS integration tests (`TestAbe.*`).
**Method:** Manual review of the security-critical paths (keygen, CP/ABE context, DEM, serialization), plus adversarial audits of the policy parser/LSSS and the ZML/serialization/RNG/memory layers. All CRITICAL findings were re-verified against the code before inclusion.

---

## 1. Executive Summary

`openabe-c` is a functional but immature port of OpenABE. Its CP-ABE encrypt/decrypt and CP-ABE keygen are structurally correct Waters '09 (and, after the DEM work, a real hybrid KEM+DEM), but the library has **serious defects** in three areas:

1. **Broken/under-powered cryptography**: the matrix-based LSSS share uses zero randomness (every share equals the secret); the matching recover is mathematically wrong; the RNG has a trivial-XOR fallback and a keystream-reuse bug in the CTR-DRBG.
2. **Remote memory-safety vulnerabilities in the deserialize policy/ciphertext path**: attacker-controlled lengths (`iv_len` → 239-byte heap overflow; `policy_len`/`attr_len` → OOB read; wire counts → multi-GB allocation) and a fixed 256-entry traversal stack a crafted policy overflows from the network.
3. **Group-element and init/teardown hygiene**: no validity/subgroup checks on deserialized group elements (small-subgroup/invalid-point attack surface), non-atomic init/shutdown (RELIC double-init / use-after-free), and secret scalars not zeroized on free.

Two further CRITICAL issues were **fixed in-tree** during this audit (see §2, "Already fixed in this audit"):
- The CP-ABE encrypt/decrypt were KEM-only (no data encryption at all) — the DEM was implemented.
- The DEM published the KEM secret (`ct->ct`) inside the ciphertext so anyone could derive the AES key — the DEM was reworked to hide the GT secret; the KEM is now only reconstructible by a policy-satisfying key.

**Recommendation:** treat the library as usable for the validated CP-ABE setup/keygen/encrypt/decrypt path only after items in §3 (CRITICAL) are fixed. The matrix-LSSS public API and RNG must be treated as non-functional until fixed (§3.1, §3.5, §3.6).

---

## 2. Already fixed in this audit

| Fix | Commit | Summary |
|-----|--------|---------|
| **CP-ABE data encryption (KEM-only gap)** | `48aebfa` | `oabe_context_cp_encrypt`/`decrypt` were KEM-only — the reference example returned empty plaintext. Added the DEM: hash the encapsulated GT element `e(g1,g2)^{alpha·s}` (SHA-256) to an AES-256-GCM key and encrypt the payload; `IV(12)+tag(16)+ct` rides in `ct->encrypted_key`, which the serializer already round-trips. Decrypt recovers the GT via Lagrange and AES-GCM decrypts. |
| **DEM published the KEM secret** | `9e0bb63` | The DEM derived the AES key from the GT element **and serialized that same element into the ciphertext**, so anyone could compute `SHA256(ct->ct)` and decrypt. Encrypt now resets `ct->ct` to the identity before serializing (the secret is only reconstructible on the decrypt side via Lagrange); decrypt derives the key from the recovered GT and relies on the GCM tag for integrity instead of a compare-to-stored check. Round-trip + policy-not-satisfied both validated via CRABS `TestAbe`. |

---

## 3. CRITICAL findings (open)

### C-1. Matrix LSSS share uses zero randomness — every share equals the secret
`src/utils/oabe_policy.c:1019-1023` (`oabe_lsss_share`)
All blinding randoms are explicitly set to zero with a comment "for deterministic testing… For simplicity use 0." Since the share matrix's first column is all 1s, `share_i = M[i][0]·s = s` — each share **is** the secret. No callers inside the library use this matrix API (the CP-ABE path uses the tree-based `oabe_lsss_share_tree`), but it is a public, exported API (`include/openabe/oabe_policy.h:313`).
**Fix:** take a real RNG parameter and call `oabe_zp_random` for columns 1..n, or delete the matrix LSSS API and keep only the correct tree-based pair.

### C-2. `oabe_lsss_recover` is mathematically wrong
`src/utils/oabe_policy.c:1180-1239`
It performs polynomial Lagrange interpolation over row indices `1..k` as though shares were polynomial evaluations. LSSS reconstruction for a matrix access structure requires solving `Σ w_i·row_i = e_1` (a linear combination over the satisfied rows). As written it cannot recover a non-trivially shared secret.
**Fix:** implement Gaussian elimination over the row vectors to compute the reconstruction coefficients `w_i`, or remove the API with C-1.

### C-3. Fixed 256-entry traversal stack overflows from a crafted policy
`src/utils/oabe_policy.c:1486` (leaf counting in `oabe_lsss_share_tree`), `:1772` (same in `oabe_lsss_recover_coefficients`), `:1377-1378` (`iterative_share_tree`)
The code allocates exactly 256 slots and pushes children with `stack[stack_top++]` **with no bounds check**. A policy with >257 leaves writes arbitrary pointers past a ~2KB heap buffer. This is remotely reachable: a malicious ciphertext deserializes its policy string and `oabe_context_cp_decrypt` calls `oabe_lsss_recover_coefficients` on it (`src/abe/oabe_context.c:1201`).
**Fix:** grow the stack dynamically (realloc) or hard-error when the count would exceed the buffer.

### C-4. Heap overflow from attacker-controlled IV length (AES deserialize)
`src/utils/oabe_ciphertext.c:139-154` (`oabe_aes_ct_deserialize`)
`iv_len` is read from the wire as a `uint8_t` (0..255) and `memcpy`d into `(*ct)->iv[16]` (declared `iv[16]` in the header). Up to 239 attacker-controlled bytes overflow past `iv`, clobbering `iv_len`, the `ciphertext` pointer, `tag`, and adjacent heap metadata — the corrupted `ciphertext` pointer is later `oabe_bytestring_free`d, a classic control-flow primitive.
**Fix:** reject `iv_len == 0 || iv_len > sizeof((*ct)->iv)` before any memcpy.

### C-5. OOB read / 4 GB allocation from wire-controlled string lengths
`src/utils/oabe_ciphertext.c:441-455` (`policy_len`), `:508-522` (CP component `attr_len`), `:806-818` (KP `attr_len`)
A 4-byte length field from the wire is memcpy'd from `input + index` with **no** `index + len <= size` check. The attacker controls `len`, causing an out-of-bounds read (information disclosure — the oversized string is hashed into the parsed policy/attribute) and a huge allocation (DoS). Contrast with `oabe_bytestring_unpack_with_len`, which does check.
**Fix:** bounds-check `index + len <= oabe_bytestring_get_size(input)` before allocating/copying.

### C-6. Unbounded allocations from wire-controlled counts
`src/utils/oabe_ciphertext.c:490-498`, `:777-786`
`num_components` / `num_attrs` (attacker `uint32_t`) go straight into `oabe_calloc(count, sizeof(...))` — up to ~4 billion entries (~100 GB) requested before any per-element validation. Memory-exhaustion DoS.
**Fix:** cap counts (e.g. 4096) and/or verify `count <= remaining_bytes / min_record_size` before allocating.

### C-7. The "AES-256-CTR" PRF fallback is a trivial XOR cipher
`src/utils/oabe_rng.c:98-119`
In `WITH_RELIC` builds (not `BP_WITH_OPENSSL`), the "keystream" is `key[i % 32] ^ counter[i]`. Given any output and knowing the counter increments, the 32-byte key is directly recoverable, making all past/future DRBG output (encryption keys, nonces, master secrets) predictable. The comment itself admits it's not production-grade.
**Fix:** delete the XOR fallback; use OpenSSL EVP, RELIC's AES module, or route to `rand_bytes` directly.

### C-8. CTR-DRBG keystream reuse and no state update
`src/utils/oabe_rng.c:218-226` (`oabe_ctr_drbg_generate`)
After generating up to 1024 bytes (64 blocks), `ctx->counter` is incremented by only one block, so the next `generate()` reuses blocks already emitted — overlapping keystream in successive "random" outputs. There is also no post-generate state update, so state compromise retro-dicloses all prior outputs (no backtracking resistance, SP 800-90A). The reseed path also does not reseed (`oabe_rng.c:212-215`).
**Fix:** advance the counter by `ceil(output_len/16)` after each generate and call a state-update (rekey); wire the reseed path to a real entropy source.

---

## 4. HIGH findings (open)

### H-1. No group-element validity/subgroup checks on deserialize
`src/zml/oabe_zml_relic.c:693` (`g1_read_bin`), `:877` (`g2_read_bin`), `:1044` (`gt_read_bin`)
Deserialized points are used without `g1_is_valid`/`g2_is_valid` or subgroup checks, and the identity element is silently accepted. On pairing curves with nontrivial cofactors this enables small-subgroup/invalid-point attacks against decryption and key validation.
**Fix:** after each read, call the RELIC validity predicate, reject infinity, and verify subgroup membership (e.g. `[order]P == inf` or cofactor clearing).

### H-2. Generic ciphertext dispatch breaks the AES round-trip (type confusion)
`src/utils/oabe_ciphertext.c:77-123` vs `:945-977`
`oabe_aes_ct_serialize` writes `iv_len` as the first byte and never a scheme byte, but `oabe_ct_deserialize` expects the first byte to equal `OABE_SCHEME_AES_GCM` (70) — anything else falls through to the KP-ABE parser. Every AES ciphertext serialized via `oabe_ct_serialize` is mis-parsed on read.
**Fix:** prepend the scheme byte in `oabe_aes_ct_serialize`, or give each type an unambiguous magic header.

### H-3. Init/shutdown are non-atomic; partial-init leak
`src/core/oabe_init.c:116-161, 204-224`
`g_library_initialized` is a plain `volatile bool` with a non-atomic check-then-set: two threads racing `oabe_init()` both run `core_init()` (RELIC does not tolerate double init). `oabe_shutdown()` runs `core_clean()` without synchronization while other threads may hold RELIC-backed objects → use-after-free. If `core_init()` succeeds but `oabe_init_thread()` fails (lines 154-157), the function returns without `core_clean()` and the flag was never set — `oabe_shutdown()` will never clean it.
**Fix:** guard global init/shutdown with `pthread_once`/mutex; roll back the backend on thread-init failure.

### H-4. Parser never requires EOF + 255-byte silent attribute truncation
`src/utils/oabe_policy.c:529` (EOF check absent), `:230, 285-293` (fixed `token_value[256]`)
`oabe_policy_parse` never verifies the parser consumed the whole string, so trailing garbage is discarded. Combined with the fixed 256-byte token buffer: an attribute longer than 255 chars stops consuming mid-token, the remainder becomes a second (dropped) token, and the stored attribute becomes the 255-char prefix — a user issued exactly that prefix attribute satisfies the policy (attribute impersonation).
**Fix:** require TOKEN_EOF after parse; dynamically size tokens or hard-error on overflow.

### H-5. Unbounded parser recursion (`(((((…` → stack-exhaustion DoS)
`src/utils/oabe_policy.c:306-510` (`parse_factor`/`parse_expression`), plus `mark_satisfied_nodes` (1584), `allocate_sat_lists` (1548), `collect_attributes` (1972), `has_attribute_recursive` (2022), `lsss_generate_shares` (827)
Recursive descent with no depth limit; `MAX_POLICY_DEPTH 256` is defined (line 41) but **never enforced**. A deeply nested policy crashes via call-stack exhaustion, remotely triggerable through the ciphertext policy parse.
**Fix:** track depth against `MAX_POLICY_DEPTH` and hard-error.

### H-6. Unvalidated threshold value → uint32 wrap → memory-exhaustion DoS
`src/utils/oabe_policy.c:374-396`
`sscanf("%dof%d")` accepts 0, negative, and huge `k` (and the parsed `n` is unused). `threshold = -2` lets `mark_satisfied_nodes` count any node as satisfied (inconsistent with `check_satisfaction`), and `iterative_share_tree` casts a negative/huge `threshold` to `uint32_t` (~4e9) and allocates that many polynomial coefficients → memory exhaustion on encrypt. `k > n` silently yields undecryptable ciphertext.
**Fix:** validate `1 <= k <= number of parsed children` at parse time; clamp threshold into a sane bound (e.g. ≤ 1024).

### H-7. Per-encryption memory leak in `iterative_share_tree`
`src/utils/oabe_policy.c:1393-1462`
Shares popped from `share_stack` are never freed: at leaves the share is **cloned** into the result list (line 1400) and the original is abandoned; the cleanup loop (1458) only frees entries still on the stack, which is empty on success. One `OABE_ZP` plus a group ADDREF leaked per non-root node per encryption — an unbounded leak in a long-running encryptor.
**Fix:** `oabe_zp_free` the popped share after processing (and after the leaf add).

### H-8. Type confusion in `oabe_attr_list_contains` — NULL deref / wild `strcmp`
`src/utils/oabe_policy.c:696`
`OABE_StringVector {items, size, capacity}` is cast to `OABE_StringMap {keys, values, size, capacity}`; the map's `size` field (offset 16) reads the vector's *capacity*, so the lookup `strcmp`s heap entries beyond `vec->size` — NULL-deref segfault (calloc'd tails) or a wild-pointer `strcmp` after `strvec_append` growth (realloc'd tail is unzeroed). A miss lookup is a reliable crash.
**Fix:** iterate the vector with plain `strcmp` (delete the cast).

### H-9. `oabe_zp_div` never reduces its output
`src/zml/oabe_zml_relic.c:381-394`
`bn_mul(r, a, inv)` returns without `bn_mod`. Lagrange denominators are negative half the time, so correctness currently depends on RELIC's inversion reducing the input — a fragile representation inconsistency vs every other ZP op which reduces.
**Fix:** normalize inputs and `bn_mod` the result by the group order.

### H-10. `oabe_zp_div` accepts non-canonical scalars on deserialize
`src/zml/oabe_zml_relic.c:489-512`
`bn_read_bin` loads `len` bytes with no reduction or check that value < group order; comparisons (`is_zero`, `is_one`) and serialized lengths become inconsistent for the same residue.
**Fix:** `bn_mod(value, value, order)` after reading.

---

## 5. MEDIUM findings (open)

### M-1. Pointer-overwrite leak in `oabe_ct_deserialize`
`src/utils/oabe_ciphertext.c:964-977`
`oabe_ct_new(type)` pre-allocates `ct->data.aes/cp/kp`, then the inner deserializer (e.g. line 132 `*ct = oabe_aes_ct_new()`) **overwrites** the pointer, leaking the pre-allocated object on every call. Repeat deserialization grows memory without bound.
**Fix:** free the pre-allocated inner object first, or have `oabe_ct_new` defer inner allocation.

### M-2. Secret scalars not zeroized on free
`src/zml/oabe_zml_relic.c:237-244, 479, 663, 847, 1015`
`oabe_zp_destroy` calls `bn_free` (RELIC does not wipe), so master-secret scalars remain in freed heap; serialize temp buffers holding secrets are `oabe_free`d without `oabe_zeroize` (contrast `src/utils/oabe_rng.c:280,337` which does it right).
**Fix:** wipe secret BIGNUMs before `bn_free`; `oabe_zeroize` temp buffers before freeing.

### M-3. RNG is a stub that ignores its arguments (seed ignored → nondeterministic test vectors broken)
`src/zml/oabe_zml_relic.c:105-146, 335-346`
`oabe_rng_new(seed,...)` accepts a seed but `oabe_rng_bytes`/`oabe_zp_random` ignore it and call RELIC `rand_bytes`. Code expecting deterministic seeded derivation silently gets system randomness.
**Fix:** implement the seeded path via `oabe_ctr_drbg_*` (after C-7/C-8 are fixed), or fail loudly.

### M-4. Rejected child nodes leak; `add_child` doesn't refcount
`src/utils/oabe_policy.c:498-499, 395-397`
On realloc failure a child leaks and the tree silently drops a branch (policy semantics differ from the input). `add_child` stores without ADDREF while destroy DEREFs children — double-free if a node is shared across parents via the public API.
**Fix:** check `add_child` returns; refcount on adopt.

### M-5. `oabe_rng_bytestring` appends instead of clearing the output
`src/utils/oabe_rng.c:320-341`
Callers expecting exactly `output_len` random bytes get stale prefix data before the new random bytes.
**Fix:** clear the output ByteString first (or document append semantics).

### M-6. Use-after-shutdown TLS hole
`src/core/oabe_init.c:87-110, 204-224`
`oabe_shutdown` frees only the calling thread's TLS; other threads' RELIC-backed objects are cleaned while still referenced → crash on next use.
**Fix:** refcount the global init; forbid TLS re-init after shutdown.

### M-7. `allocate_sat_lists` leaks partial allocations on OOM and on repeat recovery
`src/utils/oabe_policy.c:1548-1562`
**Fix:** unwind on allocation failure; free the existing `sat_list` before replacing.

### M-8. Missing public-function definitions (link errors for external callers)
`include/openabe/oabe_policy.h:390, 403` declare `oabe_evaluate_polynomial` and `oabe_compute_lagrange`, but only `static` `evaluate_polynomial`/`compute_lagrange` exist (`oabe_policy.c:1256, 1619`).
**Fix:** export non-static wrappers matching the header.

### M-9. `oabe_attr_list_from_string` empty-token pointer-arithmetic UB
`src/utils/oabe_policy.c:637-639` — `end = token + strlen(token) - 1` points before the buffer for empty trimmed tokens.
**Fix:** guard empty tokens.

### M-10. `oabe_strmap_insert` rollback leaves inconsistent state on partial realloc failure
`src/core/oabe_memory.c:346-357` — if the second `oabe_realloc` (values) fails after the first (keys) succeeded, capacity/keys are stale. Realloc values first, or preserve and restore on failure.

---

## 6. LOW findings (open)

- **L-1.** Attribute matching is case-sensitive `strcmp` while parser keywords are case-insensitive; upstream OpenABE lowercases both. Mis-deployment risk (fail-closed). Normalize (`oabe_policy.c:2022`, parser keywords).
- **L-2.** Encrypt caller misses a NULL check before `oabe_g1_mul_scalar(H_attr_neg_r, …)` (`src/abe/oabe_context.c:1107-1108`) — crash if `oabe_g1_new` failed.
- **L-3.** `oabe_ciphertext.c:453, 519` feed the parser with the memcp'd (unsanitized, unbounded) strings from C-5 — downstream crash/behavior issues even once C-5 is fixed.
- **L-4.** `oabe_bytestring.c:188, 223, 241` capacity/growth arithmetic has no overflow guards (theoretical on 32-bit with >2 GB payloads).
- **L-5.** `oabe_zeroize` (`src/core/oabe_memory.c:78-86`) uses a volatile loop that some compilers can still elide; prefer `explicit_bzero`/`memset_s`.
- **L-6.** `oabe_function_input_parse` (`oabe_policy.c:1906-1909`) misclassifies attribute lists containing "or"/"and" substrings (e.g. "endorsement,firstfloor") as policies. Match whole tokens, not substrings.
- **L-7.** `params_id` and some internal strings are duplicated via `oabe_strdup` without free in setup teardown (small, at process exit).

---

## 7. What is solid

- **CP-ABE keygen** (`src/abe/oabe_context.c:656-790`): correct Waters '09 derivation — `K = g2^{alpha + beta·t}`, `L = g2^t`, `Kx_i = H(attr)^t` — with a random `t` per user from the RELIC CSPRNG, and no reuse of group elements across keys.
- **CP-ABE KEM** (`oabe_context_cp_encrypt`, post-DEM): random `s` per message, correct secret sharing via `oabe_lsss_share_tree` (polynomial `deg(t-1)` with constant = parent share, x = child index 1..n), correct `CT/C_0/C_i/D_i` construction.
- **Lagrange recovery** (`oabe_lsss_recover_coefficients` and `iterative_share_tree`'s math): the tree-based share/recover is structurally correct — recovery computes Lagrange coefficients over the first `threshold` satisfied child indices using the same 1-based x-coordinates and applies them as G1/G2/GT exponents.
- **AES-GCM DEM (as now implemented)**: per-message random GT → message-unique key, so 96-bit random IV uniqueness is automatically satisfied, and the GCM tag authenticates the payload.
- **Serialization round-trips for CP-ABE keys/ciphertexts** are consistent (validated end-to-end via CRABS `TestAbe`.

---

## 8. Prioritized remediation plan

**Phase 1 — Remote memory safety (must block all wire-deserialization paths first):**
C-3 (traversal stack overflow), C-4 (`iv_len` heap overflow), C-5 (`policy_len`/`attr_len` OOB read), C-6 (unbounded count allocations).

**Phase 2 — Broken/under-powered crypto:**
C-1/C-2 (matrix LSSS randomness + recover), C-7/C-8 (RNG XOR fallback + CTR-DRBG reuse/reseed), H-1 (group-element validity/subgroup checks).

**Phase 3 — Robustness and lifecycle:**
H-2 (AES type confusion), H-3 (init/shutdown atomicity), H-4 (EOF + token length), H-5 (parser depth limit), H-6 (threshold validation), H-7 (encryption share leak), H-8 (attr-list type confusion), M-1 (deserialize overwrite leak).

**Phase 4 — Hygiene and hardening:**
M-2 (secret zeroization), M-3 (seeded RNG), H-9/H-10 (ZP canonicalization), M-4..M-10, L-1..L-7; add fuzz targets for every deserializer and the policy parser; add a subgroup-test and identity-rejection test vector.

---

*This audit builds on the two in-tree fixes in commits `48aebfa` (DEM implementation) and `9e0bb63` (not publishing the KEM secret). All other findings are open.*
