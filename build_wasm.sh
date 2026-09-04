#!/bin/bash
#
# build_wasm.sh — Cross-compile OpenABE-c (RELIC + OpenABE) to WebAssembly.
#
# This script builds the full ABE stack for WASM using Emscripten:
#   1. RELIC (pairing crypto library, ARITH=easy — no GMP needed)
#   2. OpenABE-c (CP-ABE keygen/encrypt/decrypt)
#
# Usage:
#   source /home/victor/emsdk/emsdk_env.sh
#   ./build_wasm.sh
#
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELIC_DIR="$ROOT_DIR/deps/relic"
RELIC_WASM_BUILD="$RELIC_DIR/build-wasm"
OPENABE_WASM_BUILD="$ROOT_DIR/build-wasm"

echo "=== OpenABE-c WASM Build ==="
echo "  Root: $ROOT_DIR"
echo "  RELIC: $RELIC_DIR"
echo ""

# ============================================================
# 1. Build RELIC for WASM
# ============================================================
echo "--- Building RELIC for WASM ---"

rm -rf "$RELIC_WASM_BUILD"
mkdir -p "$RELIC_WASM_BUILD"
cd "$RELIC_WASM_BUILD"

# Configure RELIC with Emscripten
# ARITH=easy: pure C arithmetic, no GMP dependency
# STLIB: static library (for linking into WASM)
# Disable tests/bench/docs to speed up build
emcmake cmake "$RELIC_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DARITH=easy \
  -DARCH="" \
  -DWSIZE=32 \
  -DSTLIB=ON \
  -DSHLIB=OFF \
  -DTESTS=0 \
  -DBENCH=0 \
  -DDOCUM=OFF \
  -DCHECK=OFF \
  -DCOLOR=OFF \
  -DVERBS=OFF \
  -DALIGN=1 \
  -DBN_PRECI=1024 \
  -DBN_MAGNI=DOUBLE \
  -DBN_KARAT=0 \
  -DBN_METHD="COMBA;COMBA;MONTY;SLIDE;BASIC;BASIC" \
  -DEP_PLAIN=ON \
  -DEP_ENDOM=ON \
  -DEP_CTMAP=ON \
  -DEP_PRECO=ON \
  -DEP_METHD="PROJC;LWNAF;COMBS;INTER;SSWUM" \
  -DEP_MIXED=ON \
  -DWITH_BN=ON \
  -DWITH_FP=ON \
  -DWITH_FPX=ON \
  -DWITH_FB=ON \
  -DWITH_EP=ON \
  -DWITH_EPX=ON \
  -DWITH_PP=ON \
  -DWITH_PC=ON \
  -DWITH_BC=ON \
  -DWITH_MD=ON \
  -DWITH_CP=ON \
  -DWITH_MPC=ON \
  -DALLOC=AUTO \
  -DCOMP="-O2" \
  2>&1

echo "Building RELIC..."
emmake make -j$(nproc) 2>&1

echo "RELIC WASM build complete: $RELIC_WASM_BUILD/lib/librelic_s.a"

# ============================================================
# 2. Build OpenABE-c for WASM
# ============================================================
echo ""
echo "--- Building OpenABE-c for WASM ---"

rm -rf "$OPENABE_WASM_BUILD"
mkdir -p "$OPENABE_WASM_BUILD"

cd "$ROOT_DIR"

# Compile OpenABE source files with emcc
# OpenABE uses C++ (the ABE context code) and C (the ZML/RELIC interface)
OPENABE_C_SRCS=$(find src/ -name '*.c' | sort)
OPENABE_CXX_SRCS=$(find src/ -name '*.cpp' | sort)

# Include paths — use isolated OpenSSL headers to avoid conflicting with
# Emscripten's sysroot (system /usr/include has glibc headers that clash)
OPENSSL_HEADERS_DIR="${OPENSSL_HEADERS_DIR:-/tmp/wasm-openssl-headers}"
INCLUDES="-I./include -I./deps/include -I$RELIC_DIR/include -I$RELIC_WASM_BUILD/include -I$OPENSSL_HEADERS_DIR"

# Compile flags — -DWITH_RELIC tells OpenABE to use RELIC for pairing math
# -D_POSIX_C_SOURCE makes strcasecmp/strdup/etc. available in Emscripten's libc
# Define both BP_WITH_OPENSSL and WITH_RELIC — OpenABE needs OpenSSL for
# RNG/AES-GCM and RELIC for bilinear pairings. The source uses #if/#elif
# conditionals that would skip OpenSSL headers if only WITH_RELIC is defined.
CFLAGS="-std=c11 -O2 -DWITH_RELIC -DBP_WITH_OPENSSL -D_POSIX_C_SOURCE=200809L -include strings.h -D__GLIBC_PREREQ(x,y)=0 -fPIC"
CXXFLAGS="-std=c++17 -O2 -DWITH_RELIC -DBP_WITH_OPENSSL -D_POSIX_C_SOURCE=200809L -include strings.h -D__GLIBC_PREREQ(x,y)=0 -fPIC"

echo "Compiling C sources..."
for src in $OPENABE_C_SRCS; do
  obj="$OPENABE_WASM_BUILD/$(basename ${src%.c}).o"
  echo "  CC  $src"
  emcc $CFLAGS $INCLUDES -c "$src" -o "$obj"
done

echo "Compiling C++ sources..."
for src in $OPENABE_CXX_SRCS; do
  obj="$OPENABE_WASM_BUILD/$(basename ${src%.cpp}).o"
  echo "  CXX $src"
  em++ $CXXFLAGS $INCLUDES -c "$src" -o "$obj"
done

# Create static library
echo "Creating liboabe_c_wasm.a..."
emar rcs "$OPENABE_WASM_BUILD/liboabe_c_wasm.a" $OPENABE_WASM_BUILD/*.o

echo ""
echo "=== WASM Build Complete ==="
echo "  RELIC:   $RELIC_WASM_BUILD/lib/librelic_s.a"
echo "  OpenABE: $OPENABE_WASM_BUILD/liboabe_c_wasm.a"
echo ""
echo "These static libraries can be linked into a CRABS WASM build."