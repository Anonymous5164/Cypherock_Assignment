cmake_minimum_required(VERSION 3.10)
project(mta_protocol)

# Set include directories before adding sources
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/external
    ${CMAKE_SOURCE_DIR}/external/ed25519-donna
)

# Add all required crypto sources
set(CRYPTO_SOURCES
    src/cot.c
    src/mta.c
    src/base_ot.c
    src/logger.c
    src/utils.c
    test/mta_test.c
    external/point_ops.c
    external/rand_impl.c
    external/ecdsa.c
    external/secp256k1.c
    external/sha2.c
    external/rand.c
    external/bignum.c
    external/memzero.c
    external/rfc6979.c
    external/base58.c
    external/address.c
    external/hasher.c
    external/curves.c
    external/hmac.c
    external/hmac_drbg.c
    external/sha3.c
    external/blake256.c
    external/blake2b.c
    external/groestl.c
    external/ripemd160.c
)

# Define random32 function in main.c if it's not found in any other file
add_compile_definitions(RAND_PLATFORM_INDEPENDENT)

add_library(trezor_crypto STATIC ${CRYPTO_SOURCES})
add_executable(mta_protocol main.c)
target_link_libraries(mta_protocol trezor_crypto)