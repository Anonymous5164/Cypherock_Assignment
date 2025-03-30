//  Utility functions

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <string.h>
#include "bignum.h"
#include "ecdsa.h"
#include "sha2.h"
#include "secp256k1.h"

/**
 * Generate a random scalar in the range [1, order-1]
 * 
 * @param scalar Output random scalar
 */
void generate_random_nonzero_scalar(bignum256 *scalar);

/**
 * Generate a random bignum within the curve order
 * 
 * @param num Output random bignum
 */
void generate_random_bignum(bignum256 *num);

/**
 * Derive a key from an elliptic curve point using SHA-256
 * 
 * @param point The input elliptic curve point
 * @param key The output key (32 bytes)
 */
void derive_key_from_point(const curve_point *point, uint8_t *key);

/**
 * Encrypt or decrypt data using SHA-256 and XOR
 * 
 * @param data Data to encrypt/decrypt (in-place)
 * @param key Key to use for encryption/decryption
 * @param data_len Length of the data
 */
void sha256_xor_crypt(uint8_t *data, const uint8_t *key, size_t data_len);

/**
 * XOR two buffers of the same length
 * 
 * @param result Output buffer (can be same as a or b)
 * @param a First input buffer
 * @param b Second input buffer
 * @param len Length of the buffers
 */
void xor_buffers(uint8_t *result, const uint8_t *a, const uint8_t *b, size_t len);

/**
 * Convert a bignum to bytes
 * 
 * @param num Input bignum
 * @param bytes Output byte array (32 bytes)
 */
void bignum_to_bytes(const bignum256 *num, uint8_t *bytes);

/**
 * Convert bytes to a bignum and reduce mod order
 * 
 * @param bytes Input byte array (32 bytes)
 * @param num Output bignum
 */
void bytes_to_bignum(const uint8_t *bytes, bignum256 *num);

/**
 * Check if a specific bit is set in a bignum
 * 
 * @param num The bignum to check
 * @param bit_index The bit position to check (0-255)
 * @return 1 if bit is set, 0 otherwise
 */
int get_bit(const bignum256 *num, int bit_index);

/**
 * Calculate 2^i as a bignum
 * 
 * @param i The exponent
 * @param result Output bignum set to 2^i
 */
void pow2_bignum(int i, bignum256 *result);

#endif /* __UTILS_H__ */