// utils.c
#include "utils.h"
#include "rand.h"

void generate_random_nonzero_scalar(bignum256 *scalar) {
    uint8_t buffer[32];
    
    do {
        random_buffer(buffer, sizeof(buffer));
        bn_read_be(buffer, scalar);
        bn_mod(scalar, &secp256k1.order);
    } while (bn_is_zero(scalar));
}

void generate_random_bignum(bignum256 *num) {
    uint8_t buffer[32];
    
    // Generate full 256-bit random value
    random_buffer(buffer, sizeof(buffer));
    
    // Convert to bignum and reduce modulo curve order
    bytes_to_bignum(buffer, num);
}

void derive_key_from_point(const curve_point *point, uint8_t *key) {
    uint8_t point_bytes[65];
    
    // Format the point in uncompressed form (0x04 || x || y)
    point_bytes[0] = 0x04;
    bn_write_be(&point->x, point_bytes + 1);
    bn_write_be(&point->y, point_bytes + 33);
    
    // Hash the point using SHA-256
    sha256_Raw(point_bytes, sizeof(point_bytes), key);
}

void sha256_xor_crypt(uint8_t *data, const uint8_t *key, size_t data_len) {
    // Generate keystream using SHA-256
    uint8_t keystream[32];
    sha256_Raw(key, 32, keystream);
    
    // XOR with keystream
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= keystream[i % 32];
    }
}

void xor_buffers(uint8_t *result, const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }
}

void bignum_to_bytes(const bignum256 *num, uint8_t *bytes) {
    bn_write_be(num, bytes);
}

void bytes_to_bignum(const uint8_t *bytes, bignum256 *num) {
    bn_read_be(bytes, num);
    bn_mod(num, &secp256k1.order);
}

int get_bit(const bignum256 *num, int bit_index) {
    if (bit_index < 0 || bit_index >= 256) {
        return 0;
    }
    return bn_testbit(num, bit_index) ? 1 : 0;
}

void pow2_bignum(int i, bignum256 *result) {
    bn_zero(result);
    bn_setbit(result, i);
}