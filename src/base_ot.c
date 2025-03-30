/*
  Implementation of Base Oblivious Transfer
  Using SHA-256 for key derivation and XOR for encryption
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base_ot.h"
#include "point_ops.h"  
#include "logger.h"
#include "utils.h"

int base_ot_init_sender(const uint8_t *m0, const uint8_t *m1, 
                        OT_SenderMessage *message, bignum256 *a) {
    if (!m0 || !m1 || !message || !a) {
        LOG_ERROR("Invalid parameters in base_ot_init_sender");
        return -1;
    }
    
    // Generate a random private key a
    generate_random_nonzero_scalar(a);
    
    // Compute A = a·G (public key) using optimized scalar multiplication
    curve_point A;
    int res = opt_scalar_multiply(&secp256k1, a, &A);
    
    if (res != 1) {
        LOG_ERROR("Failed to compute A = a·G");
        return -2;
    }
    
    // Compress point A
    message->A_compressed[0] = 0x02 | (A.y.val[0] & 1);  // Set prefix based on y parity
    bn_write_be(&A.x, message->A_compressed + 1);
    
    // Debug output
    uint8_t a_bytes[32];
    bn_write_be(a, a_bytes);
    char hex_buffer[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex_buffer + (i * 2), "%02x", a_bytes[i]);
    }
    LOG_DEBUG("Alice's secret a: %s", hex_buffer);
    
    // Log messages before encryption
    char hex_buffer_m0[32 * 2 + 1];
    char hex_buffer_m1[32 * 2 + 1];
    hex_buffer_m0[0] = '\0';
    hex_buffer_m1[0] = '\0';
    for (int i = 0; i < 32; i++) {
        sprintf(hex_buffer_m0 + (i * 2), "%02x", m0[i]);
        sprintf(hex_buffer_m1 + (i * 2), "%02x", m1[i]);
    }
    LOG_DEBUG("Alice's message m0: %s", hex_buffer_m0);
    LOG_DEBUG("Alice's message m1: %s", hex_buffer_m1);
    
    return 0;
}

int base_ot_receiver_choice(const OT_SenderMessage *sender_msg, int choice_bit,
    OT_ReceiverMessage *receiver_msg, uint8_t *k_c) {
    if (!sender_msg || !receiver_msg || !k_c || (choice_bit != 0 && choice_bit != 1)) {
        LOG_ERROR("Invalid parameters in base_ot_receiver_choice");
        return -1;
    }

    // Decode point A
    curve_point A;
    if (ecdsa_read_pubkey(&secp256k1, sender_msg->A_compressed, &A) != 1) {
        LOG_ERROR("Failed to decompress sender's public key A");
        return -2;
    }

    // Generate random b
    bignum256 b;
    generate_random_nonzero_scalar(&b);

    // Debug output for b
    uint8_t b_bytes[32];
    bn_write_be(&b, b_bytes);
    char hex_buffer[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex_buffer + (i * 2), "%02x", b_bytes[i]);
    }
    LOG_DEBUG("Bob's secret b: %s", hex_buffer);
    LOG_DEBUG("Bob's choice bit: %d", choice_bit);

    // Compute B = b·G + choice_bit·A
    curve_point B, bG;

    // Calculate b·G using optimized scalar multiplication
    int res = opt_scalar_multiply(&secp256k1, &b, &bG);
    if (res != 1) {
        LOG_ERROR("Failed to compute b·G, error code: %d", res);
        return -3;
    }

    // Set B = bG initially
    point_copy(&bG, &B);

    // If choice_bit is 1, add A to B
    if (choice_bit == 1) {
        point_add(&secp256k1, &A, &B);
    }

    // Compress point B
    receiver_msg->B_compressed[0] = 0x02 | (B.y.val[0] & 1);
    bn_write_be(&B.x, receiver_msg->B_compressed + 1);

    // Compute the receiver's key using optimized point multiplication
    curve_point bA;
    res = opt_point_multiply(&secp256k1, &b, &A, &bA);
    if (res != 1) {
        LOG_ERROR("Failed to compute b·A, error code: %d", res);
        return -4;
    }

    // Derive the key from bA using SHA-256
    derive_key_from_point(&bA, k_c);

    // DEBUG: Print final derived key
    char hex_buffer_k_c[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex_buffer_k_c + (i * 2), "%02x", k_c[i]);
    }
    LOG_DEBUG("Bob derived k_c: %s", hex_buffer_k_c);

    return 0;
}

int base_ot_sender_keys(const bignum256 *a, const OT_ReceiverMessage *receiver_msg,
    uint8_t *k0, uint8_t *k1) {
    if (!a || !receiver_msg || !k0 || !k1) {
        LOG_ERROR("Invalid parameters in base_ot_sender_keys");
        return -1;
    }
    
    // Decode point B
    curve_point B;
    if (ecdsa_read_pubkey(&secp256k1, receiver_msg->B_compressed, &B) != 1) {
        LOG_ERROR("Failed to decompress receiver's public key B");
        return -2;
    }
    
    // Compute A = a·G (sender's public key) using optimized scalar multiplication
    curve_point A;
    if (opt_scalar_multiply(&secp256k1, a, &A) != 1) {
        LOG_ERROR("Failed to compute A = a·G");
        return -3;
    }
    
    // Compute a·B using optimized point multiplication
    curve_point aB;
    if (opt_point_multiply(&secp256k1, a, &B, &aB) != 1) {
        LOG_ERROR("Failed to compute a·B");
        return -4;
    }
    
    // Compute a·(B-A)
    
    // First, we need B-A = B + (-A)
    curve_point B_minus_A;
    
    // Copy B to B_minus_A
    point_copy(&B, &B_minus_A);
    
    // Negate A (flip the y-coordinate)
    curve_point A_neg;
    point_copy(&A, &A_neg);
    bn_subtract(&secp256k1.prime, &A_neg.y, &A_neg.y);
    
    // Add -A to B_minus_A
    point_add(&secp256k1, &A_neg, &B_minus_A);
    
    // Compute a·(B-A) using optimized point multiplication
    curve_point a_B_minus_A;
    if (opt_point_multiply(&secp256k1, a, &B_minus_A, &a_B_minus_A) != 1) {
        LOG_ERROR("Failed to compute a·(B-A)");
        return -5;
    }
    
    // For choice bit 0, the receiver uses a·B
    // For choice bit 1, the receiver uses a·(B-A)
    derive_key_from_point(&aB, k0);  // Key for choice bit 0
    derive_key_from_point(&a_B_minus_A, k1);  // Key for choice bit 1
    
    // Debug output
    char hex_buffer_k0[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex_buffer_k0 + (i * 2), "%02x", k0[i]);
    }
    LOG_DEBUG("Alice's key for bit 0: %s", hex_buffer_k0);
    
    char hex_buffer_k1[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex_buffer_k1 + (i * 2), "%02x", k1[i]);
    }
    LOG_DEBUG("Alice's key for bit 1: %s", hex_buffer_k1);
    
    return 0;
}

int base_ot_encrypt_messages(const uint8_t *m0, const uint8_t *m1,
                             const uint8_t *k0, const uint8_t *k1,
                             uint8_t *c0, uint8_t *c1, size_t msg_len) {
    if (!m0 || !m1 || !k0 || !k1 || !c0 || !c1 || msg_len == 0) {
        LOG_ERROR("Invalid parameters in base_ot_encrypt_messages");
        return -1;
    }
    
    // First copy the original messages to output buffers
    memcpy(c0, m0, msg_len);
    memcpy(c1, m1, msg_len);
    
    // Encrypt each message with its corresponding key
    sha256_xor_crypt(c0, k0, msg_len);
    sha256_xor_crypt(c1, k1, msg_len);
    
    return 0;
}

int base_ot_receive_message(int choice_bit, const uint8_t *k_c,
                           const uint8_t *c0, const uint8_t *c1,
                           uint8_t *output, size_t msg_len) {
    if (!k_c || !c0 || !c1 || !output || msg_len == 0 || 
        (choice_bit != 0 && choice_bit != 1)) {
        LOG_ERROR("Invalid parameters in base_ot_receive_message");
        return -1;
    }
    
    // Choose the encrypted message based on the choice bit
    const uint8_t *chosen_ciphertext = (choice_bit == 0) ? c0 : c1;
    
    // Copy the chosen ciphertext to output
    memcpy(output, chosen_ciphertext, msg_len);
    
    // Decrypt the message
    sha256_xor_crypt(output, k_c, msg_len);
    
    // Print decrypted message
    char hex_buffer_output[msg_len * 2 + 1];
    for (int i = 0; i < msg_len; i++) {
        sprintf(hex_buffer_output + (i * 2), "%02x", output[i]);
    }
    LOG_DEBUG("Bob decrypted message m%d: %s", choice_bit, hex_buffer_output);
    
    return 0;
}