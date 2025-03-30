/**
 * Test implementation for the Multiplicative-to-Additive protocol
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mta.h"
#include "secp256k1.h"
#include "rand.h"
#include "logger.h"
#include "mta_test.h"

// Utility function to print a bignum
static void print_bignum(const char *label, const bignum256 *bn) {
    uint8_t bytes[32];
    bn_write_be(bn, bytes);
    
    char hex_buffer[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex_buffer + (i * 2), "%02x", bytes[i]);
    }
    
    LOG_INFO("%s: %s", label, hex_buffer);
    // Also log full details to debug log
    LOG_DEBUG("%s: %s", label, hex_buffer);
}

// Generate a random scalar in the range [1, order-1]
static void generate_random_scalar(bignum256 *scalar) {
    uint8_t buffer[32];
    
    do {
        random_buffer(buffer, sizeof(buffer));
        bn_read_be(buffer, scalar);
        bn_mod(scalar, &secp256k1.order);
    } while (bn_is_zero(scalar));
}

int run_mta_full_test(void) {
    LOG_INFO("===== Full 256-bit MtA Protocol Test =====");
    
    // Generate random values for a and b
    bignum256 a, b;
    generate_random_scalar(&a);
    generate_random_scalar(&b);
    
    // Print the input values
    print_bignum("Alice's Multiplicative share (a)", &a);
    print_bignum("Bob's Multiplicative share (b)", &b);
    
    // Calculate expected product a*b
    bignum256 expected_product;
    bn_copy(&a, &expected_product);
    bn_multiply(&b, &expected_product, &secp256k1.order);
    bn_mod(&expected_product, &secp256k1.order);
    
    print_bignum("Expected product a*b (mod order)", &expected_product);
    
    // Initialize MtA contexts
    mta_context_t sender_ctx, receiver_ctx;
    
    LOG_INFO("Initializing MtA contexts...");
    if (mta_init(&sender_ctx, MTA_ROLE_SENDER, &a) != 0 ||
        mta_init(&receiver_ctx, MTA_ROLE_RECEIVER, &b) != 0) {
        LOG_ERROR("Failed to initialize MtA contexts");
        return -1;
    }
    
    // Find the highest bit in both a and b to determine how many bits to process
    int max_bit_a = -1, max_bit_b = -1;
    for (int i = 255; i >= 0; i--) {
        if (max_bit_a < 0 && bn_testbit(&a, i)) max_bit_a = i;
        if (max_bit_b < 0 && bn_testbit(&b, i)) max_bit_b = i;
        if (max_bit_a >= 0 && max_bit_b >= 0) break;
    }
    
    // Calculate the number of bits to process
    int bits_to_process = (max_bit_a > max_bit_b ? max_bit_a : max_bit_b) + 1;
    if (bits_to_process > MTA_NUM_BITS) bits_to_process = MTA_NUM_BITS;
    
    LOG_INFO("Processing %d bits in the MtA protocol", bits_to_process);
    
    // Sum of all Ui values (for sender's final share)
    bignum256 sum_Ui;
    bn_zero(&sum_Ui);
    
    // Process bit by bit
    for (int i = 0; i < bits_to_process; i++) {
        if (i % 32 == 0) {
            LOG_INFO("Processing bits %d to %d...", 
                    i, i + 31 < bits_to_process ? i + 31 : bits_to_process - 1);
        }
        
        // Sender generates message for this bit
        OT_SenderMessage sender_msg;
        if (mta_sender_bit_message(&sender_ctx, i, &sender_msg) != 0) {
            LOG_ERROR("Failed to generate sender message for bit %d", i);
            return -1;
        }
        
        // Add the random value to the sum (for sender's final share)
        bn_add(&sum_Ui, &sender_ctx.random_values[i]);
        bn_mod(&sum_Ui, &secp256k1.order);
        
        // Receiver processes the sender's message to determine choice bit
        OT_ReceiverMessage receiver_msg;
        if (mta_receiver_bit_response(&receiver_ctx, i, &sender_msg, &receiver_msg) != 0) {
            LOG_ERROR("Failed to process sender message for bit %d", i);
            return -1;
        }
        
        // Get the receiver's choice bit for this position
        int choice_bit = receiver_ctx.choice_bits[i];
        
        // Sender processes receiver's response (normally would generate encryption keys)
        if (mta_sender_bit_complete(&sender_ctx, i, &receiver_msg) != 0) {
            LOG_ERROR("Failed to process receiver message for bit %d", i);
            return -1;
        }
        
        // DIRECT TRANSFER without encryption: Determine which message to send based on choice bit
        uint8_t *message_to_receive = choice_bit ? sender_ctx.m1_values[i] : sender_ctx.m0_values[i];
        
        // Convert message to bignum
        bignum256 received_value;
        bn_read_be(message_to_receive, &received_value);
        
        // Add to receiver's share
        bn_add(&receiver_ctx.additive_share, &received_value);
        bn_mod(&receiver_ctx.additive_share, &secp256k1.order);
        
        // Print status periodically
        if (i % 32 == 31 || i == bits_to_process - 1) {
            LOG_DEBUG("Processed %d of %d bits", i + 1, bits_to_process);
        }
    }
    
    // Calculate sender's share as -sum(Ui)
    bignum256 sender_share;
    bn_subtract(&secp256k1.order, &sum_Ui, &sender_share);
    bn_mod(&sender_share, &secp256k1.order);
    
    LOG_INFO("--- Final Results ---");
    print_bignum("Sum of all Ui values", &sum_Ui);
    print_bignum("Sender's Share (c = -Σ Ui)", &sender_share);
    print_bignum("Receiver's Share (d = Σ received values)", &receiver_ctx.additive_share);
    
    // Calculate c+d
    bignum256 c_plus_d;
    bn_copy(&sender_share, &c_plus_d);
    bn_add(&c_plus_d, &receiver_ctx.additive_share);
    bn_mod(&c_plus_d, &secp256k1.order);
    
    LOG_INFO("--- Verification ---");
    print_bignum("a*b", &expected_product);
    print_bignum("c+d", &c_plus_d);
    
    int verified = bn_is_equal(&expected_product, &c_plus_d);
    LOG_INFO("Verification result: %s", verified ? "SUCCESS" : "FAILURE");
    
    return verified ? 0 : -1;
}