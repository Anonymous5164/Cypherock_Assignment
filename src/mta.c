/*
  Implementation of the Multiplicative-to-Additive (MtA) protocol
  Works with full 256-bit numbers 
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include "logger.h"
 #include "mta.h"
 #include "utils.h"
  
 int mta_init(mta_context_t *ctx, mta_role_t role, const bignum256 *share) {
     if (!ctx || !share) {
         return -1;
     }
     
     // Initialize the context
     memset(ctx, 0, sizeof(mta_context_t));
     ctx->role = role;
     bn_copy(share, &ctx->share);
     bn_zero(&ctx->additive_share);
     
     // For the sender, generate all random values upfront
     if (role == MTA_ROLE_SENDER) {
         for (int i = 0; i < MTA_NUM_BITS; i++) {
             generate_random_bignum(&ctx->random_values[i]);
         }
     }
     
     return 0;
 }
  
 int mta_sender_bit_message(mta_context_t *ctx, int bit_index, OT_SenderMessage *message) {
     if (!ctx || !message || ctx->role != MTA_ROLE_SENDER || 
         bit_index < 0 || bit_index >= MTA_NUM_BITS) {
         return -1;
     }
     
     LOG_DEBUG("=== MtA Bit %d (Alice) ===", bit_index);
     
     // Generate random Ui for this bit
     bignum256 *Ui = &ctx->random_values[bit_index];
     
     // Calculate m0 = Ui
     uint8_t m0[32];
     bignum_to_bytes(Ui, m0);
     
     // Calculate m1 = Ui + x(2^i)
     bignum256 m1_bn;
     bn_copy(Ui, &m1_bn);
     
     // Calculate x(2^i)
     bignum256 power2i, x_times_2i;
     pow2_bignum(bit_index, &power2i);
     bn_copy(&ctx->share, &x_times_2i);
     bn_multiply(&power2i, &x_times_2i, &secp256k1.order);
     
     // Add to Ui
     bn_add(&m1_bn, &x_times_2i);
     bn_mod(&m1_bn, &secp256k1.order);
     
     uint8_t m1[32];
     bignum_to_bytes(&m1_bn, m1);
     
     // Store the key bits for later verification
     memcpy(ctx->m0_values[bit_index], m0, 32);
     memcpy(ctx->m1_values[bit_index], m1, 32);
     
     // Initialize the OT sender with these messages
     int ret = base_ot_init_sender(m0, m1, message, &ctx->sender_private_keys[bit_index]);
     if (ret != 0) {
         return ret;
     }
     
     // Save the sender message for later use
     memcpy(&ctx->sender_msgs[bit_index], message, sizeof(OT_SenderMessage));
     
     return 0;
 }
  
 int mta_receiver_bit_response(mta_context_t *ctx, int bit_index, 
                               const OT_SenderMessage *sender_msg,
                               OT_ReceiverMessage *receiver_msg) {
     if (!ctx || !sender_msg || !receiver_msg || ctx->role != MTA_ROLE_RECEIVER ||
         bit_index < 0 || bit_index >= MTA_NUM_BITS) {
         return -1;
     }
     
     LOG_DEBUG("=== MtA Bit %d (Bob) ===", bit_index);
     
     // Store the sender's message
     memcpy(&ctx->sender_msgs[bit_index], sender_msg, sizeof(OT_SenderMessage));
     
     // Determine the choice bit based on the bit of y (receiver's share)
     int choice_bit = get_bit(&ctx->share, bit_index);
     ctx->choice_bits[bit_index] = choice_bit; // Store for later use
     
     // Process the sender's message and generate our response
     int ret = base_ot_receiver_choice(
         &ctx->sender_msgs[bit_index],
         choice_bit,
         receiver_msg,
         ctx->receiver_keys[bit_index]
     );
     if (ret != 0) {
         return ret;
     }
     
     // Store the receiver message for later
     memcpy(&ctx->receiver_msgs[bit_index], receiver_msg, sizeof(OT_ReceiverMessage));
     
     return 0;
 }
  
 int mta_sender_bit_complete(mta_context_t *ctx, int bit_index, 
                             const OT_ReceiverMessage *receiver_msg) {
     if (!ctx || !receiver_msg || ctx->role != MTA_ROLE_SENDER ||
         bit_index < 0 || bit_index >= MTA_NUM_BITS) {
         return -1;
     }
     
     // Store the receiver's message
     memcpy(&ctx->receiver_msgs[bit_index], receiver_msg, sizeof(OT_ReceiverMessage));
     
     // Generate the OT keys
     uint8_t k0[32], k1[32];
     int ret = base_ot_sender_keys(
         &ctx->sender_private_keys[bit_index],
         &ctx->receiver_msgs[bit_index],
         k0, k1
     );
     if (ret != 0) {
         return ret;
     }
     
     // Store the keys for later verification
     memcpy(ctx->k0_values[bit_index], k0, 32);
     memcpy(ctx->k1_values[bit_index], k1, 32);
     
     return 0;
 }
  
 int mta_receiver_bit_complete(mta_context_t *ctx, int bit_index, 
                               const uint8_t *m0, const uint8_t *m1) {
     if (!ctx || !m0 || !m1 || ctx->role != MTA_ROLE_RECEIVER ||
         bit_index < 0 || bit_index >= MTA_NUM_BITS) {
         return -1;
     }
     
     // Get the choice bit for this position
     int choice_bit = ctx->choice_bits[bit_index];
     
     // Store the message values for verification
     memcpy(ctx->m0_values[bit_index], m0, 32);
     memcpy(ctx->m1_values[bit_index], m1, 32);
     
     // Decrypt the chosen message
     uint8_t received[32];
     int ret = base_ot_receive_message(
         choice_bit,
         ctx->receiver_keys[bit_index],
         m0, m1,
         received,
         32
     );
     if (ret != 0) {
         return ret;
     }
     
     // Convert the received message to a bignum
     bignum256 received_bn;
     bytes_to_bignum(received, &received_bn);
     
     // Add to the accumulating additive share
     bn_add(&ctx->additive_share, &received_bn);
     bn_mod(&ctx->additive_share, &secp256k1.order);
     
     return 0;
 }
  
 int mta_compute_additive_share(mta_context_t *ctx) {
     if (!ctx) {
         return -1;
     }
     
     if (ctx->role == MTA_ROLE_SENDER) {
         // For the sender (Alice), the additive share is -ΣUi
         bignum256 sum_Ui;
         bn_zero(&sum_Ui);
         
         // Sum all random values Ui for all bits
         for (int i = 0; i < MTA_NUM_BITS; i++) {
             bn_add(&sum_Ui, &ctx->random_values[i]);
             bn_mod(&sum_Ui, &secp256k1.order);
         }
         
         // Negate the sum: -sum_Ui = order - sum_Ui
         bn_subtract(&secp256k1.order, &sum_Ui, &ctx->additive_share);
         bn_mod(&ctx->additive_share, &secp256k1.order);
     } else {
         // For the receiver (Bob), the additive share has already been accumulated in mta_receiver_bit_complete
         bn_mod(&ctx->additive_share, &secp256k1.order);
     }
     
     return 0;
 }
  
 int mta_get_additive_share(const mta_context_t *ctx, bignum256 *share) {
     if (!ctx || !share) {
         return -1;
     }
     
     bn_copy(&ctx->additive_share, share);
     return 0;
 }
  
 int mta_verify(const bignum256 *a, const bignum256 *b, 
                const bignum256 *c, const bignum256 *d) {
     if (!a || !b || !c || !d) {
         return 0;
     }
 
     // Calculate a * b (mod order)
     bignum256 ab;
     bn_copy(a, &ab);
     bn_multiply(b, &ab, &secp256k1.order);
     bn_mod(&ab, &secp256k1.order);
 
     // Calculate c + d (mod order)
     bignum256 cd;
     bn_copy(c, &cd);
     bn_add(&cd, d);
     bn_mod(&cd, &secp256k1.order);
 
     // Check if a * b = c + d (mod order)
     return bn_is_equal(&ab, &cd);
 }