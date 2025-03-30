/*
  Multiplicative-to-Additive (MtA) Protocol 
  Implements a 2-party protocol where:
  - Alice has value a, Bob has value b
  - After the protocol, Alice gets c and Bob gets d
  - Such that a*b = c + d (mod order)
  - Neither party learns the other's input
  
  This implementation uses Correlated OT with bits of the receiver's share
  as choice bits to enable the conversion from multiplicative to additive shares.
 */

 #ifndef __MTA_H__
 #define __MTA_H__
 
 #include <stdint.h>
 #include "bignum.h"
 #include "ecdsa.h"
 #include "secp256k1.h"
 #include "base_ot.h"
 #include "cot.h"
 
 // Set to 256 for full security
 #define MTA_NUM_BITS 256
 
 /**
  * Role in the MtA protocol
  */
 typedef enum {
     MTA_ROLE_SENDER = 0,  // Alice in the protocol
     MTA_ROLE_RECEIVER = 1  // Bob in the protocol
 } mta_role_t;
 
 /**
  * The MtA protocol context
  */
 typedef struct {
     mta_role_t role;                    // Role in the protocol (sender or receiver)
     bignum256 share;                    // The local multiplicative share (a or b)
     bignum256 additive_share;           // The resulting additive share (c or d)
     bignum256 random_values[MTA_NUM_BITS]; // Random values Ui for sender
     OT_SenderMessage sender_msgs[MTA_NUM_BITS];   // Sender's messages for each bit
     OT_ReceiverMessage receiver_msgs[MTA_NUM_BITS]; // Receiver's messages for each bit
     bignum256 sender_private_keys[MTA_NUM_BITS];    // Sender's private keys for OT
     uint8_t receiver_keys[MTA_NUM_BITS][32];        // Receiver's keys for OT
     uint8_t m0_values[MTA_NUM_BITS][32];           // m0 values for each bit
     uint8_t m1_values[MTA_NUM_BITS][32];           // m1 values for each bit
     uint8_t k0_values[MTA_NUM_BITS][32];           // k0 values for sender
     uint8_t k1_values[MTA_NUM_BITS][32];           // k1 values for sender
     int choice_bits[MTA_NUM_BITS];                 // Receiver's choice bits
 } mta_context_t;
 
 /**
  * Initialize an MtA context for a specific role
  * 
  * @param ctx The MtA context to initialize
  * @param role The role in the protocol (sender or receiver)
  * @param share The multiplicative share (a for sender, b for receiver)
  * @return 0 on success, error code on failure
  */
 int mta_init(mta_context_t *ctx, mta_role_t role, const bignum256 *share);
 
 /**
  * Sender (Alice) starts the MtA protocol by generating messages for each bit
  * 
  * @param ctx The MtA context (must be initialized with MTA_ROLE_SENDER)
  * @param bit_index The bit index to process (0 to MTA_NUM_BITS-1)
  * @param message Output sender's message for this bit
  * @return 0 on success, error code on failure
  */
 int mta_sender_bit_message(mta_context_t *ctx, int bit_index, OT_SenderMessage *message);
 
 /**
  * Receiver (Bob) processes the sender's message for a bit and generates a response
  * 
  * @param ctx The MtA context (must be initialized with MTA_ROLE_RECEIVER)
  * @param bit_index The bit index to process (0 to MTA_NUM_BITS-1)
  * @param sender_msg The sender's message for this bit
  * @param receiver_msg Output receiver's response message for this bit
  * @return 0 on success, error code on failure
  */
 int mta_receiver_bit_response(mta_context_t *ctx, int bit_index, 
                               const OT_SenderMessage *sender_msg,
                               OT_ReceiverMessage *receiver_msg);
 
 /**
  * Sender (Alice) processes the receiver's response for a bit
  * 
  * @param ctx The MtA context (must be initialized with MTA_ROLE_SENDER)
  * @param bit_index The bit index to process (0 to MTA_NUM_BITS-1)
  * @param receiver_msg The receiver's response for this bit
  * @return 0 on success, error code on failure
  */
 int mta_sender_bit_complete(mta_context_t *ctx, int bit_index, 
                            const OT_ReceiverMessage *receiver_msg);
 
 /**
  * Receiver (Bob) processes the sender's final message for a bit
  * 
  * @param ctx The MtA context (must be initialized with MTA_ROLE_RECEIVER)
  * @param bit_index The bit index to process (0 to MTA_NUM_BITS-1)
  * @param m0 The first message (choice 0)
  * @param m1 The second message (choice 1)
  * @return 0 on success, error code on failure
  */
 int mta_receiver_bit_complete(mta_context_t *ctx, int bit_index, 
                              const uint8_t *m0, const uint8_t *m1);
 
 /**
 * Compute the final additive share after all bits have been processed
 * 
 * @param ctx The MtA context
 * @param bits_used The number of bits that were processed
 * @return 0 on success, error code on failure
 */
int mta_compute_additive_share(mta_context_t *ctx);
 
 /**
  * Get the resulting additive share
  * 
  * @param ctx The MtA context
  * @param share The output additive share (c for sender, d for receiver)
  * @return 0 on success, error code on failure
  */
 int mta_get_additive_share(const mta_context_t *ctx, bignum256 *share);
 
 /**
  * Verify that a * b = c + d (mod order)
  * This function is primarily for testing and verification
  * 
  * @param a First multiplicative share
  * @param b Second multiplicative share
  * @param c First additive share
  * @param d Second additive share
  * @return 1 if verified, 0 otherwise
  */
 int mta_verify(const bignum256 *a, const bignum256 *b, 
                const bignum256 *c, const bignum256 *d);
 
 #endif /* __MTA_H__ */