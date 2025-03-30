/*
  Base Oblivious Transfer (OT) protocol implementation
  
  Implements the 1-out-of-2 OT protocol where:
  - Sender (Alice) has two messages m0, m1
  - Receiver (Bob) selects one message (with choice bit c)
  - After the protocol, Bob gets mc, but learns nothing about m1-c
  - Alice learns nothing about Bob's choice bit c
  
  This implementation uses the secp256k1 elliptic curve with SHA-256 for
  key derivation and XOR for encryption.
 */

 #ifndef __BASE_OT_H__
 #define __BASE_OT_H__
 
 #include <stdint.h>
 #include "bignum.h"
 #include "ecdsa.h"
 #include "secp256k1.h"
 #include "sha2.h"
 #include "rand.h"
 
 
//    Sender message containing the OT public key
 
 typedef struct {
     uint8_t A_compressed[33]; // Compressed public key A
 } OT_SenderMessage;
 
//    Receiver message containing the OT key choice
  
 typedef struct {
     uint8_t B_compressed[33]; // Compressed public key B
 } OT_ReceiverMessage;
 
 /**
  * Initialize the Base OT protocol as a sender
  * 
  * @param m0 First message (input)
  * @param m1 Second message (input)
  * @param message Sender message containing public key A (output)
  * @param a The sender's private key (output, needed for later)
  * @return 0 on success, error code otherwise
  */
 int base_ot_init_sender(const uint8_t *m0, const uint8_t *m1, 
                         OT_SenderMessage *message, bignum256 *a);
 
 /**
  * Receiver generates a choice message based on which message they want to receive
  * 
  * @param sender_msg Sender's message containing key A
  * @param choice_bit 0 for m0, 1 for m1
  * @param receiver_msg Receiver's message to send back to sender (output)
  * @param k_c Receiver's derived key (output)
  * @return 0 on success, error code otherwise
  */
 int base_ot_receiver_choice(const OT_SenderMessage *sender_msg, int choice_bit,
                            OT_ReceiverMessage *receiver_msg, uint8_t *k_c);
 
 /**
  * Sender computes the two encryption keys based on receiver's message
  * 
  * @param a Sender's private key from init
  * @param receiver_msg Receiver's message containing key B
  * @param k0 First derived key (output)
  * @param k1 Second derived key (output)
  * @return 0 on success, error code otherwise
  */
 int base_ot_sender_keys(const bignum256 *a, const OT_ReceiverMessage *receiver_msg,
                         uint8_t *k0, uint8_t *k1);
 
 /**
  * Encrypt the original messages with derived keys and send them to receiver
  * 
  * @param m0 First message
  * @param m1 Second message
  * @param k0 First key
  * @param k1 Second key
  * @param c0 First encrypted message (output)
  * @param c1 Second encrypted message (output)
  * @param msg_len Length of each message
  * @return 0 on success, error code otherwise
  */
 int base_ot_encrypt_messages(const uint8_t *m0, const uint8_t *m1,
                              const uint8_t *k0, const uint8_t *k1,
                              uint8_t *c0, uint8_t *c1, size_t msg_len);
 
 /**
  * Receiver decrypts the chosen message
  * 
  * @param choice_bit 0 for m0, 1 for m1
  * @param k_c Receiver's derived key
  * @param c0 First encrypted message
  * @param c1 Second encrypted message
  * @param output Decrypted message (output)
  * @param msg_len Length of each message
  * @return 0 on success, error code otherwise
  */
 int base_ot_receive_message(int choice_bit, const uint8_t *k_c,
                            const uint8_t *c0, const uint8_t *c1,
                            uint8_t *output, size_t msg_len);
 
 #endif /* __BASE_OT_H__ */