/*
  Correlated Oblivious Transfer (COT) as per Appendix A.3.2
  
  An extension of Base OT where:
  - Sender (Alice) has a correlation between messages: m1 = m0 + Δ
  - Alice only needs to know Δ (correlation pattern)
  - Receiver (Bob) still selects one message with choice bit c
  - Protocol efficiency is improved since only one random message is needed
  
 */

 #ifndef __COT_H__
 #define __COT_H__
 
 #include <stdint.h>
 #include "base_ot.h"
 #include "bignum.h"
 #include "ecdsa.h"
 #include "secp256k1.h"
 
 /**
  * Initialize sender for Correlated OT with a correlation value
  * 
  * @param delta Correlation value (m₁ = m₀ + delta)
  * @param sender_msg Output sender message to send to receiver
  * @param a Output sender's private key (needed for later steps)
  * @return 0 on success, error code on failure
  */
 int cot_init_sender(const uint8_t *delta, OT_SenderMessage *sender_msg, bignum256 *a);
 
 /**
  * Receiver generates a choice message for COT
  * 
  * @param sender_msg Sender's initialization message
  * @param choice_bit Receiver's choice bit (0 or 1)
  * @param receiver_msg Output receiver message to send back to sender
  * @param k_c Output receiver's secret key
  * @return 0 on success, error code on failure
  */
 int cot_receiver_choice(const OT_SenderMessage *sender_msg, int choice_bit,
                         OT_ReceiverMessage *receiver_msg, uint8_t *k_c);
 
 /**
  * Sender generates correlated transfer messages
  * 
  * @param delta Correlation value (m₁ = m₀ + delta)
  * @param a Sender's private key from initialization
  * @param receiver_msg Receiver's message
  * @param m0 Random message m₀
  * @param c0 Output encrypted m₀
  * @param c1 Output encrypted m₁ (= m₀ ⊕ delta)
  * @param msg_len Length of the message
  * @return 0 on success, error code on failure
  */
 int cot_transfer(const uint8_t *delta, const bignum256 *a, 
                 const OT_ReceiverMessage *receiver_msg,
                 const uint8_t *m0, uint8_t *c0, uint8_t *c1, size_t msg_len);
 
 /**
  * Receiver decrypts the chosen message
  * 
  * @param choice_bit Receiver's choice bit (0 or 1)
  * @param k_c Receiver's secret key
  * @param c0 Encrypted m₀
  * @param c1 Encrypted m₁
  * @param output Output decrypted message
  * @param msg_len Length of the message
  * @return 0 on success, error code on failure
  */
 int cot_receive(int choice_bit, const uint8_t *k_c,
                const uint8_t *c0, const uint8_t *c1,
                uint8_t *output, size_t msg_len);
 
 #endif /* __COT_H__ */