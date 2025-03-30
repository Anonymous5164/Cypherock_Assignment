#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cot.h"
#include "logger.h"
#include "utils.h"

int cot_init_sender(const uint8_t *delta, OT_SenderMessage *sender_msg, bignum256 *a) {
    if (!delta || !sender_msg || !a) {
        LOG_ERROR("Invalid parameters in cot_init_sender");
        return -1;
    }
    
    /* The init phase is the same as in base OT
    We don't need the messages m0, m1 at this stage*/
    
    uint8_t dummy_m0[32] = {0};
    uint8_t dummy_m1[32] = {0};
    
    // Initialize the sender using base OT
    int ret = base_ot_init_sender(dummy_m0, dummy_m1, sender_msg, a);
    
    return ret;
}

int cot_receiver_choice(const OT_SenderMessage *sender_msg, int choice_bit,
                       OT_ReceiverMessage *receiver_msg, uint8_t *k_c) {
    if (!sender_msg || !receiver_msg || !k_c || (choice_bit != 0 && choice_bit != 1)) {
        LOG_ERROR("Invalid parameters in cot_receiver_choice");
        return -1;
    }
    
    // The receiver choice phase is the same as in base OT
    return base_ot_receiver_choice(sender_msg, choice_bit, receiver_msg, k_c);
}

int cot_transfer(const uint8_t *delta, const bignum256 *a, 
                const OT_ReceiverMessage *receiver_msg,
                const uint8_t *m0, uint8_t *c0, uint8_t *c1, size_t msg_len) {
    if (!delta || !a || !receiver_msg || !m0 || !c0 || !c1 || msg_len == 0) {
        LOG_ERROR("Invalid parameters in cot_transfer");
        return -1;
    }
    
    // Generate the second message m1 = m0 ⊕ delta
    uint8_t m1[msg_len];
    xor_buffers(m1, m0, delta, msg_len);
    
    // Generate the encryption keys
    uint8_t k0[32], k1[32];
    int ret = base_ot_sender_keys(a, receiver_msg, k0, k1);
    if (ret != 0) {
        return ret;
    }
    
    // Encrypt the messages
    return base_ot_encrypt_messages(m0, m1, k0, k1, c0, c1, msg_len);
}

int cot_receive(int choice_bit, const uint8_t *k_c,
               const uint8_t *c0, const uint8_t *c1,
               uint8_t *output, size_t msg_len) {
    if (!k_c || !c0 || !c1 || !output || msg_len == 0 || 
        (choice_bit != 0 && choice_bit != 1)) {
        LOG_ERROR("Invalid parameters in cot_receive");
        return -1;
    }
    
    // Decrypt using base OT
    return base_ot_receive_message(choice_bit, k_c, c0, c1, output, msg_len);
}