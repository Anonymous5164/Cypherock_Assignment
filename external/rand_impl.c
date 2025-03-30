#include <stdlib.h>
#include <stdint.h>
#include <time.h>

// Simple implementation of random32 function required by trezor crypto
uint32_t random32(void) {
    // Note: This is not cryptographically secure, but it's sufficient for testing
    uint32_t r = rand() & 0xff;
    r = (r << 8) | (rand() & 0xff);
    r = (r << 8) | (rand() & 0xff);
    r = (r << 8) | (rand() & 0xff);
    return r;
}

// Simple implementation of random_reseed function
void random_reseed(const uint32_t value) {
    srand(value);
}