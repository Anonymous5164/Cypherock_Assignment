#include <string.h>
#include "point_ops.h"

// Number of bits in the window
#define WINDOW_SIZE 4
// Number of precomputed points (2^WINDOW_SIZE)
#define PRECOMP_SIZE (1 << WINDOW_SIZE)

int opt_scalar_multiply(const ecdsa_curve *curve, const bignum256 *k, curve_point *res) {
    // Use 4-bit window for efficiency (16 precomputed points)
    curve_point precomp[PRECOMP_SIZE];
    bignum256 k_reduced;
    
    // Make a copy of k and reduce it modulo curve order
    bn_copy(k, &k_reduced);
    bn_mod(&k_reduced, &curve->order);
    
    // Precompute multiples of G: G, 2G, 3G, ..., 15G
    point_set_infinity(&precomp[0]);
    point_copy(&curve->G, &precomp[1]);
    
    for (int i = 2; i < PRECOMP_SIZE; i++) {
        point_copy(&precomp[i-1], &precomp[i]);
        point_add(curve, &curve->G, &precomp[i]);
    }
    
    // Start with infinity
    point_set_infinity(res);
    
    // Process scalar from most significant bit to least significant
    // (Right-to-left binary method with windowing)
    for (int i = 256 - WINDOW_SIZE; i >= 0; i -= WINDOW_SIZE) {
        // Double the result WINDOW_SIZE times
        for (int j = 0; j < WINDOW_SIZE; j++) {
            point_double(curve, res);
        }
        
        // Extract window_size bits
        int window = 0;
        for (int j = 0; j < WINDOW_SIZE && i + j < 256; j++) {
            if (bn_testbit(&k_reduced, i + j)) {
                window |= (1 << j);
            }
        }
        
        // Add the precomputed value if window is not 0
        if (window > 0) {
            point_add(curve, &precomp[window], res);
        }
    }
    
    return 1;
}

int opt_point_multiply(const ecdsa_curve *curve, const bignum256 *k, const curve_point *p, curve_point *res) {
    // Copy scalar and reduce modulo curve order
    bignum256 k_reduced;
    bn_copy(k, &k_reduced);
    bn_mod(&k_reduced, &curve->order);
    
    // Set result to infinity (identity element)
    point_set_infinity(res);
    
    // Use efficient double-and-add algorithm
    // This avoids the nested loop in your original implementation
    curve_point tmp;
    point_copy(p, &tmp);
    
    for (int i = 0; i < 256; i++) {
        if (bn_testbit(&k_reduced, i)) {
            point_add(curve, &tmp, res);
        }
        
        // Double the temporary point
        point_double(curve, &tmp);
    }
    
    return 1;
}