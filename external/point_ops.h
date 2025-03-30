/**
 * Optimized point operations for elliptic curve cryptography
 * Specifically designed for base_ot implementation
 */

 #ifndef __POINT_OPS_H__
 #define __POINT_OPS_H__
 
 #include "bignum.h"
 #include "ecdsa.h"
 
 /**
  * Optimized scalar multiplication using window method
  * Computes res = k * G where G is the generator point
  * 
  * @param curve The elliptic curve to use
  * @param k The scalar to multiply by
  * @param res The resulting point (output)
  * @return 1 on success, 0 on failure
  */
 int opt_scalar_multiply(const ecdsa_curve *curve, const bignum256 *k, curve_point *res);
 
 /**
  * Optimized point multiplication
  * Computes res = k * p
  * 
  * @param curve The elliptic curve to use
  * @param k The scalar to multiply by
  * @param p The point to multiply
  * @param res The resulting point (output)
  * @return 1 on success, 0 on failure
  */
 int opt_point_multiply(const ecdsa_curve *curve, const bignum256 *k, const curve_point *p, curve_point *res);
 
 #endif /* __POINT_OPS_H__ */