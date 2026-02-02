/* Fast C implementation of Diffie-Hellman operations - Header */

#ifndef C_DH_H
#define C_DH_H

#include <stdint.h>
#include <math.h>

uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod);
uint64_t mod_inverse(uint64_t a, uint64_t m);
uint64_t compute_public_value(uint64_t g, uint64_t x, uint64_t p);
uint64_t compute_public_value_128(uint64_t g_high, uint64_t g_low, uint64_t x_high, uint64_t x_low, uint64_t p_high, uint64_t p_low);
uint64_t compute_shared_secret(uint64_t peer_pub, uint64_t priv, uint64_t p);
uint64_t compute_shared_secret_128(uint64_t peer_pub_high, uint64_t peer_pub_low, uint64_t priv_high, uint64_t priv_low, uint64_t p_high, uint64_t p_low);
uint64_t baby_step_giant_step(uint64_t p, uint64_t g, uint64_t h, int verbose);
uint64_t baby_step_giant_step_128(uint64_t p_high, uint64_t p_low, uint64_t g_high, uint64_t g_low, uint64_t h_high, uint64_t h_low, int verbose);

#endif

