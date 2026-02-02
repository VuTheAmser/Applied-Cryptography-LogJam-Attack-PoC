/* Fast C implementation of Diffie-Hellman operations - Supports up to 128-bit */

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <stdio.h>

/* Use __uint128_t if available (GCC/Clang) */
#ifdef __SIZEOF_INT128__
    typedef __uint128_t uint128_t;
    #define HAVE_128BIT 1
#else
    #define HAVE_128BIT 0
    #error "128-bit integers not supported. Please use GCC or Clang compiler."
#endif

/* 128-bit multiplication for larger moduli */
static inline uint64_t mulmod_128(uint64_t a, uint64_t b, uint64_t mod) {
    uint128_t result = ((uint128_t)a * (uint128_t)b) % (uint128_t)mod;
    return (uint64_t)result;
}

/* Modular exponentiation: (base^exp) % mod - supports up to 128-bit mod */
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) {
            result = mulmod_128(result, base, mod);
        }
        exp = exp >> 1;
        base = mulmod_128(base, base, mod);
    }
    return result;
}

/* Extended Euclidean Algorithm to compute modular inverse: a^(-1) mod m */
uint64_t mod_inverse(uint64_t a, uint64_t m) {
    int64_t old_r = (int64_t)a, r = (int64_t)m;
    int64_t old_s = 1, s = 0;
    
    while (r != 0) {
        int64_t quotient = old_r / r;
        int64_t temp = r;
        r = old_r - quotient * r;
        old_r = temp;
        
        temp = s;
        s = old_s - quotient * s;
        old_s = temp;
    }
    
    if (old_r > 1) {
        return 0;  /* No inverse exists */
    }
    
    /* Make sure result is positive */
    while (old_s < 0) {
        old_s += (int64_t)m;
    }
    return (uint64_t)(old_s % (int64_t)m);
}

/* Generate random number in range [min, max] */
uint64_t random_range(uint64_t min, uint64_t max) {
    if (max <= min) return min;
    uint64_t range = max - min + 1;
    return min + (rand() % range);
}

/* Helper: Combine two uint64_t into uint128_t */
static inline uint128_t combine_128(uint64_t high, uint64_t low) {
    return ((uint128_t)high << 64) | (uint128_t)low;
}

/* Helper: Split uint128_t into two uint64_t */
static inline void split_128(uint128_t value, uint64_t *high, uint64_t *low) {
    *high = (uint64_t)(value >> 64);
    *low = (uint64_t)(value & 0xFFFFFFFFFFFFFFFFULL);
}

/* 128-bit modular exponentiation */
static uint64_t mod_pow_128_full(uint128_t base, uint128_t exp, uint128_t mod) {
    uint128_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return (uint64_t)result;
}

/* Compute public value: g^x mod p - supports up to 128-bit p */
uint64_t compute_public_value(uint64_t g, uint64_t x, uint64_t p) {
    return mod_pow(g, x, p);
}

/* Compute public value with 128-bit prime: g^x mod p */
uint64_t compute_public_value_128(uint64_t g_high, uint64_t g_low, 
                                   uint64_t x_high, uint64_t x_low,
                                   uint64_t p_high, uint64_t p_low) {
    uint128_t g = combine_128(g_high, g_low);
    uint128_t x = combine_128(x_high, x_low);
    uint128_t p = combine_128(p_high, p_low);
    return mod_pow_128_full(g, x, p);
}

/* Compute shared secret: (peer_pub)^priv mod p - supports up to 128-bit p */
uint64_t compute_shared_secret(uint64_t peer_pub, uint64_t priv, uint64_t p) {
    return mod_pow(peer_pub, priv, p);
}

/* Compute shared secret with 128-bit prime: (peer_pub)^priv mod p */
uint64_t compute_shared_secret_128(uint64_t peer_pub_high, uint64_t peer_pub_low,
                                    uint64_t priv_high, uint64_t priv_low,
                                    uint64_t p_high, uint64_t p_low) {
    uint128_t peer_pub = combine_128(peer_pub_high, peer_pub_low);
    uint128_t priv = combine_128(priv_high, priv_low);
    uint128_t p = combine_128(p_high, p_low);
    return mod_pow_128_full(peer_pub, priv, p);
}

/* Hash table size */
#define HASH_SIZE 1048576  /* 1M entries */

typedef struct {
    uint64_t key;
    uint64_t value;
} hash_entry;

uint64_t hash(uint64_t key, uint64_t size) {
    return key % size;
}

/* Baby-step giant-step discrete log: find x where g^x = h (mod p) - supports up to 128-bit p */
uint64_t baby_step_giant_step(uint64_t p, uint64_t g, uint64_t h, int verbose) {
    uint64_t order = p - 1;
    /* Calculate m = ceil(sqrt(order)) */
    double sqrt_order = sqrt((double)order);
    uint64_t m = (uint64_t)ceil(sqrt_order);
    if (m < 1) m = 1;
    /* Limit to reasonable hash table size for performance */
    if (m > HASH_SIZE) {
        if (verbose) {
            printf("[DLOG] Limiting hash table size to %d for performance\n", HASH_SIZE);
        }
        m = HASH_SIZE;
    }
    
    struct timeval start_time, current_time;
    double elapsed = 0.0;
    
    if (verbose) {
        printf("[DLOG] Computing %llu baby steps...", (unsigned long long)m);
        fflush(stdout);
        gettimeofday(&start_time, NULL);
    }
    
    /* Simple hash table for baby steps */
    hash_entry *hash_table = (hash_entry *)calloc(m, sizeof(hash_entry));
    
    /* Baby steps: store g^j mod p for j in [0, m-1] */
    uint64_t gj = 1;
    for (uint64_t j = 0; j < m; j++) {
        uint64_t idx = hash(gj, m);
        uint64_t start_idx = idx;
        uint64_t probe_count = 0;
        
        /* Linear probing with loop prevention */
        while (hash_table[idx].key != 0 && hash_table[idx].key != gj && probe_count < m) {
            idx = (idx + 1) % m;
            probe_count++;
            if (idx == start_idx) break;
        }
        
        /* Insert if slot is empty or has same key */
        if (hash_table[idx].key == 0 || hash_table[idx].key == gj) {
            hash_table[idx].key = gj;
            hash_table[idx].value = j;
        }
        
        gj = mulmod_128(gj, g, p);
        
        /* Progress indicator with timer */
        if (verbose && (j + 1) % (m / 10 + 1) == 0) {
            gettimeofday(&current_time, NULL);
            elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                     (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
            printf(" (%.1fs)", elapsed);
            fflush(stdout);
        }
    }
    
    if (verbose) {
        gettimeofday(&current_time, NULL);
        elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                 (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
        printf(" done (%.2fs)\n", elapsed);
        printf("[DLOG] Computing %llu giant steps...", (unsigned long long)m);
        fflush(stdout);
        gettimeofday(&start_time, NULL);
    }
    
    /* Giant steps */
    uint64_t g_m = mod_pow(g, m, p);
    uint64_t g_inv_m = mod_inverse(g_m, p);
    if (g_inv_m == 0) {
        free(hash_table);
        return 0;
    }
    uint64_t current = h;
    
    for (uint64_t i = 0; i < m; i++) {
        /* Progress indicator with timer */
        if (verbose && (i + 1) % (m / 10 + 1) == 0) {
            gettimeofday(&current_time, NULL);
            elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                     (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
            printf(" (%.1fs)", elapsed);
            fflush(stdout);
        }
        
        uint64_t idx = hash(current, m);
        uint64_t start_idx = idx;
        uint64_t search_count = 0;
        
        /* Search in hash table with loop prevention */
        while (hash_table[idx].key != 0 && search_count < m) {
            if (hash_table[idx].key == current) {
                uint64_t j = hash_table[idx].value;
                uint64_t x = j + i * m;
                if (verbose) {
                    gettimeofday(&current_time, NULL);
                    elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                             (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
                    printf(" found! (i=%llu, j=%llu, %.2fs)\n", (unsigned long long)i, (unsigned long long)j, elapsed);
                }
                free(hash_table);
                return x % order;
            }
            idx = (idx + 1) % m;
            search_count++;
            
            if (idx == start_idx && search_count > 0) {
                break;
            }
        }
        current = mulmod_128(current, g_inv_m, p);
    }
    
    if (verbose) {
        gettimeofday(&current_time, NULL);
        elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                 (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
        printf(" failed (%.2fs)\n", elapsed);
    }
    free(hash_table);
    return 0;
}

/* Baby-step giant-step with 128-bit prime */
uint64_t baby_step_giant_step_128(uint64_t p_high, uint64_t p_low, uint64_t g_high, uint64_t g_low, uint64_t h_high, uint64_t h_low, int verbose) {
    uint128_t p = combine_128(p_high, p_low);
    uint128_t g = combine_128(g_high, g_low);
    uint128_t h = combine_128(h_high, h_low);
    
    uint128_t order = p - 1;
    double sqrt_order = sqrt((double)order);
    uint64_t m = (uint64_t)ceil(sqrt_order);
    if (m < 1) m = 1;
    if (m > HASH_SIZE) {
        if (verbose) {
            printf("[DLOG] Limiting hash table size to %d for performance\n", HASH_SIZE);
        }
        m = HASH_SIZE;
    }
    
    struct timeval start_time, current_time;
    double elapsed = 0.0;
    
    if (verbose) {
        printf("[DLOG] Computing %llu baby steps...", (unsigned long long)m);
        fflush(stdout);
        gettimeofday(&start_time, NULL);
    }
    
    hash_entry *hash_table = (hash_entry *)calloc(m, sizeof(hash_entry));
    uint128_t gj = 1;
    
    for (uint64_t j = 0; j < m; j++) {
        uint64_t gj_low = (uint64_t)(gj & 0xFFFFFFFFFFFFFFFFULL);
        uint64_t idx = hash(gj_low, m);
        uint64_t start_idx = idx;
        uint64_t probe_count = 0;
        
        while (hash_table[idx].key != 0 && hash_table[idx].key != gj_low && probe_count < m) {
            idx = (idx + 1) % m;
            probe_count++;
            if (idx == start_idx) break;
        }
        
        if (hash_table[idx].key == 0 || hash_table[idx].key == gj_low) {
            hash_table[idx].key = gj_low;
            hash_table[idx].value = j;
        }
        
        gj = (gj * g) % p;
        
        if (verbose && (j + 1) % (m / 10 + 1) == 0) {
            gettimeofday(&current_time, NULL);
            elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                     (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
            printf(" (%.1fs)", elapsed);
            fflush(stdout);
        }
    }
    
    if (verbose) {
        gettimeofday(&current_time, NULL);
        elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                 (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
        printf(" done (%.2fs)\n", elapsed);
        printf("[DLOG] Computing %llu giant steps...", (unsigned long long)m);
        fflush(stdout);
        gettimeofday(&start_time, NULL);
    }
    
    uint128_t g_m = mod_pow_128_full(g, (uint128_t)m, p);
    uint64_t g_m_low = (uint64_t)(g_m & 0xFFFFFFFFFFFFFFFFULL);
    uint64_t p_low_64 = (uint64_t)(p & 0xFFFFFFFFFFFFFFFFULL);
    uint64_t g_inv_m = mod_inverse(g_m_low, p_low_64);
    if (g_inv_m == 0) {
        free(hash_table);
        return 0;
    }
    uint128_t g_inv_m_128 = (uint128_t)g_inv_m;
    uint128_t current = h;
    
    for (uint64_t i = 0; i < m; i++) {
        if (verbose && (i + 1) % (m / 10 + 1) == 0) {
            gettimeofday(&current_time, NULL);
            elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                     (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
            printf(" (%.1fs)", elapsed);
            fflush(stdout);
        }
        
        uint64_t current_low = (uint64_t)(current & 0xFFFFFFFFFFFFFFFFULL);
        uint64_t idx = hash(current_low, m);
        uint64_t start_idx = idx;
        uint64_t search_count = 0;
        
        while (hash_table[idx].key != 0 && search_count < m) {
            if (hash_table[idx].key == current_low) {
                uint64_t j = hash_table[idx].value;
                uint128_t x = (uint128_t)j + (uint128_t)i * (uint128_t)m;
                if (verbose) {
                    gettimeofday(&current_time, NULL);
                    elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                             (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
                    printf(" found! (i=%llu, j=%llu, %.2fs)\n", (unsigned long long)i, (unsigned long long)j, elapsed);
                }
                free(hash_table);
                return (uint64_t)(x % order);
            }
            idx = (idx + 1) % m;
            search_count++;
            if (idx == start_idx && search_count > 0) {
                break;
            }
        }
        current = (current * g_inv_m_128) % p;
    }
    
    if (verbose) {
        gettimeofday(&current_time, NULL);
        elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                 (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
        printf(" failed (%.2fs)\n", elapsed);
    }
    free(hash_table);
    return 0;
}
