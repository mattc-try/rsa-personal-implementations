#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
    uint32_t *digits;  // Little-endian storage (LSB first)
    int num_digits;     // Number of allocated digits
    int capacity;       // Total allocated capacity
    bool sign;          // true for negative
} bignum;

// Memory management
bignum* bignum_create(int capacity);
void bignum_free(bignum *n);
bignum* bignum_copy(const bignum *src);
void bignum_resize(bignum *n, int new_capacity);

// Basic arithmetic
void bignum_add(const bignum *a, const bignum *b, bignum *result);
void bignum_sub(const bignum *a, const bignum *b, bignum *result);
void bignum_mul(const bignum *a, const bignum *b, bignum *result);
void bignum_divmod(const bignum *a, const bignum *b, bignum *q, bignum *r);
void bignum_mod_exp(const bignum *base, const bignum *exp, const bignum *mod, bignum *result);
void bignum_gcd(const bignum *a, const bignum *b, bignum *result);
void bignum_mod_inverse(const bignum *a, const bignum *m, bignum *result);

// New functions: prototypes for missing operations
void bignum_shift_left(bignum *n, int bits);
void bignum_shift_right(bignum *n, int bits);
bignum* bignum_rand_range(const bignum *n);
void bignum_mod(const bignum *a, const bignum *b, bignum *result);

// Helper functions
int bignum_cmp(const bignum *a, const bignum *b);
void bignum_from_int(bignum *n, uint64_t val);
void bignum_rand(bignum *n, int bits);
bool bignum_is_prime(const bignum *n, int rounds);
void bignum_print(const bignum *n);
bignum* bignum_from_byte(uint8_t byte);
bignum* bignum_from_str(const char *str);
char* bignum_to_str(const bignum *n);

// Constants
extern const bignum BIGNUM_ZERO;
extern const bignum BIGNUM_ONE;
extern const bignum BIGNUM_TWO;

#endif
