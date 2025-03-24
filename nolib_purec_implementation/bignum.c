#include "bignum.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#define BIGNUM_BASE 0x100000000ULL  // 2^32
#define DEFAULT_CAPACITY 8

// Constants
const bignum BIGNUM_ZERO = {NULL, 0, 0, false};
const bignum BIGNUM_ONE = {NULL, 1, 1, false};
const bignum BIGNUM_TWO = {NULL, 1, 1, false};

// Memory management
bignum* bignum_create(int capacity) {
    bignum *n = malloc(sizeof(bignum));
    n->capacity = capacity > 0 ? capacity : DEFAULT_CAPACITY;
    n->digits = calloc(n->capacity, sizeof(uint32_t));
    n->num_digits = 0;
    n->sign = false;
    return n;
}

void bignum_free(bignum *n) {
    if (n) {
        free(n->digits);
        free(n);
    }
}

void bignum_resize(bignum *n, int new_capacity) {
    n->digits = realloc(n->digits, new_capacity * sizeof(uint32_t));
    memset(n->digits + n->capacity, 0, (new_capacity - n->capacity) * sizeof(uint32_t));
    n->capacity = new_capacity;
    if (n->num_digits > new_capacity) n->num_digits = new_capacity;
}

bignum* bignum_copy(const bignum *src) {
    bignum *dest = bignum_create(src->capacity);
    memcpy(dest->digits, src->digits, src->num_digits * sizeof(uint32_t));
    dest->num_digits = src->num_digits;
    dest->sign = src->sign;
    return dest;
}

// Arithmetic operations
void bignum_add(const bignum *a, const bignum *b, bignum *result) {
    int max_digits = (a->num_digits > b->num_digits) ? a->num_digits : b->num_digits;
    if (result->capacity < max_digits + 1) bignum_resize(result, max_digits + 1);

    uint64_t carry = 0;
    for (int i = 0; i < max_digits || carry; i++) {
        uint64_t sum = carry;
        if (i < a->num_digits) sum += a->digits[i];
        if (i < b->num_digits) sum += b->digits[i];
        
        result->digits[i] = sum % BIGNUM_BASE;
        carry = sum / BIGNUM_BASE;
        result->num_digits = i + 1;
    }
    result->sign = false; // Handle signs properly in actual implementation
}

void bignum_sub(const bignum *a, const bignum *b, bignum *result) {
    // Simplified implementation assuming a >= b
    int max_digits = a->num_digits;
    if (result->capacity < max_digits) bignum_resize(result, max_digits);

    uint64_t borrow = 0;
    for (int i = 0; i < max_digits; i++) {
        uint64_t sub = (i < b->num_digits) ? b->digits[i] : 0;
        uint64_t diff = BIGNUM_BASE + a->digits[i] - sub - borrow;
        result->digits[i] = diff % BIGNUM_BASE;
        borrow = 1 - (diff / BIGNUM_BASE);
    }
    result->num_digits = max_digits;
    while (result->num_digits > 0 && result->digits[result->num_digits - 1] == 0)
        result->num_digits--;
    result->sign = false; // Handle sign comparison properly
}

void bignum_mul(const bignum *a, const bignum *b, bignum *result) {
    int total_digits = a->num_digits + b->num_digits;
    if (result->capacity < total_digits) bignum_resize(result, total_digits);

    memset(result->digits, 0, total_digits * sizeof(uint32_t));
    
    for (int i = 0; i < a->num_digits; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->num_digits || carry; j++) {
            uint64_t product = result->digits[i + j] + 
                (uint64_t)a->digits[i] * (j < b->num_digits ? b->digits[j] : 0) + 
                carry;
            result->digits[i + j] = product % BIGNUM_BASE;
            carry = product / BIGNUM_BASE;
        }
    }
    
    result->num_digits = total_digits;
    while (result->num_digits > 0 && result->digits[result->num_digits - 1] == 0)
        result->num_digits--;
}

// More complex operations (simplified versions)
void bignum_divmod(const bignum *a, const bignum *b, bignum *q, bignum *r) {
    // Implement long division algorithm
    bignum_from_int(r, 0);
    bignum *current = bignum_copy(a);
    
    for (int i = current->num_digits - 1; i >= 0; i--) {
        bignum_shift_left(r, 32);
        r->digits[0] = current->digits[i];
        r->num_digits = (r->digits[0] != 0) ? 1 : 0;
        
        uint32_t quotient_digit = 0;
        while (bignum_cmp(r, b) >= 0) {
            bignum_sub(r, b, r);
            quotient_digit++;
        }
        q->digits[i] = quotient_digit;
    }
    
    bignum_free(current);
}

void bignum_mod_exp(const bignum *base, const bignum *exp, const bignum *mod, bignum *result) {
    bignum_from_int(result, 1);
    bignum *temp_base = bignum_copy(base);
    bignum *temp_exp = bignum_copy(exp);
    
    while (bignum_cmp(temp_exp, &BIGNUM_ZERO) > 0) {
        if (temp_exp->digits[0] & 1) {
            bignum_mul(result, temp_base, result);
            bignum_divmod(result, mod, NULL, result);
        }
        bignum_shift_right(temp_exp, 1);
        bignum_mul(temp_base, temp_base, temp_base);
        bignum_divmod(temp_base, mod, NULL, temp_base);
    }
    
    bignum_free(temp_base);
    bignum_free(temp_exp);
}

// New function implementations

// Shifts n left by 'bits' bits. For multiples of 32, we shift digits.
void bignum_shift_left(bignum *n, int bits) {
    int digit_shifts = bits / 32;
    int bit_shifts = bits % 32;
    // First, shift by whole digits (if needed)
    if (digit_shifts > 0) {
        if (n->capacity < n->num_digits + digit_shifts)
            bignum_resize(n, n->num_digits + digit_shifts);
        for (int i = n->num_digits - 1; i >= 0; i--) {
            n->digits[i + digit_shifts] = n->digits[i];
        }
        for (int i = 0; i < digit_shifts; i++) {
            n->digits[i] = 0;
        }
        n->num_digits += digit_shifts;
    }
    // Then shift remaining bits
    if (bit_shifts > 0) {
        uint64_t carry = 0;
        for (int i = 0; i < n->num_digits; i++) {
            uint64_t cur = ((uint64_t)n->digits[i] << bit_shifts) | carry;
            n->digits[i] = cur % BIGNUM_BASE;
            carry = cur / BIGNUM_BASE;
        }
        if (carry) {
            if (n->num_digits == n->capacity)
                bignum_resize(n, n->capacity + 1);
            n->digits[n->num_digits++] = carry;
        }
    }
}

// Shifts n right by 'bits' bits. For multiples of 32, we shift digits.
void bignum_shift_right(bignum *n, int bits) {
    int digit_shifts = bits / 32;
    int bit_shifts = bits % 32;
    if (digit_shifts >= n->num_digits) {
        n->num_digits = 0;
        return;
    }
    // Shift by whole digits
    if (digit_shifts > 0) {
        for (int i = 0; i < n->num_digits - digit_shifts; i++) {
            n->digits[i] = n->digits[i + digit_shifts];
        }
        n->num_digits -= digit_shifts;
    }
    // Then shift remaining bits
    if (bit_shifts > 0 && n->num_digits > 0) {
        uint32_t carry = 0;
        for (int i = n->num_digits - 1; i >= 0; i--) {
            uint32_t new_val = (n->digits[i] >> bit_shifts) | (carry << (32 - bit_shifts));
            carry = n->digits[i] & ((1U << bit_shifts) - 1);
            n->digits[i] = new_val;
        }
        while (n->num_digits > 0 && n->digits[n->num_digits - 1] == 0)
            n->num_digits--;
    }
}

// Returns a random bignum in the range [0, n-1].
// This is a simple implementation; in production code you might need a more secure approach.
bignum* bignum_rand_range(const bignum *n) {
    bignum *result = bignum_create(n->capacity);
    // Generate a random number with the same bit-length as n.
    int bits = n->num_digits * 32;
    bignum_rand(result, bits);
    // Use mod to bring it within [0, n-1]
    bignum_mod(result, n, result);
    return result;
}

// Computes result = a mod b.
void bignum_mod(const bignum *a, const bignum *b, bignum *result) {
    // Create temporary bignums for quotient and remainder.
    bignum *q = bignum_create(a->capacity);
    bignum *r = bignum_create(b->capacity);
    bignum_divmod(a, b, q, r);
    
    // Copy remainder r into result.
    result->num_digits = r->num_digits;
    memcpy(result->digits, r->digits, r->num_digits * sizeof(uint32_t));
    
    bignum_free(q);
    bignum_free(r);
}

// Helper functions
int bignum_cmp(const bignum *a, const bignum *b) {
    if (a->num_digits > b->num_digits) return 1;
    if (a->num_digits < b->num_digits) return -1;
    
    for (int i = a->num_digits - 1; i >= 0; i--) {
        if (a->digits[i] > b->digits[i]) return 1;
        if (a->digits[i] < b->digits[i]) return -1;
    }
    return 0;
}

void bignum_from_int(bignum *n, uint64_t val) {
    int needed_capacity = 2;
    if (n->capacity < needed_capacity) bignum_resize(n, needed_capacity);
    
    n->digits[0] = val % BIGNUM_BASE;
    n->digits[1] = val / BIGNUM_BASE;
    n->num_digits = (n->digits[1] != 0) ? 2 : 1;
}

void bignum_print(const bignum *n) {
    if (n->sign) printf("-");
    if (n->num_digits == 0) {
        printf("0");
        return;
    }
    
    // Simple hex print for demonstration
    printf("0x");
    for (int i = n->num_digits - 1; i >= 0; i--) {
        printf("%08x", n->digits[i]);
    }
}

// Prime testing (Miller-Rabin)
bool bignum_is_prime(const bignum *n, int rounds) {
    if (bignum_cmp(n, &BIGNUM_TWO) < 0) return false;
    if (bignum_cmp(n, &BIGNUM_TWO) == 0) return true;

    bignum *d = bignum_copy(n);
    bignum_sub(d, &BIGNUM_ONE, d);
    
    int s = 0;
    while ((d->digits[0] & 1) == 0) {
        bignum_shift_right(d, 1);
        s++;
    }

    for (int i = 0; i < rounds; i++) {
        bignum *a = bignum_rand_range(n);
        bignum *x = bignum_create(n->capacity);
        bignum_mod_exp(a, d, n, x);

        if (bignum_cmp(x, &BIGNUM_ONE) == 0 || bignum_cmp(x, d) == 0)
            continue;

        bool composite = true;
        for (int j = 0; j < s - 1; j++) {
            bignum_mul(x, x, x);
            bignum_mod(x, n, x);
            if (bignum_cmp(x, d) == 0) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

