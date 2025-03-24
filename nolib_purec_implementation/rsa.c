#include "rsa.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>


// Constants
// static const bignum BIGNUM_ONE = { NULL, 1, 1, false };

// Key Generation ====================================================
void rsa_keygen(RSAKey *key, int bits) {
    bignum *p = bignum_create(bits / 32 + 1);
    bignum *q = bignum_create(bits / 32 + 1);
    bignum *phi = bignum_create(bits / 16 + 1);

    // Generate primes p and q
    do {
        bignum_rand(p, bits / 2);
        while (!bignum_is_prime(p, 20)) {
            bignum_rand(p, bits / 2);
        }
        bignum_rand(q, bits / 2);
        while (!bignum_is_prime(q, 20)) {
            bignum_rand(q, bits / 2);
        }
    } while (bignum_cmp(p, q) == 0);

    // Compute n = p * q
    key->n = bignum_create(bits / 16 + 1);
    bignum_mul(p, q, key->n);

    // Compute φ(n) = (p-1)*(q-1)
    bignum *p_minus_1 = bignum_copy(p);
    bignum_sub(p_minus_1, &BIGNUM_ONE, p_minus_1);
    bignum *q_minus_1 = bignum_copy(q);
    bignum_sub(q_minus_1, &BIGNUM_ONE, q_minus_1);
    bignum_mul(p_minus_1, q_minus_1, phi);

    // Choose e (commonly 65537)
    key->e = bignum_create(1);
    bignum_from_int(key->e, 65537);
    while (bignum_cmp(key->e, phi) < 0) {
        bignum *gcd = bignum_create(1);
        bignum_gcd(key->e, phi, gcd);
        if (bignum_cmp(gcd, &BIGNUM_ONE) == 0) break;
        bignum_add(key->e, &BIGNUM_ONE, key->e);
        bignum_free(gcd);
    }

    // Compute d = e⁻¹ mod φ(n)
    key->d = bignum_create(bits / 16 + 1);
    bignum_mod_inverse(key->e, phi, key->d);

    // Cleanup
    bignum_free(p);
    bignum_free(q);
    bignum_free(phi);
    bignum_free(p_minus_1);
    bignum_free(q_minus_1);
}

// Encryption ========================================================
void rsa_encrypt(const bignum *m, const bignum *n, const bignum *e, bignum *c) {
    bignum_mod_exp(m, e, n, c);
}

// Decryption ========================================================
void rsa_decrypt(const bignum *c, const bignum *n, const bignum *d, bignum *m) {
    bignum_mod_exp(c, d, n, m);
}

// Signing ===========================================================
void rsa_sign(const char *msg, const bignum *n, const bignum *d, bignum *sigma) {
    // Compute SHA-256 hash of message
    uint8_t digest[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)msg, strlen(msg));
    sha256_final(&ctx, digest);

    // Convert hash to bignum
    bignum *hash = bignum_create(8);
    for (int i = 0; i < 32; i++) {
        bignum_shift_left(hash, 8);
        bignum_add(hash, bignum_from_byte(digest[i]), hash);
    }

    // Compute signature: σ = hash^d mod n
    bignum_mod_exp(hash, d, n, sigma);
    bignum_free(hash);
}

// Verification ======================================================
int rsa_verify(const bignum *sigma, const char *msg, const bignum *n, const bignum *e) {
    // Compute SHA-256 hash of message
    uint8_t digest[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)msg, strlen(msg));
    sha256_final(&ctx, digest);

    // Convert hash to bignum
    bignum *hash = bignum_create(8);
    for (int i = 0; i < 32; i++) {
        bignum_shift_left(hash, 8);
        bignum_add(hash, bignum_from_byte(digest[i]), hash);
    }

    // Compute recovered hash: hash' = σ^e mod n
    bignum *recovered = bignum_create(n->num_digits);
    bignum_mod_exp(sigma, e, n, recovered);

    // Compare hashes
    int result = bignum_cmp(hash, recovered);
    bignum_free(hash);
    bignum_free(recovered);
    return (result == 0);
}

// Memory Management =================================================
void rsa_free_key(RSAKey *key) {
    bignum_free(key->n);
    bignum_free(key->e);
    bignum_free(key->d);
    free(key);
}

int main() {
    RSAKey *key = malloc(sizeof(RSAKey));
    rsa_keygen(key, 2048);

    // Test encryption/decryption
    bignum *m = bignum_from_str("123456789");
    bignum *c = bignum_create(key->n->num_digits);
    rsa_encrypt(m, key->n, key->e, c);
    bignum *decrypted = bignum_create(key->n->num_digits);
    rsa_decrypt(c, key->n, key->d, decrypted);
    printf("Decrypted: %s\n", bignum_to_str(decrypted));

    // Test signing/verification
    const char *msg = "Hello World";
    bignum *sigma = bignum_create(key->n->num_digits);
    rsa_sign(msg, key->n, key->d, sigma);
    int valid = rsa_verify(sigma, msg, key->n, key->e);
    printf("Signature valid? %s\n", valid ? "Yes" : "No");

    // Cleanup
    rsa_free_key(key);
    bignum_free(m);
    bignum_free(c);
    bignum_free(decrypted);
    bignum_free(sigma);
    return 0;
}