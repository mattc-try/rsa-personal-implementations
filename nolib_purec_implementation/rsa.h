#ifndef RSA_H
#define RSA_H

#include "bignum.h"
#include "sha256.h"

// RSA Key Structure
typedef struct {
    bignum *n;  // Modulus
    bignum *e;  // Public exponent
    bignum *d;  // Private exponent
} RSAKey;

// Key Generation
void rsa_keygen(RSAKey *key, int bits);

// Encryption/Decryption
void rsa_encrypt(const bignum *m, const bignum *n, const bignum *e, bignum *c);
void rsa_decrypt(const bignum *c, const bignum *n, const bignum *d, bignum *m);

// Signing/Verification
void rsa_sign(const char *msg, const bignum *n, const bignum *d, bignum *sigma);
int rsa_verify(const bignum *sigma, const char *msg, const bignum *n, const bignum *e);

// Utility Functions
void rsa_free_key(RSAKey *key);

#endif // RSA_H