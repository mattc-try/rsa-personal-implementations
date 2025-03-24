#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// Key structure to hold RSA components
typedef struct {
    BIGNUM *n;  // modulus
    BIGNUM *e;  // public exponent
    BIGNUM *d;  // private exponent
    BIGNUM *p;  // prime p
    BIGNUM *q;  // prime q
} RSAKey;

// Generate RSA keys (n, e, d, p, q)
RSAKey keyGen(int bits) {
    RSAKey key;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();

    // Generate primes p and q (each bits/2)
    key.p = BN_new();
    key.q = BN_new();
    BN_generate_prime_ex(key.p, bits/2, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(key.q, bits/2, 0, NULL, NULL, NULL);
    
    // Compute n = p * q
    key.n = BN_new();
    BN_mul(key.n, key.p, key.q, ctx);

    // Compute phi(n) = (p-1)*(q-1)
    BN_sub(p_minus_1, key.p, BN_value_one());
    BN_sub(q_minus_1, key.q, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);

    // Choose e (usually 65537 is used, but here we generate a random e < phi)
    key.e = BN_new();
    // Get a random e with bit-length slightly less than phi
    BN_rand(key.e, BN_num_bits(phi) - 1, 0, 0);
    BN_add_word(key.e, 1); // Ensure e >= 2

    // Ensure that gcd(e, phi) == 1
    BIGNUM *gcd = BN_new();
    BN_gcd(gcd, key.e, phi, ctx);
    while (!BN_is_one(gcd)) {
        BN_rand(key.e, BN_num_bits(phi) - 1, 0, 0);
        BN_add_word(key.e, 1);
        BN_gcd(gcd, key.e, phi, ctx);
    }
    BN_free(gcd);

    // Compute d = e^-1 mod phi
    key.d = BN_new();
    BN_mod_inverse(key.d, key.e, phi, ctx);

    // Cleanup
    BN_free(phi);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);
    return key;
}

// Encrypt: c = m^e mod n
BIGNUM* encrypt(BIGNUM *m, BIGNUM *n, BIGNUM *e) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *c = BN_new();
    BN_mod_exp(c, m, e, n, ctx);
    BN_CTX_free(ctx);
    return c;
}

// Decrypt: m = c^d mod n (same operation as encryption but with d)
BIGNUM* decrypt(BIGNUM *c, BIGNUM *n, BIGNUM *d) {
    return encrypt(c, n, d);
}

// Compute SHA-1 hash of string m
void sha1_hash(const char *m, unsigned char *digest) {
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, m, strlen(m));
    SHA1_Final(digest, &ctx);
}

// Full hash H(m) truncated to (modulus_bits - 4) bits
BIGNUM* fullHash(const char *m, int modulus_bits) {
    int hash_bits = modulus_bits - 4;
    int hex_chars_needed = (hash_bits + 3) / 4; // round up to hex digits
    char *hex_str = malloc(hex_chars_needed + 1);
    int idx = 0;

    // Concatenate SHA-1 hashes until we have enough hex characters
    while (idx < hex_chars_needed) {
        char m_idx[256];
        sprintf(m_idx, "%s%d", m, idx / 40); // Append an index to vary the hash input
        unsigned char digest[SHA_DIGEST_LENGTH];
        sha1_hash(m_idx, digest);

        // Convert digest to hex string (40 hex characters)
        char hex_block[41];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            sprintf(hex_block + 2 * i, "%02x", digest[i]);
        }
        hex_block[40] = '\0';

        // Append up to 40 characters from hex_block to hex_str
        int remaining = hex_chars_needed - idx;
        int copy = (remaining > 40) ? 40 : remaining;
        strncpy(hex_str + idx, hex_block, copy);
        idx += copy;
    }
    hex_str[hex_chars_needed] = '\0';

    // Convert hex string to BIGNUM
    BIGNUM *h = BN_new();
    BN_hex2bn(&h, hex_str);
    free(hex_str);
    return h;
}

// Sign message m: sigma = H(m)^d mod n
BIGNUM* sign(const char *m, BIGNUM *n, BIGNUM *d) {
    int modulus_bits = BN_num_bits(n);
    BIGNUM *h = fullHash(m, modulus_bits);
    BIGNUM *sigma = decrypt(h, n, d); // computes h^d mod n
    BN_free(h);
    return sigma;
}

// Verify signature: check if H(m) == sigma^e mod n
int verify(BIGNUM *sigma, const char *m, BIGNUM *n, BIGNUM *e) {
    int modulus_bits = BN_num_bits(n);
    BIGNUM *h_calculated = fullHash(m, modulus_bits);
    BIGNUM *h_recovered = encrypt(sigma, n, e);
    int result = BN_cmp(h_calculated, h_recovered);
    BN_free(h_calculated);
    BN_free(h_recovered);
    return (result == 0);
}

// Test encryption/decryption
void checkEnc() {
    RSAKey key = keyGen(512);
    BIGNUM *m = BN_new();
    BN_rand(m, 512, 0, 0); // generate a random message
    BN_CTX *ctx = BN_CTX_new();
    BN_mod(m, m, key.n, ctx); // ensure m < n
    BN_CTX_free(ctx);

    BIGNUM *c = encrypt(m, key.n, key.e);
    BIGNUM *m_decrypted = decrypt(c, key.n, key.d);

    if (BN_cmp(m, m_decrypted)) {
        printf("Encryption/Decryption FAILED\n");
    } else {
        printf("Encryption/Decryption OK\n");
    }

    BN_free(m);
    BN_free(c);
    BN_free(m_decrypted);
    BN_free(key.n);
    BN_free(key.e);
    BN_free(key.d);
    BN_free(key.p);
    BN_free(key.q);
}

// Test signature generation and verification
void checkSig() {
    RSAKey key = keyGen(512);
    const char *msg = "message";
    BIGNUM *sigma = sign(msg, key.n, key.d);
    int result = verify(sigma, msg, key.n, key.e);
    if (result) {
        printf("Signature verification OK\n");
    } else {
        printf("Signature verification FAILED\n");
    }

    BN_free(sigma);
    BN_free(key.n);
    BN_free(key.e);
    BN_free(key.d);
    BN_free(key.p);
    BN_free(key.q);
}

int main() {
    checkEnc();
    checkSig();
    return 0;
}
