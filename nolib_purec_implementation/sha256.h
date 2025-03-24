#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

// SHA-256 Context
typedef struct {
    uint32_t state[8];      // Current hash value
    uint8_t buffer[64];     // Input buffer
    uint64_t bit_len;       // Total message length in bits
} SHA256_CTX;

// Function prototypes
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t digest[32]);
static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[64]);

#endif // SHA256_H