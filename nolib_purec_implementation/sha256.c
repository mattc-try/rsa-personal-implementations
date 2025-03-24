#include "sha256.h"
#include <string.h>

// Constants ========================================================
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Helper Macros ====================================================
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// Core Functions ===================================================
void sha256_init(SHA256_CTX *ctx) {
    memcpy(ctx->state, H0, sizeof(H0));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->bit_len = 0;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t buffer_idx = (size_t)((ctx->bit_len >> 3) % 64);
    ctx->bit_len += len << 3;

    // Process existing buffer
    if (buffer_idx > 0) {
        size_t copy_len = 64 - buffer_idx;
        if (copy_len > len) copy_len = len;
        memcpy(ctx->buffer + buffer_idx, data, copy_len);
        if (buffer_idx + copy_len < 64) return;
        sha256_transform(ctx, ctx->buffer);
        data += copy_len;
        len -= copy_len;
    }

    // Process full blocks
    while (len >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    // Copy remaining data to buffer
    if (len > 0) memcpy(ctx->buffer, data, len);
}

void sha256_final(SHA256_CTX *ctx, uint8_t digest[32]) {
    size_t buffer_idx = (size_t)((ctx->bit_len >> 3) % 64);
    ctx->buffer[buffer_idx++] = 0x80; // Append '1' bit

    // Pad with zeros if not enough space for length
    if (buffer_idx > 56) {
        memset(ctx->buffer + buffer_idx, 0, 64 - buffer_idx);
        sha256_transform(ctx, ctx->buffer);
        buffer_idx = 0;
    }

    memset(ctx->buffer + buffer_idx, 0, 56 - buffer_idx);
    // Append message length in bits (big-endian)
    uint64_t bit_len = ctx->bit_len;
    for (int i = 0; i < 8; ++i) {
        ctx->buffer[63 - i] = (uint8_t)(bit_len >> (i * 8));
    }
    sha256_transform(ctx, ctx->buffer);

    // Copy final state to digest (big-endian)
    for (int i = 0; i < 8; ++i) {
        uint32_t val = ctx->state[i];
        digest[i * 4 + 0] = (uint8_t)(val >> 24);
        digest[i * 4 + 1] = (uint8_t)(val >> 16);
        digest[i * 4 + 2] = (uint8_t)(val >> 8);
        digest[i * 4 + 3] = (uint8_t)(val);
    }
}

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;

    // Convert bytes to 32-bit words (big-endian)
    for (int i = 0, j = 0; i < 16; ++i, j += 4)
        W[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | (uint32_t)data[j + 3];

    // Extend message schedule
    for (int i = 16; i < 64; ++i)
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

    // Initialize working variables
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    // Compression loop
    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    // Update state
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}