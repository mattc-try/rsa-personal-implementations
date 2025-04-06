#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Generate RSA key pair with 2048 bits
EVP_PKEY* generate_rsa_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Encrypt using RSA-OAEP with SHA256
unsigned char* rsa_encrypt(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len, size_t *encrypted_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, msg, msg_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char *encrypted = malloc(outlen);
    if (!encrypted || EVP_PKEY_encrypt(ctx, encrypted, &outlen, msg, msg_len) <= 0) {
        free(encrypted);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    *encrypted_len = outlen;
    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}

// Decrypt using RSA-OAEP with SHA256
unsigned char* rsa_decrypt(EVP_PKEY *pkey, const unsigned char *encrypted, size_t encrypted_len, size_t *decrypted_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted, encrypted_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char *decrypted = malloc(outlen);
    if (!decrypted || EVP_PKEY_decrypt(ctx, decrypted, &outlen, encrypted, encrypted_len) <= 0) {
        free(decrypted);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    *decrypted_len = outlen;
    EVP_PKEY_CTX_free(ctx);
    return decrypted;
}

// Sign using RSA-PSS with SHA256
unsigned char* rsa_sign(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len, size_t *sig_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx || EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(md_ctx), RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_pkey_ctx(md_ctx), -2) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    size_t sig_length;
    if (EVP_DigestSign(md_ctx, NULL, &sig_length, msg, msg_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    unsigned char *sig = malloc(sig_length);
    if (!sig || EVP_DigestSign(md_ctx, sig, &sig_length, msg, msg_len) <= 0) {
        free(sig);
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    *sig_len = sig_length;
    EVP_MD_CTX_free(md_ctx);
    return sig;
}

// Verify signature using RSA-PSS with SHA256
int rsa_verify(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx || EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(md_ctx), RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_pkey_ctx(md_ctx), -2) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    int result = EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(md_ctx);
    return result;
}

void checkEnc() {
    EVP_PKEY *pkey = generate_rsa_key();
    if (!pkey) {
        printf("Key generation failed\n");
        return;
    }

    const char *msg = "Hello, secure world!";
    size_t msg_len = strlen(msg);
    size_t encrypted_len, decrypted_len;

    unsigned char *encrypted = rsa_encrypt(pkey, (const unsigned char*)msg, msg_len, &encrypted_len);
    if (!encrypted) {
        printf("Encryption failed\n");
        EVP_PKEY_free(pkey);
        return;
    }

    unsigned char *decrypted = rsa_decrypt(pkey, encrypted, encrypted_len, &decrypted_len);
    if (!decrypted) {
        printf("Decryption failed\n");
        free(encrypted);
        EVP_PKEY_free(pkey);
        return;
    }

    if (decrypted_len == msg_len && memcmp(msg, decrypted, msg_len) == 0) {
        printf("Encryption/Decryption OK\n");
    } else {
        printf("Encryption/Decryption FAILED\n");
    }

    free(encrypted);
    free(decrypted);
    EVP_PKEY_free(pkey);
}

void checkSig() {
    EVP_PKEY *pkey = generate_rsa_key();
    if (!pkey) {
        printf("Key generation failed\n");
        return;
    }

    const char *msg = "Test message";
    size_t msg_len = strlen(msg);
    size_t sig_len;

    unsigned char *sig = rsa_sign(pkey, (const unsigned char*)msg, msg_len, &sig_len);
    if (!sig) {
        printf("Signing failed\n");
        EVP_PKEY_free(pkey);
        return;
    }

    int result = rsa_verify(pkey, (const unsigned char*)msg, msg_len, sig, sig_len);
    if (result == 1) {
        printf("Signature verification OK\n");
    } else if (result == 0) {
        printf("Signature verification FAILED\n");
    } else {
        printf("Verification error\n");
    }

    free(sig);
    EVP_PKEY_free(pkey);
}

int main() {
    checkEnc();
    checkSig();
    return 0;
}