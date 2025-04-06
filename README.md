Here’s the rewritten markdown with the updated security details, compilation instructions, and your playful note about the "speed-optimized" executable:

---

# Secure RSA Implementation (SHA-256 + RSA-PSS/OAEP)

**Now with actual security!** 🔒

### Compilation & Execution (macOS with Homebrew OpenSSL@3):

```bash
gcc -o rsa openssl_bignumsha.c -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
```

**Run it (at your own risk 😈):**

```bash
./rsa
```

*Note: The executable is left unbundled for "speed"… but who knows what lurks in the shadows of optimization?*

---

### Key Security Upgrades (vs. Original):

| Feature                      | Original (Insecure)             | New (Secure)                                     |
| ---------------------------- | ------------------------------- | ------------------------------------------------ |
| **Hashing**            | SHA-1 (truncated)               | SHA-256                                          |
| **Encryption Padding** | Textbook RSA (`m^e mod n`)    | RSA-OAEP (Optimal Asymmetric Encryption Padding) |
| **Signature Padding**  | Textbook RSA (`H(m)^d mod n`) | RSA-PSS (Probabilistic Signature Scheme)         |
| **Key Size**           | 512-bit (weak)                  | 2048-bit (recommended)                           |

---

### Key Features:

1. **Key Generation**:

   - Uses OpenSSL’s `EVP_PKEY` API for secure RSA keypair generation (2048-bit).
   - Replaces manual prime generation with OpenSSL’s hardened `BN_generate_prime_ex`.
2. **Encryption/Decryption**:

   - **RSA-OAEP** with SHA-256 (via `EVP_PKEY_CTX_set_rsa_padding`).
   - Mitigates chosen-ciphertext attacks (unlike textbook RSA).
3. **Signatures**:

   - **RSA-PSS** with SHA-256 (via `EVP_PKEY_CTX_set_rsa_pss_saltlen`).
   - Probabilistic padding defeats signature forgery.
4. **Memory Safety**:

   - Uses OpenSSL’s `EVP_MD_CTX` and `EVP_PKEY_CTX` to automate cleanup.

🚨 Warning: I did not talk about anything related to timing and or implement anything for it this is probably side channel vulnerable, this could be done with openssl flags and at compilation, once this is done I guess the implementation would be secure given that the opensource openssl is secure but that would be a bigger problem (might still be pesky hfbs in there who knows but it's very unlikely).

---

### Notes/Warnings:

- **🚨 Don’t use the original code** for anything real—it’s vulnerable to:
  - Signature forgery (no padding).
  - Chosen-ciphertext attacks (textbook RSA).
  - SHA-1 collisions.
- **Assembly Optimization**: If you’re diving into constant-time ASM, check OpenSSL’s `bn_asm.c` for inspiration.
- **Future Work**:
  ```c
  // TODO: Add constant-time BN_mod_exp, 
  //       ChaCha20-Poly1305 hybrid encryption,
  //       and a sprinkle of paranoia.
  ```

---

### Why This Matters:

The original code was a **fun educational example** but would fail catastrophically in production. This version:

- Uses modern padding (OAEP/PSS).
- Upgrades SHA-1 → SHA-256.
- Forces 2048-bit keys.
- Still retains the low-level `BIGNUM` vibe (but securely).

**Happy hacking!** (And maybe audit that "speed-optimized" binary...) 🚀

---

### Need the Old Version?

If you want the *insecure-but-educational* original (with SHA-1 and textbook RSA), in the python juptyer notebook code and previous commit, eww shame! Otherwise, stick with this one, after making it constant time and faster through assembly might do laterr.
