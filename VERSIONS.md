### Compilation and Execution:

1. **Install OpenSSL** (required for BIGNUM and SHA-1):

   ```bash
   sudo apt-get install libssl-dev  # On Debian/Ubuntu
   ```
2. Compile the code:

   ```bash
   gcc rsa.c -o rsa -lcrypto
   ```
3. Run the program:

   ```bash
   ./rsa
   ```

### Key Features:

- **Key Generation**: Uses OpenSSL's `BN_generate_prime_ex` for prime generation and computes RSA components.
- **Encryption/Decryption**: Uses modular exponentiation (`BN_mod_exp`).
- **SHA-1 Hashing**: Implements concatenation and truncation as specified.
- **Signature Scheme**: Signs using the private key and verifies with the public key.

### Notes:

- **Security**: This code uses standard OpenSSL functions but is simplified. Real-world RSA requires padding (e.g., OAEP or PSS).
- **Memory Management**: Always free BIGNUMs to prevent leaks (handled in test functions).
- **Performance**: Generating large primes can be slow for large bit sizes (e.g., 4096 bits).


other version is also implementing sha256 and bignum but not finished I have some issues, im just doing this for fun will correct soon and I want to assembly optimize + constant time.
