#ifndef DES_H
#define DES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts data using DES in CBC mode.
 * @param blocks Pointer to the array of 64-bit data blocks (plaintext).
 * This data will be overwritten with ciphertext.
 * @param num_blocks The number of 8-byte blocks in the 'blocks' array.
 * @param key The 64-bit DES key (56 bits used + 8 parity bits).
 * @param iv The 64-bit Initialization Vector.
 */
void des_encrypt_cbc(uint64_t *blocks, int num_blocks, uint64_t key, uint64_t iv);

/**
 * @brief Decrypts data using DES in CBC mode.
 * @param blocks Pointer to the array of 64-bit data blocks (ciphertext).
 * This data will be overwritten with plaintext.
 * @param num_blocks The number of 8-byte blocks in the 'blocks' array.
 * @param key The 64-bit DES key.
 * @param iv The 64-bit Initialization Vector used during encryption.
 */
void des_decrypt_cbc(uint64_t *blocks, int num_blocks, uint64_t key, uint64_t iv);

/* --- Add declarations for other C functions if needed --- */
/* For example, if you have a separate key setting function: */
// int set_des_key(const unsigned char* key);


#ifdef __cplusplus
}
#endif

#endif // End of include guard DES_H