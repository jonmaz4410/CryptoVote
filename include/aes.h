#ifndef AES_H
#define AES_H

#include <vector>
#include <string>
#include <array>
#include <stdexcept> // For potential exceptions

/**
 * @brief Encrypts plaintext using AES-256 CBC with zero padding.
 * @param plaintext The string data to encrypt.
 * @param key The 32-byte (256-bit) AES key.
 * @return A vector of bytes containing the IV prepended to the ciphertext.
 * @throws std::invalid_argument if the key generation or encryption fails.
 */
std::vector<unsigned char> encryptAES256(const std::string& plaintext, const std::array<unsigned char, 32>& key);

/**
 * @brief Decrypts ciphertext using AES-256 CBC with zero padding.
 * @param ciphertext A vector of bytes containing the IV prepended to the ciphertext.
 * @param key The 32-byte (256-bit) AES key used for encryption.
 * @return The original plaintext string.
 * @throws std::invalid_argument if the ciphertext is invalid or decryption fails.
 */
std::string decryptAES256(const std::vector<unsigned char>& ciphertext, const std::array<unsigned char, 32>& key);

#endif // AES_H