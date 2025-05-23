#ifndef AES_H
#define AES_H

#include <vector>
#include <string>
#include <array>
#include <stdexcept>

using namespace std;
using Byte = unsigned char;

/**
 * @brief Encrypts plaintext using AES-256 CBC with zero padding.
 * @param plaintext The string data to encrypt.
 * @param key The 32-byte (256-bit) AES key.
 * @return A vector of bytes containing the IV prepended to the ciphertext.
 * @throws std::invalid_argument if the key generation or encryption fails.
 */
vector<Byte> encryptAES256(const string& plaintext, const array<Byte, 32>& key);

/**
 * @brief Decrypts ciphertext using AES-256 CBC with zero padding.
 * @param ciphertext A vector of bytes containing the IV prepended to the ciphertext.
 * @param key The 32-byte (256-bit) AES key used for encryption.
 * @return The original plaintext string.
 * @throws std::invalid_argument if the ciphertext is invalid or decryption fails.
 */
string decryptAES256(const vector<Byte>& ciphertext, const array<Byte, 32>& key);

#endif // AES_H