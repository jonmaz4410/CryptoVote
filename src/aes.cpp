/*
==========================================================================
AES-256 CBC Zero Padding
==========================================================================

--------------------------------------------------------------------------
I. Key Expansion (expandKey Function)
--------------------------------------------------------------------------
Goal: Generate 15 round keys (128-bit each) from the original 256-bit key.

1.  Input: 256-bit (32-byte) original key.
2.  Initialize: Create an array `w` to hold 60 words (4-byte chunks).
3.  Seed: Copy the original 32-byte key into the first 8 words of `w` (w[0] to w[7]).
4.  Generate Remaining Words (w[8] to w[59]):
    a. Loop from i = 8 to 59.
    b. Get previous word: `temp = w[i-1]`.
    c. If `i` is a multiple of 8:
        - Apply `RotWord` (cyclic byte shift left) to `temp`.
        - Apply `SubWord` (S-Box substitution) to each byte of `temp`.
        - XOR the first byte of `temp` with `RCON[i/8]` (round constant).
    d. Else if `i % 8 == 4`
        - Apply `SubWord` (S-Box substitution) to each byte of `temp`.
    e. Calculate new word: `w[i] = w[i-8] ^ temp`.
5.  Group the 60 words from `w` into 15 `Block`s (16 bytes each).
6.  Output: Vector containing the 15 round keys.

--------------------------------------------------------------------------
II. AES-256 CBC Encryption (encryptAES256 Function)
--------------------------------------------------------------------------
Goal: Encrypt plaintext using the key and CBC mode.

1.  Input: Plaintext string, 256-bit key.
2.  Key Expansion: Generate the 15 round keys using `expandKey`.
3.  IV Generation: Create a random 16-byte IV.
4.  Padding: Pad the plaintext with trailing zeros so its length is a multiple of 16 bytes.
5.  Initialize Ciphertext: Start the output ciphertext with the IV.
6.  Chaining: `previousBlock = IV`.
7.  Process Blocks: For each 16-byte block of the padded plaintext:
    a. Copy plaintext block to `currentBlock`.
    b. XOR: `currentBlock = currentBlock ^ previousBlock`.
    c. AES Block Encryption:
        - `AddRoundKey` (round 0 key).
        -  Loop rounds 1 to 13:
           - `SubBytes` (S-Box).
           - `ShiftRows`.
           - `MixColumns`.
           - `AddRoundKey` (key for current round).
        - Final Round (round 14):
           - `SubBytes`.
           - `ShiftRows`.
           - `AddRoundKey` (key for round 14).
    d. Append encrypted `currentBlock` to the output ciphertext.
    e. Update Chaining: `previousBlock = currentBlock`.
8.  Output: Ciphertext vector (IV + encrypted blocks).

--------------------------------------------------------------------------
III. AES-256 CBC Decryption (decryptAES256 Function)
--------------------------------------------------------------------------
Goal: Decrypt ciphertext (encrypted using this scheme) to get the original plaintext.

1.  Input: Ciphertext vector, 256-bit key.
2.  Key Expansion: Generate the 15 round keys using `expandKey`.
3.  Extract IV: Get the first 16 bytes from the input ciphertext as the IV.
4.  Chaining: `previousBlock = IV`.
5.  Initialize Plaintext: Create an empty buffer for the decrypted plaintext.
6.  Process Blocks: For each 16-byte block of the ciphertext after the IV:
    a. Copy ciphertext block to `currentBlock`.
    b. Store Original Ciphertext Block: `originalCipherBlock = currentBlock`.
    c. AES Block Decryption (on `currentBlock`):
        - `AddRoundKey` (round 14 key).
        -  `InvShiftRows`.
        -  `InvSubBytes` (Inverse S-Box).
        -  Loop rounds 13 down to 1:
           - `AddRoundKey` (key for current round).
           - `InvMixColumns`.
           - `InvShiftRows`.
           - `InvSubBytes`.
        -  `AddRoundKey` (round 0 key).
    d. XOR: `currentBlock = currentBlock ^ previousBlock`.
    e. Append decrypted `currentBlock` to the plaintext buffer.
    f. Update Chaining: `previousBlock = originalCipherBlock`.
7.  Remove Padding: Remove any trailing zero bytes from the end of the resulting plaintext buffer.
8.  Output: Original plaintext string.

*/
#include "aes.h"
#include <array>
#include <iostream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;
using Byte = unsigned char;
using Block = array<Byte, 16>;

const size_t BLOCK_SIZE = 16;
const size_t KEY_SIZE = 32;
const int ROUNDS = 14;

// S-Boxes and Rcon table
const array<Byte, 256> SBOX = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const array<Byte, 256> INV_SBOX = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

const array<Byte, 11> RCON = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// xtime calculates x * 2 in GF(2^8)
inline Byte xtime(Byte x) {
    Byte result = x << 1;
    bool MSB = (x & 0x80) != 0;

    // If the high bit was set, we need to XOR with 0x1B
    // XOR performs reduction using properties of special polynomials in GF(2^8)
    // This is equivalent to reducing modulo x^8 + x^4 + x^3 + x + 1
    if (MSB) {
        result = result ^ 0x1B;
    }
    return result;
}

// gmul calculates the product of two bytes in GF(2^8)
inline Byte gmul(Byte a, Byte b) {
    Byte p = 0;

    // Loop 8 times, once for each bit position in 'b'.
    for (int i = 0; i < 8; i++) {

        if (b & 1) {
            // XOR == addition in GF(2^8)
            p ^= a;
        }

        // Now, update 'a' to be 'a * 2' using the xtime logic.
        // This is needed for the next potential addition.
        Byte MSB = (a & 0x80); // Check for overflow (high bit set)
        a <<= 1;
        
        if (MSB) {
            a ^= 0x1B;
        }
        // Shift 'b' right to process the next bit.
        b >>= 1;
    }
    return p;
}

// Key expansion for AES-256
vector<Block> expandKey(const array<Byte, KEY_SIZE>& key) {
    vector<array<Byte, 4>> w(4 * (ROUNDS + 1));
    
    // Copy the key into the first 8 words
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            w[i][j] = key[4*i+j];
        }
    }
    
    // Generate the expanded key
    for (int i = 8; i < 4 * (ROUNDS + 1); i++) {
        array<Byte, 4> temp = w[i-1];
        
        if (i % 8 == 0) {
            // RotWord
            Byte t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            for (int j = 0; j < 4; j++) {
                temp[j] = SBOX[temp[j]];
            }
            
            temp[0] ^= RCON[i/8];
        }
        else if (i % 8 == 4) {
            // SubWord for AES-256
            for (int j = 0; j < 4; j++) {
                temp[j] = SBOX[temp[j]];
            }
        }
        
        for (int j = 0; j < 4; j++) {
            w[i][j] = w[i-8][j] ^ temp[j];
        }
    }
    
    // Arrange words into round keys
    vector<Block> roundKeys(ROUNDS + 1);
    for (int r = 0; r <= ROUNDS; r++) {
        for (int c = 0; c < 4; c++) {
            for (int j = 0; j < 4; j++) {
                roundKeys[r][4*c+j] = w[r*4+c][j];
            }
        }
    }
    
    return roundKeys;
}

void addRoundKey(Block& state, const Block& roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

void subBytes(Block& state) {
    for (Byte& b : state) {
        b = SBOX[b];
    }
}

void invSubBytes(Block& state) {
    for (Byte& b : state) {
        b = INV_SBOX[b];
    }
}

void shiftRows(Block& state) {
    Byte temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

void invShiftRows(Block& state) {
    Byte temp;
    
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

void mixColumns(Block& state) {
    Block temp = state;
    
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        Byte s0 = temp[i], s1 = temp[i+1], s2 = temp[i+2], s3 = temp[i+3];
        Byte t0 = xtime(s0), t1 = xtime(s1), t2 = xtime(s2), t3 = xtime(s3);
        
        state[i] = t0 ^ t1 ^ s1 ^ s2 ^ s3;
        state[i+1] = s0 ^ t1 ^ t2 ^ s2 ^ s3;
        state[i+2] = s0 ^ s1 ^ t2 ^ t3 ^ s3;
        state[i+3] = t0 ^ s0 ^ s1 ^ s2 ^ t3;
    }
}

void invMixColumns(Block& state) {
    Block temp = state;
    
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        Byte s0 = temp[i], s1 = temp[i+1], s2 = temp[i+2], s3 = temp[i+3];
        
        state[i] = gmul(s0, 0x0E) ^ gmul(s1, 0x0B) ^ gmul(s2, 0x0D) ^ gmul(s3, 0x09);
        state[i+1] = gmul(s0, 0x09) ^ gmul(s1, 0x0E) ^ gmul(s2, 0x0B) ^ gmul(s3, 0x0D);
        state[i+2] = gmul(s0, 0x0D) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0E) ^ gmul(s3, 0x0B);
        state[i+3] = gmul(s0, 0x0B) ^ gmul(s1, 0x0D) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0E);
    }
}

// Core block cipher
void encryptBlock(Block& block, const vector<Block>& roundKeys) {
    addRoundKey(block, roundKeys[0]);
    
    for (int round = 1; round < ROUNDS; round++) {
        subBytes(block);
        shiftRows(block);
        mixColumns(block);
        addRoundKey(block, roundKeys[round]);
    }
    
    subBytes(block);
    shiftRows(block);
    addRoundKey(block, roundKeys[ROUNDS]);
}

void decryptBlock(Block& block, const vector<Block>& roundKeys) {
    addRoundKey(block, roundKeys[ROUNDS]);
    invShiftRows(block);
    invSubBytes(block);
    
    for (int round = ROUNDS - 1; round > 0; round--) {
        addRoundKey(block, roundKeys[round]);
        invMixColumns(block);
        invShiftRows(block);
        invSubBytes(block);
    }
    
    addRoundKey(block, roundKeys[0]);
}

// Utility functions
Block generateRandomIV() {
    Block iv;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, 255);
    
    for (Byte& b : iv) {
        b = static_cast<Byte>(dist(gen));
    }
    
    return iv;
}

void xorBlocks(Block& target, const Block& source) {
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        target[i] ^= source[i];
    }
}

array<Byte, KEY_SIZE> hexStringToKey(const string& hexKey) {
    if (hexKey.length() != KEY_SIZE * 2) {
        throw invalid_argument("Hex key must be exactly 64 characters long");
    }
    
    array<Byte, KEY_SIZE> key;
    for (size_t i = 0; i < KEY_SIZE; i++) {
        string byteStr = hexKey.substr(i * 2, 2);
        key[i] = static_cast<Byte>(stoi(byteStr, nullptr, 16));
    }
    
    return key;
}

string bytesToHexString(const vector<Byte>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    
    for (Byte b : bytes) {
        ss << setw(2) << static_cast<int>(b);
    }
    
    return ss.str();
}

// Zero padding functions
vector<Byte> padData(const string& data) {
    vector<Byte> padded(data.begin(), data.end());
    size_t paddingSize = (BLOCK_SIZE - (padded.size() % BLOCK_SIZE)) % BLOCK_SIZE;
    padded.resize(padded.size() + paddingSize, 0);
    return padded;
}

void removePadding(vector<Byte>& data) {
    while (!data.empty() && data.back() == 0) {
        data.pop_back();
    }
}

vector<Byte> encryptAES256(const string& plaintext, const array<Byte, KEY_SIZE>& key) {
    auto roundKeys = expandKey(key);
    Block iv = generateRandomIV();
    vector<Byte> paddedText = padData(plaintext);
    vector<Byte> ciphertext(iv.begin(), iv.end());
    ciphertext.reserve(iv.size() + paddedText.size());
    Block previousBlock = iv;
    
    for (size_t i = 0; i < paddedText.size(); i += BLOCK_SIZE) {
        Block currentBlock;
        copy(paddedText.begin() + i, paddedText.begin() + i + BLOCK_SIZE, currentBlock.begin());
        
        // XOR with previous ciphertext block (or IV for first block)
        xorBlocks(currentBlock, previousBlock);
        
        // Encrypt the block
        encryptBlock(currentBlock, roundKeys);
        
        // Add to ciphertext and update previous block
        ciphertext.insert(ciphertext.end(), currentBlock.begin(), currentBlock.end());
        previousBlock = currentBlock;
    }
    
    return ciphertext;
}

string decryptAES256(const vector<Byte>& ciphertext, const array<Byte, KEY_SIZE>& key) {
    if (ciphertext.size() < BLOCK_SIZE || (ciphertext.size() - BLOCK_SIZE) % BLOCK_SIZE != 0) {
        throw invalid_argument("Invalid ciphertext size");
    }
    
    vector<Block> roundKeys = expandKey(key);
    
    // Extract IV (first block)
    Block iv;
    copy(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE, iv.begin());
    
    vector<Byte> plaintext;
    plaintext.reserve(ciphertext.size() - BLOCK_SIZE);
    
    Block previousBlock = iv;
    
    // Process each block
    for (size_t i = BLOCK_SIZE; i < ciphertext.size(); i += BLOCK_SIZE) {
        Block currentBlock;
        copy(ciphertext.begin() + i, ciphertext.begin() + i + BLOCK_SIZE, currentBlock.begin());
        
        Block temp = currentBlock;
        decryptBlock(temp, roundKeys);
        xorBlocks(temp, previousBlock);
        
        plaintext.insert(plaintext.end(), temp.begin(), temp.end());
        previousBlock = currentBlock;
    }
    
    // Remove padding
    removePadding(plaintext);
    
    return string(plaintext.begin(), plaintext.end());
}

void printBlock(const Block& block, const string& label = "Block") {
    cout << label << ":" << endl;
    for (int r = 0; r < 4; r++) {
        cout << "  ";
        for (int c = 0; c < 4; c++) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(block[c * 4 + r]) << " ";
        }
        cout << endl;
    }
    cout << dec;
}