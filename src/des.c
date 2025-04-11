#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "des.h"

///////////////      CONSTANTS      ///////////////

#define BLOCK_SIZE 8
#define IV 0xA5A5A5A5A5A5A5A5 // Initialization Vector -- can be changed to random in the future for more security


// Initial Permutation LUT
int IP[64] = { 
    58, 50, 42, 34, 26, 18, 10, 2, 
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 
    63, 55, 47, 39, 31, 23, 15, 7 
};

// Final Permutation LUT
int FP[64] = { 
    40, 8, 48, 16, 56, 24, 64, 32, 
    39, 7, 47, 15, 55, 23, 63, 31, 
    38, 6, 46, 14, 54, 22, 62, 30, 
    37, 5, 45, 13, 53, 21, 61, 29, 
    36, 4, 44, 12, 52, 20, 60, 28, 
    35, 3, 43, 11, 51, 19, 59, 27, 
    34, 2, 42, 10, 50, 18, 58, 26, 
    33, 1, 41, 9, 49, 17, 57, 25 
};

// Permuted Choice 1 LUT
int PC1[56] = { 
    57, 49, 41, 33, 25, 17,  9,  1,
    58, 50, 42, 34, 26, 18, 10,  2,
    59, 51, 43, 35, 27, 19, 11,  3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15,  7, 62, 54, 46, 38,
    30, 22, 14,  6, 61, 53, 45, 37,
    29, 21, 13,  5, 28, 20, 12,  4
};

// Permuted Choice 2 LUT
int PC2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28,  
    15,  6, 21, 10, 23, 19, 12,  4,  
    26,  8, 16,  7, 27, 20, 13,  2,  
    41, 52, 31, 37, 47, 55, 30, 40,  
    51, 45, 33, 48, 44, 49, 39, 56,  
    34, 53, 46, 42, 50, 36, 29, 32  
};

// Expansion LUT
int E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// S-Boxes LUT (8 separate 4x16 tables)
int S_BOXES[8][4][16] = {
    {   // S-Box 1
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    {   // S-Box 2
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    {   // S-Box 3
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    {   // S-Box 4
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    {   // S-Box 5
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    {   // S-Box 6
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    {   // S-Box 7
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    {   // S-Box 8
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};

// Permutation Box LUT
int P_BOX[32] = {
    16,  7, 20, 21, 29, 12, 28, 17, 
     1, 15, 23, 26,  5, 18, 31, 10, 
     2,  8, 24, 14, 32, 27,  3,  9, 
    19, 13, 30,  6, 22, 11,  4, 25
};



///////////////      MAIN FUNCTION PROTOTYPES      ///////////////

void initial_permutation(uint64_t *block);

void final_permutation(uint64_t *block);

uint32_t f_function(uint32_t right_half, uint64_t round_key);

void key_gen(uint64_t key, uint64_t round_keys[16]);

void des_encrypt(uint64_t *block, uint64_t key);

void des_decrypt(uint64_t *block, uint64_t key);

// void des_encrypt_cbc(uint64_t *blocks, int num_blocks, uint64_t key, uint64_t iv);

// void des_decrypt_cbc(uint64_t *blocks, int num_blocks, uint64_t key, uint64_t iv);



///////////////      HELPER FUNCTION PROTOTYPES      ///////////////

uint64_t pc1(uint64_t key);

uint64_t pc2(uint64_t key);

void split_block(uint64_t block, uint32_t *left, uint32_t *right);

void split_key(uint64_t key, uint32_t *left, uint32_t *right);

uint32_t left_circular_shift(uint32_t key_halve, int round);

uint64_t combine_halves(uint32_t left, uint32_t right, int total_bits);

uint64_t expansion(uint32_t right_half);

uint32_t s_box(uint64_t value);

uint32_t p_box(uint32_t value);

///////////////      MAIN FUNCTION      ///////////////

// int main() {
//     char plaintext[1024]; // Buffer for plaintext
//     uint64_t key; // 64-bit key

//     printf("Enter plaintext: (max size 1024) ");
//     fgets(plaintext, sizeof(plaintext), stdin); // fgets is more secure than scanf, but adds in a \n character
//     plaintext[strcspn(plaintext, "\n")] = 0;  // Remove newline that was added from fgets

//     printf("Enter 64-bit key in hexadecimal (omit 0x): ");
//     scanf("%llX", &key); // Read in key as 64-bit hexadecimal

//     int num_blocks = (strlen(plaintext) + BLOCK_SIZE - 1) / BLOCK_SIZE; // Ensure number of blocks rounds up so there are enough to store plaintext
//     uint64_t blocks[num_blocks]; 

//     memset(blocks, 0, sizeof(blocks));  // Fills entire buffer with 0x00 (basic padding)
//     memcpy(blocks, plaintext, strlen(plaintext));  // Copies plaintext into buffer

//     printf("\nOriginal Plaintext (Hex):\n");
//     for (int i = 0; i < num_blocks; i++) {
//         printf("%016llX\n", blocks[i]); // %016llX prints 64-bit hexadecimal (0 padded, 16 minimum field width, 64 bit, hexadecimal)
//     }

//     des_encrypt_cbc(blocks, num_blocks, key, IV); // Calls des_encrypt on each block and uses CBC mode of operation

//     printf("\nEncrypted Ciphertext (Hex):\n");
//     for (int i = 0; i < num_blocks; i++) {
//         printf("%016llX\n", blocks[i]);
//     }

//     des_decrypt_cbc(blocks, num_blocks, key, IV); // Decrypts according to CBC mode of operation

//     printf("\nDecrypted Plaintext (Hex):\n");
//     for (int i = 0; i < num_blocks; i++) {
//         printf("%016llX\n", blocks[i]);
//     }

//     return 0;
// }
///////////////      FUNCTION DECLARATIONS      ///////////////

///////////////      IP(X) FUNCTION     ///////////////
// Applies the Initial Permutation (IP).
// Input: 64-bit block plaintext
// Output: 64-bit block with permuted bits

// Notes: Find each bit in the block and move it to the new position. This is done by shifting the plaintext to the right position 
// and then masking it with 1 to get the bit value. The bit value is then shifted to the left and ORed with the output.
// This information is public knowledge and can be found in the DES standard.

// Example: original bit positions numbered 1-64. Bit 1 is mapped to bit 58 (found in IP array). In DES, the bit locations are given 1-64 
// (left to right), but in C, bits are stored 63-0 (left to right). Shift right by (64 - i) and mask. This will give us the value of bit 58.
// Then, shift to the left 63 - i to store in the correct location in the new array (filled left to right). When reading from an LUT, this same
// format is repeated in many other functions 

void initial_permutation(uint64_t *block) {
    uint64_t output = 0;

    for (int i = 0; i < 64; i++) {
        output |= ((*block >> (64 - IP[i])) & 1) << (63 - i);
    }

    *block = output;
}

///////////////      FP(X) FUNCTION     ///////////////
// Applies the Final Permutation (FP)
// Input: 64-bit block after 16 rounds of DES
// Output: Ciphertext
// Notes: Undoes the Initial Permutation. See initial_permuation function for explanation.
// The logic is the same except for the use of a different table to handle the mappings.

void final_permutation(uint64_t *block) {
    uint64_t output = 0;

    for (int i = 0; i < 64; i++) {
        output |= ((*block >> (64 - FP[i])) & 1) << (63 - i);
    }

    *block = output;
}

///////////////      PERMUTED CHOICE 1     ///////////////
// Input: 64-bit key
// Output: 56-bit key
// Notes: Permuted Choice 1 (PC1) is used for generating round keys. The 64-bit key is permuted to 56-bits.
// The 8th bit is dropped (8, 16, 24 ... 64). According to DES standard, bits are also rearranged in the process.

uint64_t pc1(uint64_t key){
    uint64_t output = 0;

    for (int i = 0; i < 56; i++) {
        output |= ((key >> (64 - PC1[i])) & 1) << (55 - i);
    }

    return output;
}

///////////////      PERMUTED CHOICE 2    ///////////////
// Input: 56-bit key
// Output: 48-bit key
// Notes: Same as PC1, but with a different table and output size. The 56-bit key is permuted to 48-bits.

uint64_t pc2(uint64_t key){
    uint64_t output = 0;

    for (int i = 0; i < 48; i++) {
        output |= ((key >> (56 - PC2[i])) & 1) << (47 - i);
    }

    return output;
}


///////////////      SPLIT BLOCK   ///////////////
// Input: 64-bit block
// Output: none
// Notes: splits 64-bit block into two halves.
void split_block(uint64_t block, uint32_t *left, uint32_t *right){
    *left = block >> 32;
    *right = block & 0xFFFFFFFF;
}

///////////////      SPLIT KEY   ///////////////
// Input: 56-bit key
// Output: none
// Notes: splits 56-bit key into two halves. This is required for the left_circular_shift function.
void split_key(uint64_t key, uint32_t *left, uint32_t *right){
    *left = key >> 28;
    *right = key & 0xFFFFFFF;
}

///////////////      COMBINE HALVES  ///////////////
// Input: two 32-bit halves, total number of bits
// Output: 64-bit combined block
// Notes: total_bits allows this function to be used to combine any two halves of a block, not just 32-bit halves.
uint64_t combine_halves(uint32_t left, uint32_t right, int total_bits) {
    uint64_t combined = 0;
    combined = left << (total_bits / 2) | right;
    return combined;
}

///////////////      LEFT CIRCULAR SHIFT   ///////////////
// Input: 32-bit key halve, round number
// Output: 32-bit key halve
// Notes: Shifts the key halve left by 1 or 2 bits depending on the round number.
// Rounds are zero-indexed to simplify the logic (there are 16 rounds total).
// The bits from shifting left are not lost but are wrapped around to the right side.
uint32_t left_circular_shift(uint32_t key_halve, int round){
    int shift = 1;
    if (round == 0 || round == 1 || round == 8 || round == 15){
        shift = 1;
    }
    else{
        shift = 2;
    }

    return (key_halve << shift) | (key_halve >> (28 - shift));
}

///////////////      EXPANSION   ///////////////
// Input: 32-bit right half of block
// Output: 48-bit expanded block
// Notes: Specific values in the table are repeated according to DES standard to go from 32-bits to 48-bits.
uint64_t expansion(uint32_t right_half){
    uint64_t output = 0;

    for (int i = 0; i < 48; i++) {
        output |= ((right_half >> (32 - E[i])) & 1) << (47 - i);
    }

    return output;
}

///////////////      KEY GENERATION     ///////////////
// Input: 64-bit key, 16 48-bit round keys (pointer since it is an array)
// Output: none
// Notes: Uses pc1, pc2, split_key, left_circular_shift, and combine_halves functions to generate 16 round keys.
// For each round, the previous left and right is used as input to subsequent rounds, allowing the shift to persist from round to round.
void key_gen(uint64_t key, uint64_t round_keys[16]) {
    uint64_t permuted_key = pc1(key);
    uint32_t left, right;
    split_key(permuted_key, &left, &right);

    for (int i = 0; i < 16; i++) {
        left = left_circular_shift(left, i);
        right = left_circular_shift(right, i);

        uint64_t combined = combine_halves(left, right, 56); // 56 is hard-coded since we know the size of the key
        round_keys[i] = pc2(combined);
    }
}

///////////////      F FUNCTION      ///////////////
// Input: 32-bit right half of block, 48-bit round key
// Output: 32-bit to be XORed with left half
// Notes: Expansion, S-Box, and P-Box functions are used to generate the output.
// The right half is expanded to 48-bits, XORed with the round key, and then passed through the S-Boxes.
// For each round, the previous left and right is used as input to subsequent rounds, allowing the shift to persist from round to round.
uint32_t f_function(uint32_t right_half, uint64_t round_key) {
    uint64_t expanded = expansion(right_half);
    uint64_t xor_output = expanded ^ round_key;
    uint32_t sbox_output = s_box(xor_output);
    uint32_t pbox_output = p_box(sbox_output);

    return pbox_output;
}

///////////////      S BOX      ///////////////
// Input: 48-bit value
// Output: 32-bit value
// Notes: Splits the 48-bit value into 8 6-bit values, each of which is sent to the corresponding S-Box, which is stored as a 3D array.
// The row comes from the first and last bit and the column comes from the middle 4 bits. These are used to index the S-Box and get the 4-bit output.
// The output is stored 4 bits at a time by shifting to the right 28 bits, using i as an index to designate proper location.
uint32_t s_box(uint64_t value) {
    uint32_t output = 0;

    for (int i = 0; i < 8; i++) {  
        uint8_t six_bits = (value >> (42 - (i * 6))) & 0x3F;  // Extract 6 bits

        int row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);  // Row (first and last bit)
        int col = (six_bits >> 1) & 0x0F;  // Column (middle 4 bits)

        uint8_t sbox_value = S_BOXES[i][row][col];  // Get the 4-bit result
        output |= sbox_value << (28 - (i * 4));  // Store in final 32-bit output
    }

    return output;
}

///////////////      P BOX      ///////////////
// Input: 32-bit value
// Output: 32-bit value
// Notes: Rearranges the bits in the 32-bit value according to the P-Box LUT.
// The value is shifted to the right by 32 - P_BOX[i] to get the bit value, which is then shifted to the left by 31 - i to store in the correct location.
uint32_t p_box(uint32_t value){
    uint32_t output = 0;

    for (int i = 0; i < 32; i++) {
        output |= ((value >> (32 - P_BOX[i])) & 1) << (31 - i);
    }

    return output;
}

///////////////     DES ENCRYPTION      ///////////////
// Input: 64-bit block plaintext (pointer), 64-bit key
// Output: 64-bit block ciphertext (in memory)
// Notes: Declare an array to store the 16 round keys. Call the key_gen function to generate the round keys.
// Perform initial permutation and then split the block into two halves. Perform 16 rounds of DES encryption.
// XOR the left half with the output of the f_function. Swap the left and right halves and perform final permutation.
void des_encrypt(uint64_t *block, uint64_t key) {
    uint64_t round_keys[16];  // Stores generated round keys
    uint32_t left, right;
    key_gen(key, round_keys);

    initial_permutation(block);

    split_block(*block, &left, &right);

    for (int i = 0; i < 16; i++) {
        uint32_t temp = right;
        right = left ^ f_function(right, round_keys[i]);
        left = temp;
    }

    *block = ((uint64_t)right << 32) | left;

    final_permutation(block);
}

///////////////     DES DECRYPTION      ///////////////
// Input: 64-bit block ciphertext (pointer), 64-bit key
// Output: 64-bit block plaintext
// Notes: For decryption, everything is the same as encryption except the round keys are used in reverse order.
// Final permutation is the inverse of the initial permutation.
void des_decrypt(uint64_t *block, uint64_t key) {
    uint64_t round_keys[16];
    key_gen(key, round_keys);

    initial_permutation(block);

    uint32_t left = (*block) >> 32;
    uint32_t right = (*block) & 0xFFFFFFFF;

    for (int i = 15; i >= 0; i--) {  // Reverse round keys for decryption
        uint32_t temp = right;
        right = left ^ f_function(right, round_keys[i]);
        left = temp;
    }

    *block = ((uint64_t)right << 32) | left;

    final_permutation(block);
}


///////////////     DES ENCRYPTION CBC      ///////////////
// Input: 64-bit block plaintext (pointer), number of blocks, 64-bit key, 64-bit IV
// Output: 64-bit block ciphertext (in memory) with CBC mode of operation
// Notes: CBC mode of operation uses the previous ciphertext as the IV for the next block.
// The IV is XORed with the plaintext before encryption and the ciphertext is stored as the IV for the next block.
void des_encrypt_cbc(uint64_t *blocks, int num_blocks, uint64_t key, uint64_t iv) {
    uint64_t previous_cipher = iv;  // Start with IV

    for (int i = 0; i < num_blocks; i++) {
        blocks[i] ^= previous_cipher;  // XOR with previous ciphertext (or IV)
        des_encrypt(&blocks[i], key);  // Encrypt with DES
        previous_cipher = blocks[i];   // Update previous ciphertext
    }
}


///////////////     DES DECRYPTION CBC      ///////////////
// Input: 64-bit block ciphertext (pointer), number of blocks, 64-bit key, 64-bit IV
// Output: 64-bit block plaintext with CBC mode of operation
// Notes: CBC mode of operation uses the previous ciphertext as the IV for the next block.
// The IV is XORed with the plaintext before decryption and the ciphertext is stored as the IV for the next block.
void des_decrypt_cbc(uint64_t *blocks, int num_blocks, uint64_t key, uint64_t iv) {
    uint64_t previous_cipher = iv;

    for (int i = 0; i < num_blocks; i++) {
        uint64_t temp = blocks[i];  // Store original ciphertext
        des_decrypt(&blocks[i], key);  // Decrypt with DES
        blocks[i] ^= previous_cipher;  // XOR with previous ciphertext (or IV)
        previous_cipher = temp;  // Update previous ciphertext
    }
}
