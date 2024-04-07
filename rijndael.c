/*
 * Philip Keogh
 * 
 * This code implements the Rijndael cipher.
 * It includes functions for key expansion, and the four main operations of the AES algorithm: sub_bytes, shift_rows, mix_columns, and add_round_key. 
 * Both encryption and decryption are supported, with separate functions for the inverse operations used in decryption.
 */

#include <stdlib.h>
#include <stdio.h>

#include "rijndael.h"


// Implementation: S-Box
unsigned char S_BOX[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F

unsigned char RS_BOX[256] =
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};


unsigned char get_sbox_value(unsigned char num) {
    return S_BOX[num];
}
unsigned char get_s_box_invert(unsigned char num) {
    return RS_BOX[num];
}


// Rotate the bytes of a word to the left. This operation is a part of the key expansion process.
void rotate(unsigned char *word) {
    unsigned char temp = word[0];
    for (int i = 0; i < 3; i++) {
        word[i] = word[i + 1];
    }
    word[3] = temp;
}


// Implementation: Rcon
unsigned char R_CON[255] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
};

// Implementation: Get Rcon Value
unsigned char get_rcon_value(unsigned char num) {
    return R_CON[num];
}

// Implementation: Key Schedule Core
void core(unsigned char *word, int iteration) {
    // Rotate the input word 1 byte to the left
    rotate(word);

    // Apply S-Box substitution on all bytes of the word
    for (int i = 0; i < 4; ++i) {
        word[i] = get_sbox_value(word[i]);
    }

    // XOR the output of the rcon operation with the first part of the word
    word[0] ^= get_rcon_value(iteration);
}



// Helper functions
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) == 1) 
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80) 
            a ^= 0x1b;		
        b >>= 1;
    }
    return p;
}

unsigned char mul_by_02(unsigned char num) {
    if (num < 0x80) 
        return (num << 1);
    else
        return (num << 1) ^ 0x1b;
}

unsigned char mul_by_03(unsigned char num) {
    return mul_by_02(num) ^ num;
}

unsigned char mul_by_0e(unsigned char num) {
    return (unsigned char)((num << 1) ^ (num << 2) ^ (num << 3) ^ ((num & 0x80 ? 0x1B : 0) << 1));
}

unsigned char mul_by_0b(unsigned char num) {
    return (unsigned char)(num ^ (num << 1) ^ (num << 3) ^ ((num & 0x80 ? 0x1B : 0) << 1));
}

unsigned char mul_by_0d(unsigned char num) {
    return (unsigned char)(num ^ (num << 2) ^ (num << 3) ^ ((num & 0x80 ? 0x1B : 0) << 1));
}

unsigned char mul_by_09(unsigned char num) {
    return (unsigned char)(num ^ (num << 3) ^ ((num & 0x80 ? 0x1B : 0) << 1));
}


/*
 * Operations used when encrypting a block
 */


// This step is a non-linear byte substitution for each byte in the input block.
void sub_bytes(unsigned char *block) {
    // Iterate through each byte in the 16-byte block.
    for (int i = 0; i < BLOCK_SIZE; i++) {
        // Substitute each byte using the S-box.
        // The S_BOX array acts as a lookup table to perform the substitution.
        block[i] = S_BOX[block[i]];
    }
}

// Performs the ShiftRows step in the AES encryption process.
// Rows of the state are cyclically shifted by different offsets.
void shift_rows(unsigned char *block) {
    unsigned char temp;

    // Shift the second row 1 byte to the left
    // This uses a temporary variable to cyclically rotate the bytes
    temp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp;

    // Shift the third row 2 bytes to the left
    // It requires two steps, swapping two pairs of bytes
    temp = block[2];  // Temporarily store the value at block[2]
    block[2] = block[10];
    block[10] = temp;
    temp = block[6];  // Temporarily store the next value to keep the shift
    block[6] = block[14];
    block[14] = temp;

    // Shift the fourth row 3 bytes to the left
    // This is a circular shift done in the reverse direction of the second row
    temp = block[3];
    block[3] = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = temp;
}

// This function mixes the columns of the state matrix.
void mix_columns(unsigned char *block) {
    unsigned char temp[4];

    // Iterate over each column of the state block
    for (int i = 0; i < 4; i++) {
        // Copy the current column to a temporary array for manipulation
        for (int j = 0; j < 4; j++) {
            temp[j] = block[i * 4 + j];
        }

        // Perform the mix column operation on the temporary array and
        // write the results back to the original block.
        // Each byte in a column is replaced with a value dependent on the values of all bytes in that column.
        block[i * 4 + 0] = gmul(temp[0], 0x02) ^ gmul(temp[3], 0x01) ^ gmul(temp[2], 0x01) ^ gmul(temp[1], 0x03);
        block[i * 4 + 1] = gmul(temp[1], 0x02) ^ gmul(temp[0], 0x01) ^ gmul(temp[3], 0x01) ^ gmul(temp[2], 0x03);
        block[i * 4 + 2] = gmul(temp[2], 0x02) ^ gmul(temp[1], 0x01) ^ gmul(temp[0], 0x01) ^ gmul(temp[3], 0x03);
        block[i * 4 + 3] = gmul(temp[3], 0x02) ^ gmul(temp[2], 0x01) ^ gmul(temp[1], 0x01) ^ gmul(temp[0], 0x03);
    }
}


/*
 * Operations used when decrypting a block
 */



// This function applies the inverse S-Box to each byte of the state block,
// effectively reversing the sub_bytes step of the encryption process.
void invert_sub_bytes(unsigned char *block) {
    // Iterate over each byte in the 16-byte block
    for (int i = 0; i < BLOCK_SIZE; i++) {
        // Replace each byte with its corresponding value from the inverse S-Box (RS_BOX)
        block[i] = RS_BOX[block[i]];
    }
}



// This function reverses the row shifting done during the encryption's shift_rows step,
// effectively aligning the block back to its original row order before encryption.
void invert_shift_rows(unsigned char *block) {
    unsigned char temp; // Temporary storage for byte swapping

    // Shift the second row to the right by 1 position
    temp = block[13]; // Temporarily store the last byte of the row
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = temp; // Move the temporary stored byte to the start of the row

    // Shift the third row to the right by 2 positions
    // Perform the shift in two steps for each byte to complete the two-position shift
    temp = block[2]; // Temporarily store the second byte of the row
    block[2] = block[10];
    block[10] = temp; // Complete the first half of the shifting
    temp = block[6]; // Repeat for the second half
    block[6] = block[14];
    block[14] = temp;

    // Shift the fourth row to the right by 3 positions, completing a circular shift
    temp = block[3]; // Temporarily store the first byte of the row
    block[3] = block[15]; // Shift each byte to the right by 3 positions
    block[15] = block[11];
    block[11] = block[7];
    block[7] = temp; // Place the temporarily stored byte at the last position
}



// This function reverses the column mixing done during the encryption's mix_columns step,
// effectively realigning the block columns to their original state before encryption.
void invert_mix_columns(unsigned char *block) {
    unsigned char temp[4]; // Temporary storage for a column

    // Iterate over each of the 4 columns
    for(int col = 0; col < 4; col++) {
        // Copy the current column into temp
        for(int row = 0; row < 4; row++) {
            temp[row] = block[col * 4 + row];
        }

        // Apply the Inverse MixColumns transformation using pre-defined multiplication functions
        block[col * 4 + 0] = (unsigned char)(mul_by_0e(temp[0]) ^ mul_by_0b(temp[1]) ^ mul_by_0d(temp[2]) ^ mul_by_09(temp[3]));
        block[col * 4 + 1] = (unsigned char)(mul_by_09(temp[0]) ^ mul_by_0e(temp[1]) ^ mul_by_0b(temp[2]) ^ mul_by_0d(temp[3]));
        block[col * 4 + 2] = (unsigned char)(mul_by_0d(temp[0]) ^ mul_by_09(temp[1]) ^ mul_by_0e(temp[2]) ^ mul_by_0b(temp[3]));
        block[col * 4 + 3] = (unsigned char)(mul_by_0b(temp[0]) ^ mul_by_0d(temp[1]) ^ mul_by_09(temp[2]) ^ mul_by_0e(temp[3]));
    }
}

/*
 * This operation is shared between encryption and decryption
 */

// This step combines the block of data with a key using bitwise XOR.
// It is used both in encryption and decryption processes.
void add_round_key(unsigned char *block, unsigned char *round_key) {
    // Iterate through each byte of the block
    for (int index = 0; index < BLOCK_SIZE; index++) {
        // Perform bitwise XOR between each byte of the block and the round key
        block[index] ^= round_key[index];
    }
}


/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
    unsigned char *expanded_key = malloc(EXPANDED_KEY_SIZE);
    unsigned char temp[4];
    int i = 0;

    // The first round key is the cipher key
    for (i = 0; i < 16; i++) {
        expanded_key[i] = cipher_key[i];
    }

    // All other round keys are found from the previous round keys
    for (; i < 176; i += 4) {
        for (int j = 0; j < 4; j++) {
            temp[j] = expanded_key[i - 4 + j];
        }

        if (i % 16 == 0) {
            // Perform core schedule operations
            rotate(temp);
            for (int j = 0; j < 4; j++) {
                temp[j] = S_BOX[temp[j]];
            }
            temp[0] ^= R_CON[i/16];
        }

        for (unsigned char a = 0; a < 4; a++) {
            expanded_key[i + a] = expanded_key[i - 16 + a] ^ temp[a];
        }
    }

    return expanded_key;
}
/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
    unsigned char state[16]; // the state array
    unsigned char *expanded_key = expand_key(key); // expand the key into 176 bytes

    // the initial state is the plaintext
    for (int i = 0; i < 16; i++) {
        state[i] = plaintext[i];
    }

    // initial add_round_key
    add_round_key(state, expanded_key);

    // 9 rounds of sub_bytes, shift_rows, mix_columns, add_round_key
    for (int round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, expanded_key + round * 16);
    }

    // final round (no MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, expanded_key + 10 * 16);

    // the final state is the ciphertext
    unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * 16);
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }

    free(expanded_key); // free the expanded key

    return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {
    unsigned char state[16]; // the state array
    unsigned char *expanded_key = expand_key(key); // expand the key into 176 bytes

    // the initial state is the ciphertext
    for (int i = 0; i < 16; i++) {
        state[i] = ciphertext[i];
    }

    // initial add_round_key
    add_round_key(state, expanded_key + 10 * 16);

    // 9 rounds of invert_shift_rows, invert_sub_bytes, add_round_key, invert_mix_columns
    for (int round = 9; round > 0; round--) {
        invert_shift_rows(state);
        invert_sub_bytes(state);
        add_round_key(state, expanded_key + round * 16);
        invert_mix_columns(state);
    }

    // final round (no invert_mix_columns)
    invert_shift_rows(state);
    invert_sub_bytes(state);
    add_round_key(state, expanded_key);

    // the final state is the plaintext
    unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * 16);
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }

    free(expanded_key); // free the expanded key

    return output;
}

