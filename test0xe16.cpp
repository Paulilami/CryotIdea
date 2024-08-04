#include <stdint.h>
#include <cmath>
#include <cstring>
#include <iostream>
#include <vector>
#include <stdexcept>

const int ROUNDS = 14;
const int BLOCK_SIZE = 16; 
const int KEY_SIZE = 32;   
const int EXPANDED_KEY_SIZE = 176;

uint8_t sbox[256];
uint8_t inv_sbox[256];

void generate_sbox() {
    for (int i = 0; i < 256; ++i) {
        uint8_t x = i;
        uint8_t y = x;
        for (int j = 0; j < 7; ++j) {
            y = (y << 1) ^ ((y & 0x80) ? 0x1B : 0);
        }
        sbox[i] = y ^ 0x63; 
    }
      for (int i = 0; i < 256; ++i) {
        inv_sbox[sbox[i]] = i;
    }
}

uint32_t sbox_sub(uint32_t x) {
    return (sbox[x & 0xFF] << 24) |
           (sbox[(x >> 8) & 0xFF] << 16) |
           (sbox[(x >> 16) & 0xFF] << 8) |
           sbox[x >> 24];
}

uint32_t inv_sbox_sub(uint32_t x) {
    return (inv_sbox[x & 0xFF] << 24) |
           (inv_sbox[(x >> 8) & 0xFF] << 16) |
           (inv_sbox[(x >> 16) & 0xFF] << 8) |
           inv_sbox[x >> 24];
}

void key_schedule(const uint8_t* key, uint8_t* expanded_key) {
    memcpy(expanded_key, key, KEY_SIZE);
    for (int i = KEY_SIZE; i < EXPANDED_KEY_SIZE; i++) {
        expanded_key[i] = sbox[expanded_key[i - KEY_SIZE] ^ expanded_key[i - 1]];
        expanded_key[i] ^= (i / KEY_SIZE) & 0xFF; 
    }
}

void shift_rows(uint8_t* state) {
    uint8_t temp[BLOCK_SIZE];
    memcpy(temp, state, BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = temp[(i + (i % 4)) % BLOCK_SIZE];
    }
}

void inv_shift_rows(uint8_t* state) {
    uint8_t temp[BLOCK_SIZE];
    memcpy(temp, state, BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[(i + (i % 4)) % BLOCK_SIZE] = temp[i];
    }
}

void encrypt(uint8_t* block, const uint8_t* key) {
    uint8_t state[BLOCK_SIZE];
    uint8_t expanded_key[EXPANDED_KEY_SIZE];
    key_schedule(key, expanded_key);
    memcpy(state, block, BLOCK_SIZE);

    for (int round = 0; round < ROUNDS; round++) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = sbox[state[i]];
        }
        shift_rows(state);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] ^= expanded_key[round * BLOCK_SIZE + i];
        }
    }
    memcpy(block, state, BLOCK_SIZE);
}

void decrypt(uint8_t* block, const uint8_t* key) {
    uint8_t state[BLOCK_SIZE];
    uint8_t expanded_key[EXPANDED_KEY_SIZE];
    key_schedule(key, expanded_key);

    memcpy(state, block, BLOCK_SIZE);

    for (int round = ROUNDS - 1; round >= 0; round--) {
      for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] ^= expanded_key[round * BLOCK_SIZE + i];
        }
        inv_shift_rows(state);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = inv_sbox[state[i]];
        }
    }

    memcpy(block, state, BLOCK_SIZE);
}

void encrypt_cbc(uint8_t* input, uint8_t* output, size_t length, const uint8_t* key, uint8_t* iv) {
    uint8_t block[BLOCK_SIZE];
    uint8_t prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < length; i += BLOCK_SIZE) {
        memcpy(block, input + i, BLOCK_SIZE);
        for (int j = 0; j < BLOCK_SIZE; j++) {
            block[j] ^= prev_block[j];
        }
        encrypt(block, key);
        memcpy(output + i, block, BLOCK_SIZE);
        memcpy(prev_block, block, BLOCK_SIZE);
    }
}

void decrypt_cbc(uint8_t* input, uint8_t* output, size_t length, const uint8_t* key, uint8_t* iv) {
    uint8_t block[BLOCK_SIZE];
    uint8_t prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < length; i += BLOCK_SIZE) {
        memcpy(block, input + i, BLOCK_SIZE);
        decrypt(block, key);
        for (int j = 0; j < BLOCK_SIZE; j++) {
            block[j] ^= prev_block[j];
        }
        memcpy(output + i, block, BLOCK_SIZE);
        memcpy(prev_block, input + i, BLOCK_SIZE);
    }
}

int main() {
    generate_sbox();

    uint8_t input[BLOCK_SIZE] = { /* input data */ };
    uint8_t output[BLOCK_SIZE] = {0};
    uint8_t key[KEY_SIZE] = { /* 256-bit key */ };
    uint8_t iv[BLOCK_SIZE] = { /* initialization vector */ };

    try {
        encrypt_cbc(input, output, BLOCK_SIZE, key, iv);
        std::cout << "Encrypted: ";
        for (int i = 0; i < BLOCK_SIZE; i++) {
            std::cout << std::hex << static_cast<int>(output[i]) << " ";
        }
        std::cout << std::endl;

        decrypt_cbc(output, input, BLOCK_SIZE, key, iv);
        std::cout << "Decrypted: ";
        for (int i = 0; i < BLOCK_SIZE; i++) {
            std::cout << std::hex << static_cast<int>(input[i]) << " ";
        }
        std::cout << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
