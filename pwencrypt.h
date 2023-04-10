/************************************************************
*
*  pwcrack
*  Nathan Smith
*  https://github.com/charlesnathansmith/pwcrack
* 
*  Original reverse engineered password encryption routine
*  Decryption is the same as encryption
* 
************************************************************/

#pragma once
#include <cstdint>

// 32-bit rotate right
uint32_t ror32(uint32_t value, uint8_t amount)
{
    return (value >> amount) | (value << (32 - amount));
}

// 32-bit rotate left
uint32_t rol32(uint32_t value, uint8_t amount)
{
    return (value << amount) | (value >> (32 - amount));
}

// Pasword encryption helper
uint32_t codex(const char* key, uint32_t shift)
{
    uint16_t counter = 0;

    do {
        shift ^= ((uint32_t)*key) << 8;

        do {
            shift = (shift ^ (counter & 0xFF)) + 0x7034616b;
            shift = ror32(shift, shift & 0xFF);
            shift ^= 0x8372a5a7;
            counter--;
        } while (counter != 0);
    } while (*key++ != 0);

    return shift;
}

// Password encryption
// len specifies number of uint32_t values in plain_in plaintext buffer
void pw_encrypt(const uint32_t* plain_in, uint32_t* crypt_out, size_t len, const char* password)
{
    // Initialize shift registers
    uint32_t shift_a = 0x41363233 ^ password[0];
    uint32_t shift_b = shift_a = codex(password, shift_a);

    shift_a ^= ((uint32_t)password[0]) << 8;
    shift_a = codex(password, shift_a);

    // Encryption loop
    for (size_t i = 0; i < len; i++)
    {
        crypt_out[i] = plain_in[i] ^ shift_a;

        shift_b = rol32(shift_b, shift_a & 0xff);
        shift_a ^= shift_b;

        shift_a = ror32(shift_a, (shift_b >> 8) & 0xff);
        shift_b += shift_a;
    }
}
