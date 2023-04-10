#include <iostream>

/*
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
void pw_encrypt(uint32_t* buf, size_t size, const char* key)
{
    size_t num_blocks = size / 4;

    // Initialize shift registers
    uint32_t shift_a = 0x41363233 ^ key[0];
    uint32_t shift_b = shift_a = codex(key, shift_a);
*/

// Rotate right
uint32_t ror32(uint32_t value, uint8_t amount)
{
    return (value >> amount) | (value << (32 - amount));
}

int main()
{
    char key[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    uint32_t a = 0x41363233;

    for (size_t i = 0; i < strlen(key); i++)
    {
        uint32_t shift = a ^ (uint32_t)key[i] ^ (uint32_t)(key[i] << 8);

        uint16_t counter = 0;
        do {
            shift = (shift ^ (counter & 0xFF)) + 0x7034616b;
            shift = ror32(shift, shift & 0xFF);
            shift ^= 0x8372a5a7;
            counter--;
        } while (counter != 0);

        printf("%c\t%.8x\n", key[i], shift);
    }
}
