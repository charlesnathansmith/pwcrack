#include <iostream>
#include <set>
#include "pwencrypt.h"

// Solves pwencrypt for shift_a and shift_b given plain and encrypted text
// len specifies the number of uint32_t values in plain and crypt
// len must be at least 3, but more data decreases the chance of false positives
bool pwencrypt_solve(const uint32_t* plain, const uint32_t* crypt, size_t len, uint32_t* shift_a, uint32_t* shift_b)
{
    if (len < 3)
        return false;

    std::set<uint32_t> b_test;
    uint32_t shift_a1 = plain[0] ^ crypt[0];
    uint32_t shift_a3 = plain[1] ^ crypt[1];

    printf("shift_a1: %.8x\n", shift_a1);
    printf("shift_a3: %.8x\n\n", shift_a3);

    // Find candidate shift_b values
    printf("Candidate shift_b values\n");

    for (size_t i = 0; i <= 0xff; i++)
    {
        uint32_t shift_a2 = rol32(shift_a3, i);
        uint32_t shift_b2 = shift_a2 ^ shift_a1;

        if (((shift_b2 >> 8) & 0xff) == i)
        {
            uint32_t shift_b1 = ror32(shift_b2, shift_a1 & 0xff);

            printf("%.8x\n", shift_b1);
            b_test.insert(shift_b1);
        }
    }

    // Test candidate values against the data
    printf("\nTesting candidate values\n\n");

    for (uint32_t _b : b_test)
    {
        uint32_t a = plain[0] ^ crypt[0];
        uint32_t b = _b;
        bool found = true;

        for (size_t i = 0; i < len; i++)
        {
            if ((plain[i] ^ a) != crypt[i])
            {
                found = false;
                break;
            }

            b = rol32(b, a & 0xff);
            a ^= b;
            a = ror32(a, (b >> 8) & 0xff);
            b += a;
        }

        if (found)
        {
            *shift_a = plain[0] ^ crypt[0];
            *shift_b = _b;

            printf("Found\n");
            printf("shift_a: %.8x\n", *shift_a);
            printf("shift_b: %.8x\n\n", *shift_b);
            return true;
        }
    }

    return false;
}

void pwencrypt_ab(const uint32_t* plain_in, uint32_t* crypt_out, size_t len, uint32_t shift_a, uint32_t shift_b)
{
    for (size_t i = 0; i < len; i++)
    {
        crypt_out[i] = plain_in[i] ^ shift_a;
        shift_b = rol32(shift_b, shift_a & 0xff);
        shift_a ^= shift_b;
        shift_a = ror32(shift_a, (shift_b >> 8) & 0xff);
        shift_b += shift_a;
    }
}

int main()
{
    const uint32_t plaintext[] = { 0x5e3b2c68, 0x82890e1f, 0xb1b52b92, 0x23bff22b, 0xa4ecf4cb, 0x953a9ee3, 0x873e8e20, 0xa936446d, 0x455aef03, 0xaee04849, 0x8d808eb2, 0x8b511e0a };
    const char password[] = "2a7l9O18tNauR38W7v92l4wCEJcW7wY1";
    
    // Expect { 0x97001ccf, 0xfc91c8ac, 0xef7eedd0, 0x895d8540, 0x1ed5a1f6, 0x213a9a7d, 0x01cf5626, 0xa37b8a51, 0xdbb3adac, 0xc8c902ac, 0x22c95eff, 0x577fb2d9 };
    uint32_t encrypted[sizeof(plaintext) / sizeof(uint32_t)];

    size_t len = sizeof(plaintext) / sizeof(uint32_t);
    uint32_t shift_a = 0, shift_b = 0;

    puts("Plaintext");

    for (uint32_t e : plaintext)
        printf("%.8x ", e);

    // Encrypting with original password encrypt routine
    pw_encrypt(plaintext, encrypted, len, password);

    puts("\n\nEncrypted");

    for (uint32_t e : encrypted)
        printf("%.8x ", e);

    puts("\n\nAttempting to solve for shift registers\n");

    if (!pwencrypt_solve(plaintext, encrypted, len, &shift_a, &shift_b))
    {
        printf("Couldn't find shift register values\n");
        return -1;
    }

    printf("Testing encryption with shift_a = %.8x, shift_b = %.8x\n\n", shift_a, shift_b);

    uint32_t test[sizeof(encrypted) / sizeof(uint32_t)];
    pwencrypt_ab(plaintext, test, len, shift_a, shift_b);

    puts("Test encryption result");

    for (uint32_t e : test)
        printf("%.8x ", e);

    for (size_t i = 0; i < len; i++)
        if (test[i] != encrypted[i])
        {
            puts("Encryption failed");
            return -1;
        }

    puts("\n\nEncryption succesful");
    return 0;
}
