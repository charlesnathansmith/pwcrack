# pwcrack
This program demonstrates a flaw in a password encryption method used by a commercial product

pwencrypt.h contains the original routine as reverse engineered from the product binary

pwcrack.cpp demonstrates a known plaintext attack that can completely circumvent the offered protection

The original encryption method hashes the provided password in order to generate two shift registers that are then used to actually encrypt the data.

While it would be difficult to recover the orignal password, determining the generated shift registers is enough to fully encrypt or decrypt any data, and these are relatively trivial to recover from a small sample of corresponding plaintext and encrypted values
