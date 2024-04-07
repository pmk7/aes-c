# AES-C

This project is an implementation of the Advanced Encryption Standard (AES) in C. AES is a symmetric block cipher that's used to encrypt and decrypt information in blocks of 128 bits.

# Features
Implements AES encryption and decryption
Includes a main program that demonstrates encryption and decryption of a 128-bit block of plaintext using a 128-bit key

To compile the project, run:

`make`

To run tests, run:

`make test`

To compile, run:

`./main`

This will encrypt a block of plaintext, print the resulting ciphertext, decrypt the ciphertext, and print the recovered plaintext.

# Code Structure 

`rijndael.c` and `rijndael.h` : These files contain the implementation of the AES algorithm, including key expansion, the main AES rounds, and the final AES round.
`main.c`: This file contains a main program that demonstrates how to use the functions in rijndael.c to encrypt and decrypt a block of plaintext.
`aes-python` submodule contains an implementation of AES in Python as well as a suite of tests which can be used to test both the C and Python implementations
