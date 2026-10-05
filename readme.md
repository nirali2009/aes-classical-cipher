# AES CLASSICAL CIPHER

A command line encryption and decryption tool implementing the Vigenere cipher and AES-128 from scratch in Python

## Features

- Vigenere cipher encryption and decryption 
- AES-128 encryption and decryption (in ECB mode)
- Direct string and text file input 
- Hexadecimal and Base64 ciphertext output for AES encryption 
- Hexadecimal and Base64 input for AES decryption 
- No external cryptography libraries used

## Command line arguments 

- ‘-e’,’--encrypt’,’Encrypt the input’
- ‘-d’,’--decrypt’,’Decrypt the input’
- ‘-c’,’--cipher’,’Select the cipher’
- ‘-f’,’--file’,’Input as a text file’
- ‘-s’,’--string’,’Input as a string’
- ‘-k’,’--key’,’Provide the encryption and decryption key’
- ‘-o’,’--output’,’Select Hex or Base64 encoding for AES encryption output or decryption input’

## Requirements

- Python 3
- No external cryptography libraries required

## Execution examples

- Vigenere encryption 
   ```
   py cipher_implementation.py -e -c vigenere -s "Hello_World" -k "key" 
   ```
- Vigenere decryption 
   ```
   py cipher_implementation.py -d -c vigenere -s "Rijvs_Uyvjn" -k "key"
   ```
- AES-128 encryption 
   ```
   py cipher_implementation.py -e -c aes -s "Hello AES!" -k "1234567890123456"
   ```
- AES-128 encryption with base64 output
   ```
   py cipher_implementation.py -e -c aes -s "Hello AES!" -k "1234567890123456" -o base64
   ```
- AES-128 decryption from hex
   ```
   py cipher_implementation.py -d -c aes -s "049704ee9f079487de866637f738339d" -k "1234567890123456" -o hex
   ```
- AES-128 decryption from base64
   ```
   py cipher_implementation.py -d -c aes -s "NSZ5g0rObjUWqanTAH3TRgYBDCkSf2tsEI6pgh/nufQ=" -k "1234567890123456" -o base64
   ```
- AES-128 encryption from file
   ```
   py cipher_implementation.py -e -c aes -f test.txt -k "1234567890123456" -o hex
   ```
   (The specified text file must exist at the given path)
