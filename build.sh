#!/bin/bash

# Compile the C code and extract the shellcode.
make shellcode -j 4

# Convert the shellcode to a C array.
xxd -i shellcode.bin > shellcode.h

# Compile the test program to run the shellcode.
make sleep -j 4

echo ""
echo "Run '.\sleep.exe [time in milliseconds]' to test the shellcode."