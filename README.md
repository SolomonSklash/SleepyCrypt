# SleepyCrypt

A shellcode function to encrypt a running process image in memory when sleeping.

This is the companion code for my blog post [here](https://www.solomonsklash.io/SOMETHING.html).

## Build

Just run `build.sh` to compile the C code, extract the `.text` section as shellcode, and compile it into a test binary called `sleep.exe`. This will require MinGW (`x86_64-w64-mingw32-gcc`, `x86_64-w64-mingw32-ld`, and `objcopy`) on Linux.
