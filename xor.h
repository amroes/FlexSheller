#ifndef XOR_H
#define XOR_H

#include <windows.h>

// Function to encrypt shellcode using xor
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bkey, IN SIZE_T sKeySize);

#endif
