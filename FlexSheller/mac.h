#ifndef MAC_H
#define MAC_H

#include <windows.h>

// Helper function for MAC formatting
char* GenerateMAC(int a, int b, int c, int d, int e, int f);

// Function to obsucate shellcode to MAC Format
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);

// Padding Function to assure that our payload is a multiple of 16
BOOL PaddBuffer6(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize);
#endif
