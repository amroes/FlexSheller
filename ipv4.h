#ifndef IPV4_H
#define IPV4_H

#include <windows.h>

// Helper function for IPv4 formatting
char* GenerateIpv4(int a, int b, int c, int d);

// Function to obsucate shellcode to IPv4 Format
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);

// Padding Function to assure that our payload is a multiple of 4
BOOL PaddBuffer4(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize);
#endif
