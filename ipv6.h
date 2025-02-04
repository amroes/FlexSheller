#ifndef IPV6_H
#define IPV6_H

#include <windows.h>

// Helper function for IPv6 formatting
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p);

// Function to obsucate shellcode to IPv6 Format
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);

// Padding Function to assure that our payload is a multiple of 16
BOOL PaddBuffer16(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize);
#endif
