#ifndef UUID_H
#define UUID_H

#include <windows.h>

// Helper function for uuid formatting
char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p);

// Function to obsucate shellcode to uuid Format
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);

// Padding function already defined in IPV6
#endif
