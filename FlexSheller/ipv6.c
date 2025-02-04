#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "ipv6.h"

// Function takes in 16 raw bytes and returns them in an IPv6 address string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

    // Dynamically allocate memory for the IPv6 address (40 bytes to accommodate the full address)
    char* result = (char*)malloc(40 * sizeof(char));  // 40 characters for the IPv6 address string, including the colon separators
    if (result == NULL) {
        return NULL;  // Memory allocation failed
    }

    // Generate the IPv6 address as before
    snprintf(result, 40, "%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X",
        a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);

    return result;  // Return the dynamically allocated string
}


// Generate the IPv6 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
    // If the shellcode buffer is null or the size is zero, exit
    if (pShellcode == NULL || ShellcodeSize == 0) {
        return FALSE;
    }

    // If the size is not a multiple of 16, pad it
    if (ShellcodeSize % 16 != 0) {
        unsigned char* paddedShellcode = NULL;
        SIZE_T paddedSize = 0;
        if (!PaddBuffer16(pShellcode, ShellcodeSize, &paddedShellcode, &paddedSize)) {
            return FALSE;  // Padding failed
        }
        pShellcode = paddedShellcode;
        ShellcodeSize = paddedSize;
    }

    printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));

    // We will read one shellcode byte at a time, when the total is 16, begin generating the IPv6 address
    // The variable 'c' is used to store the number of bytes read. By default, starts at 16.
    int c = 16, counter = 0;
    char* IP = NULL;

    for (int i = 0; i < ShellcodeSize; i++) {
        // Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the IPv6 address
        if (c == 16) {
            counter++;

            // Generating the IPv6 address from 16 bytes which begin at i until [i + 15]
            IP = GenerateIpv6(
                pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
                pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
                pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
                pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
            );

            if (i == ShellcodeSize - 16) {
                // Printing the last IPv6 address
                printf("\"%s\"", IP);
                break;
            }
            else {
                // Printing the IPv6 address
                printf("\"%s\", ", IP);
            }
            c = 1;

            // Optional: To beautify the output on the console
            if (counter % 3 == 0) {
                printf("\n\t");
            }
        }
        else {
            c++;
        }
    }
    printf("\n};\n\n");

    // Free the dynamically allocated memory for IPv6 addresses
    if (IP != NULL) {
        free(IP);
    }

    return TRUE;
}

BOOL PaddBuffer16(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {
    // Round up the size to the next multiple of 16
    SIZE_T PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16); // Align to the next multiple of 16
    PBYTE PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
    if (!PaddedBuffer) {
        return FALSE;  // Memory allocation failed
    }

    ZeroMemory(PaddedBuffer, PaddedSize); // Clean the buffer
    memcpy(PaddedBuffer, InputBuffer, InputBufferSize); // Copy the original data

    *OutputPaddedBuffer = PaddedBuffer;
    *OutputPaddedSize = PaddedSize;

    return TRUE;
}
