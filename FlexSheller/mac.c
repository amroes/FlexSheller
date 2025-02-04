#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "mac.h"

// Function takes in 6 raw bytes and returns them in a MAC address string format
char* GenerateMAC(int a, int b, int c, int d, int e, int f) {
    static char Output[64]; // Using static memory for the output buffer

    // Creating the MAC address and saving it to the 'Output' variable
    sprintf_s(Output, sizeof(Output), "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", a, b, c, d, e, f);

    return Output;
}

// Generate the MAC output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
    // If the shellcode buffer is null or the size is not a multiple of 6, exit
    if (pShellcode == NULL || ShellcodeSize == 0) {
        return FALSE;
    }
    if (ShellcodeSize % 6 != 0) {
        unsigned char* paddedShellcode = NULL;
        SIZE_T paddedSize = 0;
        if (!PaddBuffer6(pShellcode, ShellcodeSize, &paddedShellcode, &paddedSize)) {
            return FALSE;
        }
        pShellcode = paddedShellcode;
        ShellcodeSize = paddedSize;
    }

    printf("char* MacArray[%d] = {\n\t", (int)(ShellcodeSize / 6));

    // We will read one shellcode byte at a time, when the total is 6, begin generating the MAC address
    int c = 6, counter = 0;
    char* Mac = NULL;

    for (int i = 0; i < ShellcodeSize; i++) {
        // Track the number of bytes read and when they reach 6 we enter this if statement to begin generating the MAC address
        if (c == 6) {
            counter++;

            // Generating the MAC address from 6 bytes which begin at i until [i + 5]
            Mac = GenerateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5]);

            if (i == ShellcodeSize - 6) {
                // Printing the last MAC address
                printf("\"%s\"", Mac);
                break;
            }
            else {
                // Printing the MAC address
                printf("\"%s\", ", Mac);
            }
            c = 1;

            // Optional: To beautify the output on the console
            if (counter % 6 == 0) {
                printf("\n\t");
            }
        }
        else {
            c++;
        }
    }
    printf("\n};\n\n");
    return TRUE;
}

// Helper function to pad the buffer size to the nearest multiple of 6
BOOL PaddBuffer6(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {
    // Round up the size to the next multiple of 6
    SIZE_T PaddedSize = InputBufferSize + 6 - (InputBufferSize % 6); // Align to the next multiple of 6
    PBYTE PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
    if (!PaddedBuffer) {
        return FALSE;
    }

    ZeroMemory(PaddedBuffer, PaddedSize); // Clean the buffer
    memcpy(PaddedBuffer, InputBuffer, InputBufferSize); // Copy the original data

    *OutputPaddedBuffer = PaddedBuffer;
    *OutputPaddedSize = PaddedSize;

    return TRUE;
}
