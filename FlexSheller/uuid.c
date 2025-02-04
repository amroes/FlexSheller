#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "uuid.h"

// Function takes in 16 raw bytes and returns them in a UUID string format
char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

    // Dynamically allocate memory for the UUID string
    char* result = (char*)malloc(37 * sizeof(char));  // UUID format is "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (36 characters + 1 for '\0')
    if (result == NULL) {
        return NULL;  // Memory allocation failed
    }

    // Generating UUID segments
    sprintf_s(result, 37, "%0.2X%0.2X%0.2X%0.2X-%0.2X%0.2X-%0.2X%0.2X-%0.2X%0.2X-%0.2X%0.2X%0.2X%0.2X",
        a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);

    return result;
}

// Generate the UUID output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
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

    printf("char* UuidArray[%d] = { \n\t", (int)(ShellcodeSize / 16));

    // We will read one shellcode byte at a time, when the total is 16, begin generating the UUID string
    int c = 16, counter = 0;
    char* UUID = NULL;

    for (int i = 0; i < ShellcodeSize; i++) {
        if (c == 16) {
            counter++;

            // Generating the UUID string from 16 bytes which begin at i until [i + 15]
            UUID = GenerateUUid(
                pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
                pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
                pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
                pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
            );

            if (i == ShellcodeSize - 16) {
                // Printing the last UUID string
                printf("\"%s\"", UUID);
                free(UUID);  // Free the dynamically allocated memory
                break;
            }
            else {
                // Printing the UUID string
                printf("\"%s\", ", UUID);
                free(UUID);  // Free the dynamically allocated memory after use
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

    return TRUE;
}

