#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define CBC 1
#define AES256 1
#include "xor.h"
#include "aes.h"
#include "rc4.h"
#include "ipv4.h"
#include "ipv6.h"
#include "mac.h"
#include "uuid.h"

void GenerateRandomBytes(uint8_t* buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (uint8_t)(rand() % 0xFF);
    }
}

void PrintBanner(const char* mode) {
    printf("######################################################################\n");
    printf("#                                                                    #\n");
    printf("#                          FlexSheller                               #\n");
    printf("#                          Mode: %-10s                            #\n", mode);
    printf("#                          Made by @amroes                           #\n");
    printf("#                                                                    #\n");
    printf("######################################################################\n\n");
}

void PrintUsage() {
    printf("######################################################################\n");
    printf("#                                                                    #\n");
    printf("#                          FlexSheller                               #\n");
    printf("#                          Made by @amroes                           #\n");
    printf("#                                                                    #\n");
    printf("######################################################################\n\n");
    printf("Usage: flexsheller <mode> <payload_file> [key] [-o <output_file>]\n");
    printf("Modes:\n");
    printf("\tmac   - Generate MAC Address payload\n");
    printf("\tipv4  - Generate IPv4 Address payload\n");
    printf("\tipv6  - Generate IPv6 Address payload\n");
    printf("\tuuid  - Generate UUID payload\n");
    printf("\taes   - AES-256 encrypted payload (requires key)\n");
    printf("\trc4   - RC4 encrypted payload (requires key)\n");
    printf("\txor   - XOR encrypted payload (requires key)\n");
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
    printf("unsigned char %s[] = {", Name);
    for (size_t i = 0; i < Size; i++) {
        if (i % 16 == 0)
            printf("\n\t");
        printf("0x%0.2X%s", Data[i], (i < Size - 1) ? ", " : " ");
    }
    printf("\n};\n");
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        PrintUsage();
        return 1;
    }

    char* mode = argv[1];
    char* filename = argv[2];
    unsigned char* key = NULL;
    SIZE_T keySize = 0;
    char* outputFile = NULL;

    if (argc > 3 && strcmp(argv[3], "-o") == 0) {
        outputFile = argv[4];
    }

    int encryptionMode = (strcmp(mode, "rc4") == 0 || strcmp(mode, "xor") == 0);
    if (encryptionMode && argc < 4) {
        printf("!!!!!!!! Error: RC4 and XOR Encryption mode requires a key !!!!!!!!\n");
        return 1;
    }

    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        printf("Error opening file: %s\n", filename);
        return 1;
    }

    fseek(fp, 0L, SEEK_END);
    SIZE_T shellcodeSize = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    unsigned char* shellcode = (unsigned char*)malloc(shellcodeSize);
    if (!shellcode) {
        printf("Memory allocation failed!\n");
        fclose(fp);
        return 1;
    }

    if (fread(shellcode, 1, shellcodeSize, fp) != shellcodeSize) {
        printf("Error reading file!\n");
        fclose(fp);
        free(shellcode);
        return 1;
    }
    fclose(fp);

    if (encryptionMode) {
        key = (unsigned char*)argv[3];
        keySize = strlen((char*)key);
    }

    if (strcmp(mode, "mac") == 0) {
        PrintBanner(mode);
        GenerateMacOutput(shellcode, shellcodeSize);
    }
    else if (strcmp(mode, "ipv4") == 0) {
        PrintBanner(mode);
        GenerateIpv4Output(shellcode, shellcodeSize);
    }
    else if (strcmp(mode, "ipv6") == 0) {
        PrintBanner(mode);
        GenerateIpv6Output(shellcode, shellcodeSize);
    }
    else if (strcmp(mode, "uuid") == 0) {
        PrintBanner(mode);
        GenerateUuidOutput(shellcode, shellcodeSize);
    }
    else if (strcmp(mode, "aes") == 0) {
        PrintBanner(mode);
        struct AES_ctx ctx;
        uint8_t pKey[32];
        uint8_t pIv[16];

        srand((unsigned int)time(NULL));
        GenerateRandomBytes(pKey, sizeof(pKey));
        GenerateRandomBytes(pIv, sizeof(pIv));

        printf("AES Key (hex):\n");
        PrintHexData("Key", pKey, sizeof(pKey));
        printf("\nAES IV (hex):\n");
        PrintHexData("IV", pIv, sizeof(pIv));

        AES_init_ctx_iv(&ctx, pKey, pIv);

        uint8_t* PaddedBuffer = NULL;
        size_t PaddedSize = 0;

        if (shellcodeSize % AES_BLOCKLEN != 0) {
            PaddBuffer16(shellcode, shellcodeSize, &PaddedBuffer, &PaddedSize);
            if (PaddedBuffer) {
                AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PaddedSize);
                if (outputFile) {
                    FILE* outFile = fopen(outputFile, "wb");
                    if (outFile) {
                        fwrite(PaddedBuffer, 1, PaddedSize, outFile);
                        fclose(outFile);
                    }
                    else {
                        printf("Error writing to output file!\n");
                    }
                }
                else {
                    PrintHexData("CipherText", PaddedBuffer, PaddedSize);
                }
                HeapFree(GetProcessHeap(), 0, PaddedBuffer);
            }
        }
        else {
            AES_CBC_encrypt_buffer(&ctx, shellcode, shellcodeSize);
            if (outputFile) {
                FILE* outFile = fopen(outputFile, "wb");
                if (outFile) {
                    fwrite(shellcode, 1, shellcodeSize, outFile);
                    fclose(outFile);
                }
                else {
                    printf("Error writing to output file!\n");
                }
            }
            else {
                PrintHexData("AES_Encrypted", shellcode, shellcodeSize);
            }
        }
    }
    else if (strcmp(mode, "rc4") == 0) {
        PrintBanner(mode);
        Rc4EncryptionViaSystemFunc032(key, shellcode, keySize, shellcodeSize);
        PrintHexData("RC4_Encrypted", shellcode, shellcodeSize);
    }
    else if (strcmp(mode, "xor") == 0) {
        PrintBanner(mode);
        XorByInputKey(shellcode, shellcodeSize, key, keySize);
        PrintHexData("XOR_Encrypted", shellcode, shellcodeSize);
    }
    else {
        printf("Invalid mode specified.\n");
        PrintUsage();
        free(shellcode);
        return 1;
    }

    free(shellcode);
    return 0;
}
