#ifndef RC4_H
#define RC4_H

#include <windows.h>

// Function to encrypt shellcode using rc4
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);

#endif

