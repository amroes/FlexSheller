#include <stdio.h>
#include <windows.h>
#include "rc4.h"

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} RC4USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct RC4USTRING* Data,
	struct RC4USTRING* Key
	);

/*
Helper function that calls SystemFunction032
* pRc4Key - The RC4 key use to encrypt/decrypt
* pPayloadData - The base address of the buffer to encrypt/decrypt
* dwRc4KeySize - Size of pRc4key (Param 1)
* sPayloadSize - Size of pPayloadData (Param 2)
*/
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS STATUS = NULL;

	RC4USTRING Data = {
		.Buffer = pPayloadData,
		.Length = sPayloadSize,
		.MaximumLength = sPayloadSize
	};

	RC4USTRING	Key = {
		.Buffer = pRc4Key,
		.Length = dwRc4KeySize,
		.MaximumLength = dwRc4KeySize
	};
		fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
