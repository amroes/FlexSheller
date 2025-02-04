#include <stdio.h>
#include <windows.h>
#include "xor.h"

VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bkey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j > sKeySize) {
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bkey[j];
	}
}

