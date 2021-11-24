#include <Windows.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <TlHelp32.h>

#include "Utils.h"

// TODO Split Utils into multiple files

// Expand Don...
// Path.
LPTSTR ExpandPath(LPCTSTR path) {
	if (path == NULL)
		return NULL;

	LPTSTR resolvedPath = (LPTSTR)MemeAlloc(MAX_PATH * sizeof(TCHAR));
	ExpandEnvironmentStrings(path, resolvedPath, MAX_PATH);

	LPTSTR fullName = (LPTSTR)MemeAlloc(MAX_PATH * sizeof(TCHAR));
	GetFullPathName(resolvedPath, MAX_PATH, fullName, NULL);

	MemeFree(resolvedPath);

	return fullName;
}

BOOL CreateDirs(LPCTSTR path, BOOL isfile) {
	if (path == NULL)
		return FALSE;

	LPTSTR newPath = (LPTSTR)MemeAlloc(MAX_PATH * sizeof(TCHAR));
	lstrcpy(newPath, path);

	if (isfile)
		PathRemoveFileSpec(newPath);

	int result = SHCreateDirectoryEx(NULL, newPath, NULL);
	SetLastError(result);

	MemeFree(newPath);

	// Return true even if it already exists
	// TODO Fix this for OS drives
	return result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS || result == ERROR_FILE_EXISTS;
}

HANDLE RunFileExFlags(LPCTSTR path, LPTSTR args, LPCTSTR dir, BOOL wait, DWORD flags) {
	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);

	PROCESS_INFORMATION pinfo;
	if (!CreateProcess(path, args, NULL, NULL, TRUE, flags, NULL, dir, &sinfo, &pinfo))
		return NULL;

	if (wait) {
		WaitForSingleObject(pinfo.hProcess, INFINITE);
		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);
	}

	return pinfo.hProcess;
}

int GetPIDFromProcessName(LPTSTR name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);

	BOOL hasNext = Process32First(snapshot, &procEntry);

	while (hasNext) {
		if (lstrcmpi(procEntry.szExeFile, name) == 0) {
			return procEntry.th32ProcessID;
		}

		hasNext = Process32Next(snapshot, &procEntry);
	}

	return -1;
}

BOOL KillProcessByName(LPTSTR name) {
	int pid = GetPIDFromProcessName(name);

	if (pid == -1)
		return FALSE;

	return KillProcessByID(pid);
}

BOOL KillProcessByID(DWORD pid) {
	HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	return TerminateProcess(proc, 0);
}

BOOL SaveBuffer(LPCTSTR path, LPVOID data, DWORD size, DWORD attributes) {
	LPTSTR outPath = ExpandPath(path);
	CreateDirs(outPath, true);

	HANDLE file = CreateFile(outPath, GENERIC_WRITE, 0,
		NULL, CREATE_ALWAYS, attributes, 0);

	if (file == INVALID_HANDLE_VALUE)
		return FALSE;

	MemeFree(outPath);

	DWORD written = 0;
	if (!WriteFile(file, data, size, &written, NULL)) {
		CloseHandle(file);
		return FALSE;
	}

	CloseHandle(file);
	return TRUE;
}

BOOL SaveResource(LPCTSTR name, LPCTSTR type, LPCTSTR path, DWORD attributes) {
	HRSRC resource = FindResource(NULL, name, type);
	if (resource == NULL)
		return FALSE;

	HGLOBAL resPointer = LoadResource(NULL, resource);

	DWORD resSize = SizeofResource(NULL, resource);
	LPVOID resData = LockResource(resPointer);
	if (resData == NULL)
		return FALSE;

	return SaveBuffer(path, resData, resSize, attributes);
}

//static void initProv();

HCRYPTPROV prov;
static void initProv() {
	if (prov == NULL)
		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT))
			ExitProcess(1);
}

int random() {
	initProv();

	int out;
	CryptGenRandom(prov, sizeof(out), (BYTE*)&out);
	return out & 0x7fffffff;
}

DWORD64 randomLong() {
	initProv();

	DWORD64 out;
	CryptGenRandom(prov, sizeof(out), (BYTE*)&out);
	return out;
}

size_t randomSizeT() {
	initProv();

	size_t out;
	CryptGenRandom(prov, sizeof(out), (BYTE*)&out);
	return out;
}

BOOL endsWith(LPCTSTR str, LPCTSTR end) {
	int originalLen = lstrlen(str);
	int endLen = lstrlen(end);

	if (endLen > originalLen)
		return FALSE;

	return lstrcmpi(str + originalLen - endLen, end) == 0;
}

void *memeset(void *data, int value, size_t length) {
	BYTE* bytes = (BYTE*)data;

	while (length--)
		*bytes++ = (BYTE)value;

	return data;
}

size_t CorruptMemory(byte *data, size_t length, int chance) {
	size_t corrupted = 0;

	for (size_t i = 0; i < length; i++) {
		if (random() % chance == 0) {
			int operation = random() % 2;

			if (operation == 0) {
				data[i]--;
			} else {
				data[i]++;
			}

			corrupted++;
		}
	}

	return corrupted;
}