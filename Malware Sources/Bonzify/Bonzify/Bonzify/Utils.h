#include <Windows.h>

#define MemeAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define MemeFree(handle) HeapFree(GetProcessHeap(), 0, handle);

LPTSTR ExpandPath(LPCTSTR path);
BOOL CreateDirs(LPCTSTR path, BOOL isfile);

#define RunFileEx(path, args, dir, wait) RunFileExFlags(path, args, NULL, wait, 0)
#define RunFileWithArgs(path, args) RunFileEx(path, args, NULL, FALSE)
#define RunFileSimple(path) RunFileEx(path, NULL, NULL, FALSE)

#define RunFileWaitEx(path, args, dir) RunFileEx(path, args, dir, TRUE)
#define RunFileWaitWithArgs(path, args) RunFileEx(path, args, NULL, TRUE)
#define RunFileWaitSimple(path) RunFileEx(path, NULL, NULL, TRUE)

HANDLE RunFileExFlags(LPCTSTR path, LPTSTR args, LPCTSTR dir, BOOL wait, DWORD flags);

int GetPIDFromProcessName(LPTSTR name);
BOOL KillProcessByName(LPTSTR name);
BOOL KillProcessByID(DWORD pid);

#define SaveBufferNormal(path, data, size) SaveBuffer(path, data, size, FILE_ATTRIBUTE_NORMAL)
#define SaveBufferHidden(path, data, size) SaveBuffer(path, data, size, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)
BOOL SaveBuffer(LPCTSTR path, LPVOID data, DWORD size, DWORD attributes);

#define SaveResourceNormal(name, path) SaveResource((LPTSTR)name, TEXT("data"), path, FILE_ATTRIBUTE_NORMAL)
#define SaveResourceHidden(name, path) SaveResource((LPTSTR)name, TEXT("data"), path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
BOOL SaveResource(LPCTSTR name, LPCTSTR type, LPCTSTR path, DWORD attributes);

int random();
DWORD64 randomLong();
size_t randomSizeT();

BOOL endsWith(LPCTSTR str, LPCTSTR end);

void *memeset(void *data, int value, size_t length);
#pragma intrinsic(memeset)
#define memset memeset

size_t CorruptMemory(byte *data, size_t length, int chance);