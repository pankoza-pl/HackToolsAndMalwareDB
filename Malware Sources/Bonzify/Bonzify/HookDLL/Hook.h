#pragma once

#define OEMRESOURCE
#include <Windows.h>

extern HINSTANCE dllHandle;
extern LPWSTR dllFileName;

typedef struct {
	char *originalDLL;
	char *originalName;

	LPVOID hookProc;

	LPVOID backup;
} HOOK, *PHOOK;

#define DefineHook(func, dll, ret, ...) \
	typedef ret ## (__stdcall * ## func ## _HookType)(__VA_ARGS__); \
	ret __stdcall func ## _HookFunc (__VA_ARGS__); \
	HOOK func ## _Hook = { #dll, #func, func ## _HookFunc }; \
	ret __stdcall func ## _HookFunc (__VA_ARGS__)

#define CallHook(func, ...) ((func ## _HookType)func ## _Hook.backup)(__VA_ARGS__);