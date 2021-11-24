#include "StringHooks.h"
#include "resource.h"

extern HINSTANCE dllHandle;

// MessageBoxW Hook
DefineHook(MessageBoxW, USER32.dll, int, HWND hwnd, LPCWSTR text, LPCWSTR caption, UINT type) {
	return CallHook(MessageBoxW, hwnd, L"Bonzi Rulez", L"BONZI", type);
}

// LoadStringW Hook
DefineHook(LoadStringW, USER32.dll, int, HINSTANCE instance, UINT uid, LPWSTR buffer, int maxlen) {
	return CallHook(LoadStringW, dllHandle, IDS_BONZI, buffer, maxlen);
}

// DrawTextW Hook
DefineHook(DrawTextW, USER32.dll, int, HDC hdc, LPCWSTR text, int txtlen, LPRECT rect, UINT format) {
	LPCWSTR x = L"Hello, Expand Dong";
	return CallHook(DrawTextW, hdc, x, lstrlenW(x), rect, format);
}

// SetWindowTextW Hook
DefineHook(SetWindowTextW, USER32.dll, BOOL, HWND hwnd, LPCWSTR str) {
	return CallHook(SetWindowTextW, hwnd, L"Bonzai Buhdy");
}

// CreateWindowExW Hook
DefineHook(CreateWindowExW, USER32.dll, HWND, DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
	return CallHook(CreateWindowExW, dwExStyle, lpClassName, L"Succ Me", dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

// FormatMessageW Hook
DefineHook(FormatMessageW, KERNEL32.dll, DWORD, DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments) {
	return CallHook(FormatMessageW, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments);
}