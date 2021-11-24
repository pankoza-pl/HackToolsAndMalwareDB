#include <Windows.h>

#include "../Bonzify/Utils.h"
#include "Payloads.h"

BOOL WINAPI EnumWindowProc(HWND hwnd, LPARAM parameter);

DWORD WINAPI HWNDFuckerThread(LPVOID parameter) {
	for (;;) {
		EnumChildWindows(GetDesktopWindow(), EnumWindowProc, NULL);

		Sleep(100);
	}
}

BOOL WINAPI EnumWindowProc(HWND hwnd, LPARAM parameter) {
	//LONG style = GetWindowLong(hwnd, GWL_STYLE);

	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid != GetCurrentProcessId())
		return TRUE;

	//Sleep(10);

	if (random() % 1000 == 0) {
		SetWindowLong(hwnd, GWL_STYLE, random());
		SetWindowLong(hwnd, GWL_EXSTYLE, random());
	}

	// A bit like Welcomer
	if (random() % 10 == 0) {
		RECT rekt;
		GetWindowRect(hwnd, &rekt);

		MapWindowPoints(HWND_DESKTOP, GetParent(hwnd), (LPPOINT)&rekt, 2);

		rekt.left += random() % 8 - 4;
		rekt.top += random() % 8 - 4;
		rekt.right += random() % 8 - 4;
		rekt.bottom += random() % 8 - 4;

		MoveWindow(hwnd, rekt.left, rekt.top, rekt.right - rekt.left, rekt.bottom - rekt.top, FALSE);
	}

	return TRUE;
}