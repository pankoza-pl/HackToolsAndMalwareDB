#include <Windows.h>

#include "../Bonzify/Utils.h"
#include "Payloads.h"

DWORD WINAPI msgBoxThread(LPVOID parameter);
LRESULT CALLBACK msgBoxHook(int nCode, WPARAM wParam, LPARAM lParam);
DWORD WINAPI closeWindowThread(LPVOID parameter);

DWORD WINAPI MsgBoxSpamThread(LPVOID parameter) {
	for (;;) {
		Sleep(random() % 20000 + 10000);
		CreateThread(NULL, NULL, msgBoxThread, NULL, 0, NULL);
	}
}

const LPTSTR messages[] = {
	TEXT("\"Lemon\" mixed with \"milk\""),
	TEXT("Vinesauce is my favourite Anime"),
	TEXT("Expand Dong"),
	TEXT("It's hip to fuck Bees"),
	TEXT("Succ is Dead"),
	TEXT("It's magic Joel, it's magic!"),
	TEXT("What did the beaver say to the tree?\r\n\r\nIt's been nice gnawing you!"),
	TEXT("Windows Vista is my favourite OS."),
	TEXT("uhhh yeeees"),
	TEXT("No Succ"),
	TEXT("Windows is in Danger"),
};

const size_t msgCount = sizeof(messages) / sizeof(LPTSTR);

DWORD WINAPI msgBoxThread(LPVOID parameter) {
	HHOOK hook = SetWindowsHookEx(WH_CBT, msgBoxHook, 0, GetCurrentThreadId());

	DWORD msg = 0;
	msg += random() % 7;           // Random buttons
	msg += (random() % 5) << 4;    // Random icon

	MessageBox(NULL, messages[random() % msgCount], TEXT("Bonzify"), msg);
	UnhookWindowsHookEx(hook);

	return 0;
}

DWORD WINAPI closeWindowThread(LPVOID parameter) {
	Sleep(random() % 4000 + 2000);
	DestroyWindow((HWND)parameter);

	return 0;
}

LRESULT CALLBACK msgBoxHook(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HCBT_CREATEWND) {
		CREATESTRUCT *pcs = ((CBT_CREATEWND *)lParam)->lpcs;

		if ((pcs->style & WS_DLGFRAME) || (pcs->style & WS_POPUP)) {
			HWND hwnd = (HWND)wParam;

			CreateThread(NULL, 0, closeWindowThread, hwnd, 0, NULL);

			int x = random() % (GetSystemMetrics(SM_CXSCREEN) - pcs->cx);
			int y = random() % (GetSystemMetrics(SM_CYSCREEN) - pcs->cy);

			pcs->x = x;
			pcs->y = y;
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}