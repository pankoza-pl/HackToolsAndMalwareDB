#include <Windows.h>
#include "Hook.h"

extern HOOK MessageBoxW_Hook;
extern HOOK LoadStringW_Hook;
extern HOOK DrawTextW_Hook;
extern HOOK SetWindowTextW_Hook;
extern HOOK CreateWindowExW_Hook;
extern HOOK FormatMessageW_Hook;