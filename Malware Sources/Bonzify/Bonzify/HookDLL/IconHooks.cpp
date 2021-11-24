#include "IconHooks.h"
#include "resource.h"

// LoadIconW Hook
DefineHook(LoadIconW, USER32.dll, HICON, HINSTANCE instance, LPCWSTR iconName) {
	return CallHook(LoadIconW, dllHandle, MAKEINTRESOURCEW(IDI_BONZI));
}

// LoadImageW Hook
DefineHook(LoadImageW, USER32.dll, HANDLE, HINSTANCE hinst, LPCWSTR lpszName, UINT uType, int cxDesired, int cyDesired, UINT fuLoad) {
	if (uType == IMAGE_ICON)
		return CallHook(LoadImageW, dllHandle, MAKEINTRESOURCEW(IDI_BONZI), uType, cxDesired, cyDesired, fuLoad & ~LR_LOADFROMFILE);

	return CallHook(LoadImageW, hinst, lpszName, uType, cxDesired, cyDesired, fuLoad);
}

// ExtractIconExW Hook
DefineHook(ExtractIconExW, SHELL32.dll, UINT, LPCWSTR file, int index, HICON *largeIcons, HICON *smallIcons, UINT nIcons) {
	return CallHook(ExtractIconExW, dllFileName, 0, largeIcons, smallIcons, nIcons);
}

// PrivateExtractIconsW Hook
DefineHook(PrivateExtractIconsW, USER32.dll, UINT, LPCWSTR file, int index, int cx, int cy, HICON *icon, UINT *iconid, UINT nIcons, UINT flags) {
	return CallHook(PrivateExtractIconsW, dllFileName, 0, cx, cy, icon, iconid, nIcons, flags);
}

// ExtractAssociatedIconW Hook
DefineHook(ExtractAssociatedIconW, USER32.dll, HICON, HINSTANCE hInst, LPWSTR lpIconPath, WORD *lpIcon) {
	*lpIcon = 0;
	return CallHook(ExtractAssociatedIconW, hInst, dllFileName, lpIcon);
}