#include <Windows.h>

const IID IID_IAgentEx = {0x48D12BA0, 0x5B77, 0x11d1, {0x9E, 0xC1, 0x00, 0xC0, 0x4F, 0xD7, 0x08, 0x1F}};
const CLSID CLSID_AgentServer = {0xD45FD2FC, 0x5C6E, 0x11D1, {0x9E, 0xC1, 0x00, 0xC0, 0x4F, 0xD7, 0x08, 0x1F}};

// Inspired by https://www.codeproject.com/Articles/34998/MS-Office-OLE-Automation-Using-C
HRESULT RunOLE(int type, IDispatch* id, VARIANT *result, LPOLESTR name, int args...) {
	va_list vargs;
	va_start(vargs, args);

	DISPPARAMS dp = { 0 };

	DISPID dispID = { 0 };
	HRESULT hr = id->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &dispID);

	VARIANT *xargs = (VARIANT*)LocalAlloc(LMEM_ZEROINIT, (args + 1) * sizeof(VARIANT));
	for (int i = 0; i < args; i++) {
		xargs[i] = va_arg(vargs, VARIANT);
	}

	dp.cArgs = args;
	dp.rgvarg = xargs;

	if (type & DISPATCH_PROPERTYPUT) {
		dp.cNamedArgs = 1;
		DISPID dispIDPut = DISPID_PROPERTYPUT;
		dp.rgdispidNamedArgs = &dispIDPut;
	}

	hr = id->Invoke(dispID, IID_NULL, LOCALE_SYSTEM_DEFAULT, type, &dp, result, NULL, NULL);
	va_end(vargs);

	return hr;
}

static IDispatch *character = NULL;
static long characterID = 0;
static IDispatch *agentServer = nullptr;

void Bonzi_Init() {
	CoInitialize(NULL);

	// Start the MS Agent Server
	CoCreateInstance(CLSID_AgentServer, NULL, CLSCTX_SERVER, IID_IAgentEx, (void**)&agentServer);

	VARIANT bonziFile = { 0 };
	bonziFile.vt = VT_BSTR;
	bonziFile.bstrVal = SysAllocString(L"Bonzi.acs");

	VARIANT charID = { 0 };
	charID.vt = VT_I4 | VT_BYREF;
	charID.plVal = &characterID;

	VARIANT requestID = { 0 };
	requestID.vt = VT_I4 | VT_BYREF;
	static long rid = 0;
	requestID.plVal = &rid;

	HRESULT res;
	res = RunOLE(DISPATCH_METHOD, agentServer, NULL, L"Load", 3, requestID, charID, bonziFile);

	VARIANT charStruct = { 0 };
	charStruct.vt = VT_DISPATCH | VT_BYREF;
	charStruct.ppdispVal = &character;

	charID = { 0 };
	charID.vt = VT_I4;
	charID.lVal = characterID;

	VARIANT result = { 0 };

	res = RunOLE(DISPATCH_METHOD, agentServer, &result, L"GetCharacterEx", 2, charStruct, charID);

	VARIANT vtBool = { 0 };
	vtBool.vt = VT_BOOL;
	vtBool.boolVal = false;

	res = RunOLE(DISPATCH_METHOD, character, &result, L"Show", 2, requestID, vtBool);
}

void Bonzi_Speak(LPWSTR message) {
	if (agentServer == nullptr)
		Bonzi_Init();

	BSTR bmsg = SysAllocString(message);

	VARIANT msg = { 0 };
	msg.vt = VT_BSTR;
	msg.bstrVal = bmsg;

	VARIANT useless = { 0 };
	msg.vt = VT_BSTR;

	VARIANT requestID = { 0 };
	requestID.vt = VT_I4 | VT_BYREF;
	static long rid = 0;
	requestID.plVal = &rid;

	HRESULT res = RunOLE(DISPATCH_METHOD, character, NULL, L"Speak", 3, requestID, useless, msg);

	SysFreeString(bmsg);
}