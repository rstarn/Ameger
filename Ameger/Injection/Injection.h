#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

// The injection flags, the INJECTIONDATA{A,W}/MEMORY_INJECTIONDATA payloads and
// the exported entry points are defined once in the outer header
// (Ameger/Injection.h) so the host and the runtime cannot drift apart. This
// header adds only the runtime internals that are not part of the exported ABI.
#include "../Injection.h"

DWORD __stdcall InjectA(INJECTIONDATAA * pData);
DWORD __stdcall InjectW(INJECTIONDATAW * pData);

DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData);

DWORD __stdcall GetSymbolState();

DWORD __stdcall GetImportState();

struct INJECTIONDATA_INTERNAL
{
	std::wstring	DllPath;
	std::wstring	TargetProcessExeFileName;

	BYTE *			RawData;
	DWORD			RawSize;

	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	ULONG_PTR		hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;
	DWORD			TargetTid;
	ULONG_PTR		hThreadHandleValue;

	INJECTIONDATA_INTERNAL(const INJECTIONDATAA			* pData);
	INJECTIONDATA_INTERNAL(const INJECTIONDATAW			* pData);
	INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA	* pData);
};

DWORD __stdcall Inject_Internal(INJECTIONDATA_INTERNAL * pData);
