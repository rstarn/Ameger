#pragma once

#define AMEGER_INJ_MOD_NAME64W L"Ameger Injector - x64.dll"
#define AMEGER_INJ_MOD_NAME64A "Ameger Injector - x64.dll"

#define AMEGER_INJ_MOD_NAMEW AMEGER_INJ_MOD_NAME64W
#define AMEGER_INJ_MOD_NAMEA AMEGER_INJ_MOD_NAME64A

#if defined(UNICODE) || defined(_UNICODE)
#define AMEGER_INJ_MOD_NAME AMEGER_INJ_MOD_NAMEW
#else
#define AMEGER_INJ_MOD_NAME AMEGER_INJ_MOD_NAMEA
#endif

#include <Windows.h>
#include "Core/Foundation/Primitives/InjectionTypes.h"

struct INJECTIONDATAA
{
	char			szDllPath[MAX_PATH * 2];	
	DWORD			ProcessID;					
	INJECTION_MODE	Mode;						
	LAUNCH_METHOD	Method;						
	DWORD			Flags;						
	DWORD			Timeout;					
	ULONG_PTR		hHandleValue;				
	HINSTANCE		hDllOut;					
	bool			GenerateErrorLog;			
	DWORD			TargetTid;					// pre-selected victim thread (0 = runtime picks)
	ULONG_PTR		hThreadHandleValue;			// sponsor thread handle (0 = none)
};

struct INJECTIONDATAW
{
	wchar_t			szDllPath[MAX_PATH * 2];
	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	ULONG_PTR		hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;
	DWORD			TargetTid;					// pre-selected victim thread (0 = runtime picks)
	ULONG_PTR		hThreadHandleValue;			// sponsor thread handle (0 = none)
};

struct MEMORY_INJECTIONDATA
{
	BYTE * RawData;
	DWORD RawSize;
	DWORD ProcessID;
	INJECTION_MODE Mode;
	LAUNCH_METHOD Method;
	DWORD Flags;
	DWORD Timeout;
	ULONG_PTR hHandleValue;
	HINSTANCE hDllOut;
	bool GenerateErrorLog;
	DWORD TargetTid;				// pre-selected victim thread (0 = runtime picks)
	ULONG_PTR hThreadHandleValue;	// sponsor thread handle (0 = none)
};

#if defined(UNICODE) || defined(_UNICODE)
#define INJECTIONDATA INJECTIONDATAW
#else
#define INJECTIONDATA INJECTIONDATAA
#endif

#define INJ_ERASE_HEADER				0x0001	
// Bit 0x0002 is retired (was INJ_FAKE_HEADER). Do not reuse: a stale caller may
// still pass it and a silent meaning change would be a surprise.
#define INJ_NO_DONOR_SCAN				0x0004	// sponsor-only acquisition; skip the foreign-donor scan
// Bit 0x0008 is retired (was INJ_NO_DIRECT_FALLBACK). Do not reuse: with
// INJ_HANDLE_HIJACKING set, acquisition is now always stealth-only and fails
// closed when no donor qualifies, so there is no direct OpenProcess/OpenThread
// fallback left to disable.
#define INJ_SCRAMBLE_DLL_NAME			0x0010	
#define INJ_LOAD_DLL_COPY				0x0020	
#define INJ_SKIP_SPONSOR_ROUNDTRIP		0x0080	// skip the sponsor alloc/write/read/release proof
// INJ_HANDLE_HIJACKING lives in Core/Foundation/Primitives/InjectionTypes.h.

#define INJ_MM_CLEAN_DATA_DIR			0x00010000	
#define INJ_MM_RESOLVE_IMPORTS			0x00020000	
#define INJ_MM_RESOLVE_DELAY_IMPORTS	0x00040000	
#define INJ_MM_EXECUTE_TLS				0x00080000	
#define INJ_MM_ENABLE_EXCEPTIONS		0x00100000	
#define INJ_MM_SET_PAGE_PROTECTIONS		0x00200000	
#define INJ_MM_INIT_SECURITY_COOKIE		0x00400000	
#define INJ_MM_RUN_DLL_MAIN				0x00800000	
								
#define INJ_MM_RUN_UNDER_LDR_LOCK		0x01000000	
// Bit 0x02000000 is retired (was INJ_MM_SHIFT_MODULE_BASE). Do not reuse.
#define INJ_MM_MAP_FROM_MEMORY		0x04000000
// Bit 0x08000000 is retired (was INJ_MM_ENABLE_VEH, C++ EH VEH shim). Do not
// reuse: VEH chain entries are the hottest Warden walk surface, so the shim
// was removed entirely. SEH (0x00100000) is inverted table +
// RtlAddFunctionTable + fake dir only, with zero VEH handlers.

#define MM_DEFAULT (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RESOLVE_DELAY_IMPORTS | INJ_MM_INIT_SECURITY_COOKIE | INJ_MM_EXECUTE_TLS | INJ_MM_ENABLE_EXCEPTIONS | INJ_MM_RUN_DLL_MAIN | INJ_MM_SET_PAGE_PROTECTIONS | INJ_MM_RUN_UNDER_LDR_LOCK)

// Last handle-acquisition outcome (HijackSource / HijackStats live in
// Core/Foundation/Primitives/InjectionTypes.h, included above).

using f_InjectA = DWORD(__stdcall*)(INJECTIONDATAA * pData);
using f_InjectW = DWORD(__stdcall*)(INJECTIONDATAW * pData);
using f_Memory_Inject = DWORD(__stdcall*)(MEMORY_INJECTIONDATA * pData);

using f_GetSymbolState = DWORD(__stdcall *)();
using f_GetImportState = DWORD(__stdcall *)();
using f_InitializeRuntime = DWORD(__stdcall *)();
using f_ShutdownRuntime = DWORD(__stdcall *)();

using f_StartDownload = void(__stdcall *)();
using f_GetLastHijackStats = void(__stdcall *)(HijackStats * ProcessOut, HijackStats * ThreadOut);
using f_GetLastMapStats = void(__stdcall *)(MAP_STATS * Out);
using f_GetLastStringStats = void(__stdcall *)(STRING_STATS * Out);
using f_GetLastThreadExecStats = void(__stdcall *)(THREAD_EXEC_STATS * Out);


using f_raw_print_callback = void(__stdcall *)(const char * szText);
using f_SetRawPrintCallback = DWORD(__stdcall *)(f_raw_print_callback callback);

DWORD __stdcall InitializeRuntime();
DWORD __stdcall ShutdownRuntime();
void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut);
void __stdcall GetLastMapStats(MAP_STATS * Out);
void __stdcall GetLastStringStats(STRING_STATS * Out);
void __stdcall GetLastThreadExecStats(THREAD_EXEC_STATS * Out);

// Zeroes the telemetry each getter above exposes. Call once at the start of an
// injection: the backing statics are process-wide and are only written on their
// success paths, so without this a run that fails early reports the previous
// run's outcome (e.g. a stale "thread context restored"). String stats are
// excluded - they are filled once at import-resolution time, not per injection.
void ResetHijackStats();
void ResetMapStats();
void ResetThreadExecStats();
