#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Core/Utility/PE/PEImage.h"
#include "NT/NTDefinitions.h"

#include "NT/NTFunctions.h"

#define ALIGN_UP(X, A) ((((ULONG_PTR)(X)) + ((ULONG_PTR)(A) - 1)) & (~(((ULONG_PTR)(A)) - 1)))

#define MAXPATH_IN_TCHAR	(MAX_PATH)

inline HINSTANCE g_hInjMod = NULL;

struct ERROR_INFO
	
{
	std::wstring	DllFileName;
	std::wstring	TargetProcessExeFileName;
	DWORD			TargetProcessId;
	INJECTION_MODE	InjectionMode;
	LAUNCH_METHOD	LaunchMethod;
	DWORD			Flags;
	DWORD			ErrorCode;
	DWORD			AdvErrorCode;
	ULONG_PTR		HandleValue;
	int				bNative;
	std::wstring	SourceFile;
	std::wstring	FunctionName;
	int				Line;

	
	BYTE *	RawData;
	DWORD	RawSize;
};

struct INJECTION_SOURCE
{
	std::wstring DllPath;

	BYTE *	RawData		= nullptr;
	DWORD	RawSize		= 0;
	bool	FromMemory	= false;
};

inline std::wstring	g_RootPathW;

inline DWORD g_OSVersion = 0;
inline DWORD g_OSBuildNumber = 0;

// Build-number constants. They label a Windows build for logging/version
// display only; none of the Windows 10 (or earlier) values can be selected as
// a runtime layout - the entry gate rejects every build below 22000 (Win11
// 21H2), so GetSupportedWindowsLayout always resolves to a Win11 family.
#define g_Windows10_1607 14393
#define g_Windows11_21H2 22000
#define g_Windows11_22H2 22621
#define g_Windows11_23H2 22631
#define g_Windows11_24H2 26100
#define g_Windows11_25H2 26200

enum class WINDOWS_LAYOUT_FAMILY
{
	Windows11_21H2,
	Windows11_22H2,
	Windows11_24H2,
	Windows11_25H2
};

DWORD GetOSVersion(DWORD * error_code = nullptr);

DWORD GetOSBuildVersion();

bool GetSupportedWindowsLayout(DWORD build_number, WINDOWS_LAYOUT_FAMILY & layout_family);

bool FileExistsW(const std::wstring & FilePath);

DWORD ValidateDllFile(const std::wstring & FilePath, DWORD target_machine, DWORD flags = 0);

DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine, DWORD flags = 0);

bool GetOwnModulePathW(std::wstring & out);

// Per-user cache root for the downloaded ntdll PDB. Deliberately NOT the
// module's own directory: a multi-megabyte ntdll.pdb appearing next to the
// injector is a loud, timestamped on-disk artifact. Neutral name under
// %LOCALAPPDATA% so nothing in the path names the tool or its purpose.
bool GetSymbolCacheRoot(std::wstring & out);

bool IsNativeProcess(HANDLE hTargetProc, DWORD * error_code = nullptr);

void ErrorLog(const ERROR_INFO & info);

std::wstring CharArrayToStdWstring(const char * szString);

void __stdcall StartDownload();

DWORD CreateTempFileCopy(std::wstring & FilePath, DWORD & win32err);

DWORD ScrambleFileName(std::wstring & FilePath, UINT Length, DWORD & win32err);

