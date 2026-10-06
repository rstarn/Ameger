#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Utility/Tools/Tools.h"
#include "Injection.h"
#include "System/Import/ImportHandler.h"

#include <bcrypt.h>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

namespace
{

SRWLOCK g_ErrorLogLock = SRWLOCK_INIT;
}

namespace
{
	INIT_ONCE g_OSVersionInitOnce = INIT_ONCE_STATIC_INIT;

	BOOL CALLBACK InitOSVersionOnce(PINIT_ONCE, PVOID parameter, PVOID *)
	{
		DWORD * error_code = static_cast<DWORD *>(parameter);

		// No PEB/TEB offsets here: version comes from RtlGetVersion (ntdll
		// export, no struct layout needed) instead of __readgsqword(0x60) +
		// hardcoded PEB field offsets. Fully dynamic, no per-build constants.
		auto ntdll_name = XOR_STR_W(L"ntdll.dll");
		HMODULE hNtdll = GetModuleHandleW(ntdll_name.get());
		if (!hNtdll)
		{
			if (error_code)
			{
				*error_code = INJ_ERR_GET_MODULE_HANDLE_FAIL;
			}
			return FALSE;
		}
		auto rtlver_name = XOR_STR_A("RtlGetVersion");
		using f_RtlGetVersion = LONG(NTAPI *)(PRTL_OSVERSIONINFOW);
		auto pRtlGetVersion = ReCa<f_RtlGetVersion>(GetProcAddress(hNtdll, rtlver_name.get()));
		if (!pRtlGetVersion)
		{
			if (error_code)
			{
				*error_code = INJ_ERR_GET_PROC_ADDRESS_FAIL;
			}
			return FALSE;
		}
		RTL_OSVERSIONINFOW ver{};
		ver.dwOSVersionInfoSize = sizeof(ver);
		if (pRtlGetVersion(&ver) != 0)
		{
			if (error_code)
			{
				*error_code = INJ_ERR_WINDOWS_VERSION;
			}
			return FALSE;
		}

		DWORD v_hi = ver.dwMajorVersion;
		DWORD v_lo = ver.dwMinorVersion;

		for (; v_lo >= 10; v_lo /= 10);

		g_OSVersion = v_hi * 10 + v_lo;
		g_OSBuildNumber = ver.dwBuildNumber;

		return TRUE;
	}
}

DWORD GetOSVersion(DWORD * error_code)
{
	DWORD init_error = 0;
	if (!InitOnceExecuteOnce(&g_OSVersionInitOnce, InitOSVersionOnce, error_code ? error_code : &init_error, nullptr))
	{
		return 0;
	}

	return g_OSVersion;
}

DWORD GetOSBuildVersion()
{
	if (g_OSBuildNumber == 0)
	{
		GetOSVersion();
	}

	return g_OSBuildNumber;
}

bool GetSupportedWindowsLayout(DWORD build_number, WINDOWS_LAYOUT_FAMILY & layout_family)
{
	// 22H2 (22621) and 23H2 (22631) share the same ntdll/loader layout
	// (23H2 is a 22H2 enablement package), so they map to one family.
	// 24H2 (26100) and 25H2 (26200) are likewise layout-compatible within
	// their ranges. Exact-equality matching broke every 23H2 machine
	// (the most common Win11 gaming build) with INJ_ERR_WINDOWS_BUILD_UNSUPPORTED
	// (0x4E), which the UI then misreported as "Failed to load symbols".
	// Match by range and forward-map newer builds to the latest known family
	// instead of failing closed on each feature update.
	bool supported = true;

	if (build_number >= 26200)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_25H2;
		if (build_number != g_Windows11_25H2)
		{
			LOG(1, "Forward-mapped Windows build %lu to 25H2 layout (known RTM %lu); recalibrate if loader drifts\n",
				static_cast<unsigned long>(build_number), static_cast<unsigned long>(g_Windows11_25H2));
		}
	}
	else if (build_number >= 26100)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_24H2;
		if (build_number != g_Windows11_24H2)
		{
			LOG(1, "Forward-mapped Windows build %lu to 24H2 layout (known RTM %lu); recalibrate if loader drifts\n",
				static_cast<unsigned long>(build_number), static_cast<unsigned long>(g_Windows11_24H2));
		}
	}
	else if (build_number >= 22621 && build_number < 23000)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_22H2;
		if (build_number != g_Windows11_22H2 && build_number != g_Windows11_23H2)
		{
			LOG(1, "Forward-mapped Windows build %lu to 22H2/23H2 layout; recalibrate if loader drifts\n",
				static_cast<unsigned long>(build_number));
		}
	}
	else if (build_number >= 22000 && build_number < 22621)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
		if (build_number != g_Windows11_21H2)
		{
			LOG(1, "Forward-mapped Windows build %lu to 21H2 layout; recalibrate if loader drifts\n",
				static_cast<unsigned long>(build_number));
		}
	}
	else
	{
		supported = false;
	}

	return supported;
}

bool FileExistsW(const std::wstring & FilePath)
{
	const DWORD attributes = GetFileAttributesW(FilePath.c_str());
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

DWORD ValidateDllFile(const std::wstring & FilePath, DWORD target_machine, DWORD flags)
{
	std::ifstream file(FilePath, std::ios::binary | std::ios::ate);
	if (!file.good())
	{
		LOG(1, "Can't open file\n");

		return FILE_ERR_CANT_OPEN_FILE;
	}

	const std::streamoff file_size = file.tellg();
	if (file_size <= 0)
	{
		LOG(1, "Specified file is too small\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}
	if (static_cast<unsigned long long>(file_size) > PE_IMAGE::MAX_IMAGE_SIZE)
	{
		LOG(1, "Specified file is too large\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	try
	{
		std::vector<BYTE> data(static_cast<size_t>(file_size));
		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<char *>(data.data()), file_size);
		if (!file || file.gcount() != file_size)
		{
			LOG(1, "Failed to read the complete file\n");

			return FILE_ERR_INVALID_FILE_SIZE;
		}

		PE_IMAGE::VIEW view;
		const DWORD validation_result = PE_IMAGE::Validate(data.data(), data.size(), target_machine, BuildPeValidationOptions(flags), view);
		if (validation_result != FILE_ERR_SUCCESS)
		{
			LOG(1, "PE validation failed: %08X\n", validation_result);
		}

		return validation_result;
	}
	catch (const std::bad_alloc &)
	{
		LOG(1, "Memory allocation failed\n");

		return FILE_ERR_MEMORY_ALLOCATION_FAILED;
	}
}

DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine, DWORD flags)
{
	if (!RawData || RawSize < sizeof(IMAGE_DOS_HEADER))
	{
		LOG(1, "Specified file is too small\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	PE_IMAGE::VIEW view;
	const DWORD validation_result = PE_IMAGE::Validate(RawData, RawSize, target_machine, BuildPeValidationOptions(flags), view);
	if (validation_result != FILE_ERR_SUCCESS)
	{
		LOG(1, "PE validation failed: %08X\n", validation_result);
	}

	return validation_result;
}

bool GetOwnModulePathW(std::wstring & out)
{
	wchar_t buffer[MAX_PATH * 2]{ 0 };
	DWORD mod_ret = GetModuleFileNameW(g_hInjMod, buffer, sizeof(buffer) / sizeof(wchar_t));
	if (!mod_ret || mod_ret >= sizeof(buffer) / sizeof(wchar_t))
	{
		return false;
	}

	std::wstring temp = buffer;
	auto pos = temp.find_last_of('\\');
	if (pos == std::wstring::npos)
	{
		return false;
	}

	out = temp.substr(0, pos + 1);

	return true;
}

bool GetSymbolCacheRoot(std::wstring & out)
{
	out.clear();

	wchar_t local_app_data[MAX_PATH]{ 0 };
	const DWORD length = GetEnvironmentVariableW(XOR_STR_W(L"LOCALAPPDATA").get(), local_app_data, MAX_PATH);
	if (!length || length >= MAX_PATH)
	{
		return false;
	}

	std::wstring root(local_app_data, length);
	if (root.back() != L'\\')
	{
		root += L'\\';
	}

	// Neutral, non-descriptive leaf: nothing in the path names the tool, the
	// target, or that it caches symbols. Created on demand. Both literals
	// are stack-decrypted so neither persists in .rdata.
	auto leaf = XOR_STR_W(L"LocalCache\\");
	root += leaf.get();

	const DWORD attributes = GetFileAttributesW(root.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES)
	{
		if (!CreateDirectoryW(root.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			return false;
		}
	}

	out = root;
	return true;
}

bool IsNativeProcess(HANDLE hTargetProc, DWORD * error_code)
{
	BOOL bWOW64 = FALSE;
	if (!IsWow64Process(hTargetProc, &bWOW64))
	{
		if (error_code)
		{
			*error_code = GetLastError();
		}

		return false;
	}

	if (error_code)
	{
		*error_code = ERROR_SUCCESS;
	}

	return !bWOW64;
}

// Stealth: no disk artifact. Failures stay in a volatile ring buffer
// (16 entries) and go to the debug callback only. Full DLL paths are
// reduced to basenames before storing so even a crash dump never holds
// absolute operator paths; PIDs never touch disk.
namespace
{
	constexpr size_t kErrorRingCapacity = 16;
	ERROR_INFO g_ErrorRing[kErrorRingCapacity]{};
	size_t g_ErrorRingHead = 0;
	size_t g_ErrorRingCount = 0;

	std::wstring BasenameOnly(const std::wstring & path)
	{
		const size_t slash = path.find_last_of(L"\\/");

		return slash == std::wstring::npos ? path : path.substr(slash + 1);
	}
}

void ErrorLog(const ERROR_INFO & info)
{
	ERROR_INFO redacted = info;
	redacted.DllFileName = BasenameOnly(info.DllFileName);
	// TargetProcessExeFileName is already a bare exe name (see
	// Inject_Internal QueryFullProcessImageNameW handling); keep as-is.
	// RawData pointer/size are kept in memory only for the live session.

	AcquireSRWLockExclusive(&g_ErrorLogLock);
	g_ErrorRing[g_ErrorRingHead] = redacted;
	g_ErrorRingHead = (g_ErrorRingHead + 1) % kErrorRingCapacity;
	if (g_ErrorRingCount < kErrorRingCapacity)
	{
		++g_ErrorRingCount;
	}
	ReleaseSRWLockExclusive(&g_ErrorLogLock);

	// Debug channel only (console/callback when the operator attaches one).
	// No PID, no full path, no file write.
	LOG(1, "Load failed: code=%08X adv=%08X flags=%08X mode=%d method=%d\n",
		info.ErrorCode, info.AdvErrorCode, info.Flags,
		static_cast<int>(info.InjectionMode), static_cast<int>(info.LaunchMethod));
}

std::wstring CharArrayToStdWstring(const char * szString)
{
	std::wstring out;
	if (szString)
	{
		const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szString, -1, nullptr, 0);
		if (required > 1)
		{
			out.assign(static_cast<size_t>(required) - 1, L'\0');
			// Same flag as the sizing call: without it the conversion silently
			// substitutes U+FFFD for invalid bytes, so a string that failed the
			// size probe could still yield a (corrupted) result here.
			if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szString, -1, out.data(), required))
			{
				out.clear();
			}
		}
	}

	return out;
}

void __stdcall StartDownload()
{
#pragma EXPORT_FUNCTION("CoreFetch", __FUNCDNAME__)

	const DWORD initialization_state = InitializeRuntime();
	if (initialization_state != INJ_ERR_SUCCESS)
	{
		LOG(0, "Runtime initialization failed: %08X\n", initialization_state);

		return;
	}

	LOG(0, "Beginning download(s)\n");

	sym_ntdll_native.SetDownload(true);
}

DWORD CreateTempFileCopy(std::wstring & FilePath, DWORD & win32err)
{
	auto FileNamePos = FilePath.find_last_of(L"\\/");
	if (FileNamePos == std::wstring::npos)
	{
		return INJ_ERR_INVALID_FILEPATH;
	}

	wchar_t szTempPath[MAXPATH_IN_TCHAR]{ 0 };
	if (!GetTempPathW(sizeof(szTempPath) / sizeof(wchar_t), szTempPath))
	{
		win32err = GetLastError();

		return INJ_ERR_CANT_GET_TEMP_DIR;
	}

	// Random 3-char prefix. The old fixed "AME" was a static, scanner-visible
	// string, and GetTempFileNameW's counter made the rest of the name
	// predictable, so the temp file could be enumerated before it existed.
	wchar_t temp_prefix[4] = { 0 };
	{
		static const wchar_t kAlphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		unsigned char pick[3] = { 0 };
		if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, pick, sizeof(pick), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
		{
			const ULONGLONG ticks = GetTickCount64();
			for (int i = 0; i < 3; ++i)
			{
				pick[i] = static_cast<unsigned char>((ticks >> (i * 8)) ^ (static_cast<ULONGLONG>(i) * 131ull));
			}
		}
		for (int i = 0; i < 3; ++i)
		{
			temp_prefix[i] = kAlphabet[pick[i] % 26];
		}
	}

	wchar_t szTempFile[MAXPATH_IN_TCHAR]{ 0 };
	if (!GetTempFileNameW(szTempPath, temp_prefix, 0, szTempFile))
	{
		win32err = GetLastError();

		return INJ_ERR_CANT_GET_TEMP_DIR;
	}

	if (!CopyFileW(FilePath.c_str(), szTempFile, FALSE))
	{
		win32err = GetLastError();
		DeleteFileW(szTempFile);

		return INJ_ERR_CANT_COPY_FILE;
	}

	FilePath = szTempFile;
	win32err = ERROR_SUCCESS;

	return FILE_ERR_SUCCESS;
}

DWORD ScrambleFileName(std::wstring & FilePath, UINT Length, DWORD & win32err)
{
	auto FileNamePos = FilePath.find_last_of(L"\\/");
	if (FileNamePos == std::wstring::npos)
	{
		win32err = ERROR_INVALID_PARAMETER;

		return INJ_ERR_INVALID_FILEPATH;
	}

	if (!Length || Length > 64)
	{
		win32err = ERROR_INVALID_PARAMETER;

		return INJ_ERR_INVALID_FILEPATH;
	}

	const std::wstring base_path = FilePath.substr(0, FileNamePos + 1);

	ULONG seed = 0;
	if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, ReCa<PUCHAR>(&seed), sizeof(seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		LARGE_INTEGER counter{ 0 };
		QueryPerformanceCounter(&counter);
		seed = counter.LowPart ^ static_cast<ULONG>(GetTickCount64());
	}

	std::mt19937 gen(seed);

	// Keep the first failure, not the last: EEXIST collisions are expected on
	// retry, so reporting the final errno would hide the root cause (e.g. an
	// EACCES denial on attempt 0 followed by a collision on attempt 7 would
	// misleadingly report "already exists").
	DWORD first_err = ERROR_GEN_FAILURE;

	for (int attempt = 0; attempt < 8; ++attempt)
	{
		auto NewPath = base_path;

		for (UINT i = 0; i != Length; ++i)
		{
			auto val = gen() % 3;
			if (val == 0)
			{
				val = gen() % 10;
				NewPath += wchar_t('0' + val);
			}
			else if (val == 1)
			{
				val = gen() % 26;
				NewPath += wchar_t('A' + val);
			}
			else
			{
				val = gen() % 26;
				NewPath += wchar_t('a' + val);
			}
		}
		NewPath += L".dll";

		if (!_wrename(FilePath.c_str(), NewPath.c_str()))
		{
			FilePath = NewPath;
			win32err = ERROR_SUCCESS;

			return FILE_ERR_SUCCESS;
		}

		// _wrename reports through errno, but every caller treats win32err as a
		// Win32 code, so translate the common cases instead of leaking a CRT
		// errno value into an error struct the UI renders as Win32.
		DWORD translated = ERROR_GEN_FAILURE;
		switch (errno)
		{
		case EACCES: translated = ERROR_ACCESS_DENIED;   break;
		case EEXIST: translated = ERROR_ALREADY_EXISTS;  break;
		case ENOENT: translated = ERROR_FILE_NOT_FOUND;  break;
		default:     translated = ERROR_GEN_FAILURE;     break;
		}

		if (attempt == 0)
		{
			first_err = translated;
		}

		win32err = first_err;
	}

	return INJ_ERR_CANT_RENAME_FILE;
}
