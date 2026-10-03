#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Core/Foundation/Primitives/VmpMarkers.h"
#include "Injection.h"
#include "Injection/ManualMapping/ManualMappingCore.h"
#include "System/Handle/HandleHijack.h"

DWORD __stdcall InitializeRuntime();

namespace
{
	AMEGER_VMP_NOINLINE DWORD OpenTargetProcess(DWORD Pid, DWORD AccessMask, DWORD Flags, ULONG_PTR SponsorValue, UniqueHandle & Out, ERROR_DATA & ErrorData)
	{
		AMEGER_VMP_ULTRA_BEGIN("hdl_acquire");
		UNREFERENCED_PARAMETER(ErrorData);

		Out.reset();

		if (Flags & INJ_HANDLE_HIJACKING)
		{
			HijackStats Stats{ };
			Stats.Attempted = 1;
			Stats.Source = static_cast<DWORD>(HijackSource::Scan);

			// 1. Sponsor: cooperating holder (normally the injector itself,
			//    which runs this DLL in-process) pre-opened the target.
			if (SponsorValue)
			{
				HANDLE Sponsor = ReCa<HANDLE>(SponsorValue);
				if (ValidateProcessDonorHandle(Sponsor, Pid, AccessMask))
				{
					Stats.SponsorValidated = 1;
					Stats.DonorHandle = PtrToUlong(Sponsor);
					HANDLE Duplicated = nullptr;
					bool duplicate_ok = DuplicateHandle(GetCurrentProcess(), Sponsor, GetCurrentProcess(),
						&Duplicated, AccessMask, FALSE, 0) && Duplicated && ValidateProcessDonorHandle(Duplicated, Pid, AccessMask);
					const bool roundtrip_ok = duplicate_ok &&
						((Flags & INJ_SKIP_SPONSOR_ROUNDTRIP) != 0 || ProbeMemoryRoundtrip(Duplicated));
					if (duplicate_ok && roundtrip_ok)
					{
						Out.reset(Duplicated);
						Stats.Success = 1;
						Stats.Source = static_cast<DWORD>(HijackSource::Sponsor);
						Stats.DonorPid = GetCurrentProcessId();
						Stats.GrantedAccess = AccessMask;
						Stats.NewHandle = PtrToUlong(Duplicated);
					Stats.SponsorState = 2;
					Stats.SponsorProbed = (Flags & INJ_SKIP_SPONSOR_ROUNDTRIP) ? 0 : 1;
					Stats.FailCode = INJ_ERR_SUCCESS;
						RecordHijackOutcome(Stats, false);
						LOG(0, "Acquired target process handle from sponsor\n");

						return INJ_ERR_SUCCESS;
					}

					if (Duplicated)
					{
						CloseHandle(Duplicated);
					}
				}

				Stats.SponsorState = 1;
				LOG(0, "Sponsor handle failed validation\n");
			}

			// 2. Foreign-donor scan. Its counters stay in Stats even when it
			//    finds nothing, so the UI can tell "empty table" apart from
			//    "denied query" (SnapStatus) instead of showing zeros.
			//    The scan overwrites the whole struct, so preserve our
			//    sponsor fields across the call.
			if (!(Flags & INJ_NO_DONOR_SCAN))
			{
				HANDLE Hijacked = nullptr;
				const DWORD SavedSponsorState = Stats.SponsorState;
				const DWORD SavedSponsorValidated = Stats.SponsorValidated;
				const DWORD SavedSponsorProbed = Stats.SponsorProbed;
				const DWORD SavedDonorHandle = Stats.DonorHandle;
				// Pass the sponsor handle so a target-owned entry duplicates from
				// it rather than OpenProcess(PROCESS_DUP_HANDLE, target) - the
				// direct open this whole path exists to avoid. The sponsor was
				// validated as a handle to Pid above and carries DUP_HANDLE.
				const DWORD HijackRet = HijackProcessHandle(Pid, AccessMask, Hijacked, &Stats,
					SponsorValue ? ReCa<HANDLE>(SponsorValue) : nullptr);
				Stats.SponsorState = SavedSponsorState;
				Stats.SponsorValidated = SavedSponsorValidated;
				Stats.SponsorProbed = SavedSponsorProbed;
				if (Stats.Success == 0)
				{
					Stats.DonorHandle = SavedDonorHandle;
				}
				if (HijackRet == INJ_ERR_SUCCESS && Hijacked)
				{
					Out.reset(Hijacked);
					RecordHijackOutcome(Stats, false);
					LOG(0, "Acquired target process handle via hijacking\n");

					return INJ_ERR_SUCCESS;
				}

				LOG(0, "Handle hijacking found no donor (%08X)\n", HijackRet);
				Stats.FailCode = HijackRet;
			}
			else if (Stats.FailCode == INJ_ERR_SUCCESS)
			{
				Stats.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
			}

			// 3. Direct fallback: record the attempt, then honor the refusal
			//    flag (stealth fails closed instead of opening the target
			//    with a fresh OpenProcess).
			Stats.Source = static_cast<DWORD>(HijackSource::Direct);
			RecordHijackOutcome(Stats, false);

			if (Flags & INJ_NO_DIRECT_FALLBACK)
			{
				LOG(0, "Direct OpenProcess fallback disabled (INJ_NO_DIRECT_FALLBACK); refusing\n");
				return INJ_ERR_HANDLE_HIJACK_FAILED;
			}
		}

		Out.reset(OpenProcess(AccessMask, FALSE, Pid));
		if (!Out)
		{
			return INJ_ERR_CANT_OPEN_PROCESS;
		}

		AMEGER_VMP_ULTRA_END();
		return INJ_ERR_SUCCESS;
	}

	class InjectionGateGuard
	{
		bool m_Acquired = false;

	public:
		InjectionGateGuard()
		{
			m_Acquired = InterlockedCompareExchange(&g_InjectionGate, 1, 0) == 0;
			if (m_Acquired)
			{
				SetEvent(g_hRunningEvent);
				ResetEvent(g_hInterruptEvent);
				ResetEvent(g_hInterruptedEvent);
			}
		}

		~InjectionGateGuard()
		{
			if (m_Acquired)
			{
				ResetEvent(g_hRunningEvent);
				InterlockedExchange(&g_InjectionGate, 0);
			}
		}

		explicit operator bool() const
		{
			return m_Acquired;
		}
	};

	class PreparedDllFile
	{
		std::wstring m_Path;
		bool m_Owned = false;

	public:
		explicit PreparedDllFile(const std::wstring & path) : m_Path(path)
		{
		}

		~PreparedDllFile()
		{
			if (m_Owned && !m_Path.empty())
			{
				DeleteFileW(m_Path.c_str());
			}
		}

		void Update(const std::wstring & path)
		{
			if (m_Owned && !m_Path.empty() && _wcsicmp(m_Path.c_str(), path.c_str()) != 0)
			{
				DeleteFileW(m_Path.c_str());
			}

			m_Path = path;
			m_Owned = true;
		}
	};
}

DWORD InitErrorStruct(const INJECTIONDATA_INTERNAL & Data, int Native, DWORD ErrorCode, const ERROR_DATA & error_data);

DWORD __stdcall InjectA(INJECTIONDATAA * pData) try
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "InjectA called with pData = %p\n", pData);

	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		LOG(0, "Different injection in progress. Wait for the other injection to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	if (!pData)
	{
		LOG(0, "pData is invalid\n");

		return INJ_ERR_NO_DATA;
	}

	if (pData->szDllPath[0] == '\0' || pData->szDllPath[sizeof(pData->szDllPath) - 1] != '\0')
	{
		LOG(0, "Invalid path\n");

		return INJ_ERR_INVALID_FILEPATH;
	}
	
	INJECTIONDATA_INTERNAL data_internal(pData);
	DWORD Ret = Inject_Internal(&data_internal);
	pData->hDllOut = data_internal.hDllOut;

	return Ret;
}
catch (...)
{
	if (pData)
	{
		pData->hDllOut = NULL;
	}

	LOG(0, "InjectA failed with an unhandled exception\n");

	return INJ_ERR_UNHANDLED_EXCEPTION;
}

DWORD __stdcall InjectW(INJECTIONDATAW * pData) try
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "InjectW called with pData = %p\n", pData);

	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		LOG(0, "Different injection in progress. Wait for the other injection to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	if (!pData)
	{
		LOG(0, "pData is invalid\n");

		return INJ_ERR_NO_DATA;
	}

	if (pData->szDllPath[0] == L'\0' || pData->szDllPath[_countof(pData->szDllPath) - 1] != L'\0')
	{
		LOG(0, "Invalid path\n");

		return INJ_ERR_INVALID_FILEPATH;
	}
	
	INJECTIONDATA_INTERNAL data_internal(pData);
	DWORD Ret = Inject_Internal(&data_internal);
	pData->hDllOut = data_internal.hDllOut;

	return Ret;	
}
catch (...)
{
	if (pData)
	{
		pData->hDllOut = NULL;
	}

	LOG(0, "InjectW failed with an unhandled exception\n");

	return INJ_ERR_UNHANDLED_EXCEPTION;
}

DWORD __stdcall Inject_Internal(INJECTIONDATA_INTERNAL * pData) try
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "Inject_Internal called with pData = %p\n", pData);

	if (!pData)
	{
		return INJ_ERR_NO_DATA;
	}

	InjectionGateGuard injection_guard;
	if (!injection_guard)
	{
		LOG(0, "Different injection in progress. Wait for the other injection to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	// Clear last run's telemetry so a failure this run cannot be reported as the
	// previous run's success. String stats are excluded: they are filled once at
	// import-resolution time, before any injection, and zeroing them makes the
	// interface report them as unavailable.
	ResetHijackStats();
	ResetMapStats();
	ResetThreadExecStats();

	DWORD RetVal = INJ_ERR_SUCCESS;

	ERROR_DATA error_data{ 0 };
	auto & Data = *pData;
	PreparedDllFile prepared_file(Data.DllPath);

	RetVal = GetImportState();
	if (RetVal != INJ_ERR_SUCCESS)
	{
		LOG(0, "Resolving imports failed: %08X\n", RetVal);

		error_data = import_handler_error_data;

		return InitErrorStruct(Data, -1, INJ_ERR_IMPORT_HANDLER_NOT_DONE, error_data);
	}

	
	if (Data.Mode != INJECTION_MODE::IM_ManualMap)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Only ManualMap is supported in this build\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_INJ_METHOD, error_data);
	}

	if (Data.Method != LAUNCH_METHOD::LM_HijackThread)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Only HijackThread is supported in this build\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_INJ_METHOD, error_data);
	}

	if (Data.DllPath.empty())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid path provided (empty string)\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_FILEPATH, error_data);
	}

	if (!FileExistsW(Data.DllPath))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "File doesn't exist: %08X\n", error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_FILE_DOESNT_EXIST, error_data);
	}

	if (PathIsRelativeW(Data.DllPath.c_str()))
	{
		wchar_t buffer[MAX_PATH * 2]{ 0 };
		auto win_ret = GetFullPathNameW(Data.DllPath.c_str(), sizeof(buffer) / sizeof(wchar_t), buffer, nullptr);
		if (!win_ret || win_ret >= sizeof(buffer) / sizeof(wchar_t))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(0, "Failed to resolve absolute file path: %08X\n", error_data.AdvErrorCode);

			return InitErrorStruct(Data, -1, INJ_ERR_FAILED_TO_RESOLVE_PATH, error_data);
		}

		Data.DllPath = buffer;
	}

	if (!Data.ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid process identifier specified\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PID, error_data);
	}

	// Inject_Internal is the file-path entry point (InjectA/W): there is no
	// RawData, so INJ_MM_MAP_FROM_MEMORY is never valid here. Strip a stale
	// bit defensively. Memory injection bypasses this function entirely via
	// Memory_Inject (which never touches disk), and ManualMap normalizes
	// every file to a staged image before the remote shell runs
	// (remote_flags |= INJ_MM_MAP_FROM_MEMORY), so no skip-branch is needed.
	if (Data.Flags & INJ_MM_MAP_FROM_MEMORY)
	{
		Data.Flags &= ~INJ_MM_MAP_FROM_MEMORY;
	}

	if (Data.Flags & INJ_LOAD_DLL_COPY)
	{
		LOG(0, "Copying dll into temp directory\n");

		DWORD win32err = NULL;

		auto dwRet = CreateTempFileCopy(Data.DllPath, win32err);
		if (dwRet != FILE_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, win32err);

			LOG(0, "Failed to copy file to temp directory: %08X\n", dwRet);

			return InitErrorStruct(Data, -1, dwRet, error_data);
		}

		prepared_file.Update(Data.DllPath);
		LOG(0, "Path of dll copy: %ls\n", Data.DllPath.c_str());
	}

	if (Data.Flags & INJ_SCRAMBLE_DLL_NAME)
	{
		LOG(0, "Scrambling dll name\n");

		DWORD win32err = NULL;
		if (!(Data.Flags & INJ_LOAD_DLL_COPY))
		{
			const DWORD copy_result = CreateTempFileCopy(Data.DllPath, win32err);
			if (copy_result != FILE_ERR_SUCCESS)
			{
				INIT_ERROR_DATA(error_data, win32err);

				return InitErrorStruct(Data, -1, copy_result, error_data);
			}

			prepared_file.Update(Data.DllPath);
		}

		auto dwRet = ScrambleFileName(Data.DllPath, 10, win32err);
		if (dwRet != FILE_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, win32err);

			LOG(0, "Failed to copy file to temp directory: %08X\n", dwRet);

			return InitErrorStruct(Data, -1, dwRet, error_data);
		}

	prepared_file.Update(Data.DllPath);
	LOG(0, "Path of renamed dll: %ls\n", Data.DllPath.c_str());
}

	DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
	if (Data.Flags & INJ_HANDLE_HIJACKING)
	{
		// The acquired handle doubles as the scan's target-owner source for
		// the thread pass: pre-grant the duplicate rights so the target is
		// never opened a second time.
		access_mask |= PROCESS_DUP_HANDLE;
	}
	UniqueHandle hTargetProc;
	const DWORD OpenRet = OpenTargetProcess(Data.ProcessID, access_mask, Data.Flags, Data.hHandleValue, hTargetProc, error_data);
	if (OpenRet != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "OpenTargetProcess failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, OpenRet, error_data);
	}

	DWORD handle_info = 0;
	if (!GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "Invalid process handle: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	LOG(0, "Attached to target process\n");

	wchar_t szExePath[MAX_PATH * 2]{ 0 };
	DWORD size_inout = sizeof(szExePath) / sizeof(szExePath[0]);
	if (!QueryFullProcessImageNameW(hTargetProc, NULL, szExePath, &size_inout))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "QueryFullProcessImageNameW failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		

		return InitErrorStruct(Data, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

	auto ExePath	= std::wstring(szExePath);
	auto ExeNamePos = ExePath.find_last_of('\\');

	if (ExeNamePos == std::wstring::npos)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Failed to extract exe name from path\n");

		

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_EXE_PATH, error_data);
	}

	Data.TargetProcessExeFileName = ExePath.substr(ExeNamePos + 1);

	LOG(0, "Target process name = %ls\n", Data.TargetProcessExeFileName.c_str());

	LOG(0, "Validating specified file\n");

	DWORD FileErr = FILE_ERR_SUCCESS;
	DWORD wow_error = ERROR_SUCCESS;
	bool native_target = true;
	native_target = IsNativeProcess(hTargetProc, &wow_error);
	if (!native_target)
	{
		INIT_ERROR_DATA(error_data, wow_error != ERROR_SUCCESS ? wow_error : static_cast<DWORD>(INJ_ERR_ADVANCED_NOT_DEFINED));

		LOG(0, "32-bit targets not supported in this x64-only build\n");

		

		return InitErrorStruct(Data, false, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}
	FileErr = ValidateDllFile(Data.DllPath, IMAGE_FILE_MACHINE_AMD64, Data.Flags);

	if (FileErr != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		LOG(0, "Invalid file specified\n");

		

		return InitErrorStruct(Data, native_target, FileErr, error_data);
	}

	LOG(0, "File validated and prepared for injection:\n %ls\n", Data.DllPath.c_str());
	
	HINSTANCE hOut = NULL;

	INJECTION_SOURCE source;
	source.DllPath = Data.DllPath;

	RetVal = MMAP_NATIVE::ManualMap(source, hTargetProc, Data.Method, Data.Flags, hOut, Data.Timeout, Data.hThreadHandleValue, Data.TargetTid, error_data);

	LOG(0, "Injection finished\n");

	
	
	Data.hDllOut = hOut;

	return InitErrorStruct(Data, native_target, RetVal, error_data);
}
catch (...)
{
	LOG(0, "Inject_Internal failed with an unhandled exception\n");

	return INJ_ERR_UNHANDLED_EXCEPTION;
}

AMEGER_VMP_NOINLINE DWORD InitErrorStruct(const INJECTIONDATA_INTERNAL & Data, int Native, DWORD ErrorCode, const ERROR_DATA & error_data)
{
	AMEGER_VMP_ULTRA_BEGIN("inj_errstruct");
	if (ErrorCode && Data.GenerateErrorLog)
	{
		ERROR_INFO info{ };
		info.DllFileName				= Data.DllPath;
		info.TargetProcessExeFileName	= Data.TargetProcessExeFileName;
		info.TargetProcessId			= Data.ProcessID;
		info.InjectionMode				= Data.Mode;
		info.LaunchMethod				= Data.Method;
		info.Flags						= Data.Flags;
		info.HandleValue				= Data.hHandleValue;
		info.bNative					= Native;
		info.RawData					= Data.RawData;
		info.RawSize					= Data.RawSize;

		info.ErrorCode		= ErrorCode;
		info.AdvErrorCode	= error_data.AdvErrorCode;
		info.SourceFile		= error_data.szFileName;
		info.FunctionName	= error_data.szFunctionName;
		info.Line			= error_data.Line;

		ErrorLog(info);
	}

	AMEGER_VMP_ULTRA_END();
	return ErrorCode;
}

DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData) try
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "Memory_Inject called with pData = %p\n", pData);

	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		LOG(0, "Different injection in progress. Wait for the other injection to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	// Clear last run's telemetry so a failure this run cannot be reported as the
	// previous run's success. String stats are excluded for the same reason as in
	// Inject_Internal.
	ResetHijackStats();
	ResetMapStats();
	ResetThreadExecStats();

	if (!pData)
	{
		LOG(0, "pData is invalid\n");

		return INJ_ERR_NO_DATA;
	}

	if (!pData->RawData)
	{
		LOG(0, "No raw data\n");

		return INJ_ERR_NO_RAW_DATA;
	}

	InjectionGateGuard injection_guard;
	if (!injection_guard)
	{
		LOG(0, "Different injection in progress. Wait for the other injection to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	pData->Flags |= INJ_MM_MAP_FROM_MEMORY;

	DWORD RetVal = INJ_ERR_SUCCESS;

	ERROR_DATA error_data{ 0 };
	INJECTIONDATA_INTERNAL Data(pData);

	RetVal = GetImportState();
	if (RetVal != INJ_ERR_SUCCESS)
	{
		LOG(0, "Resolving imports failed: %08X\n", RetVal);

		error_data = import_handler_error_data;

		return InitErrorStruct(Data, -1, INJ_ERR_IMPORT_HANDLER_NOT_DONE, error_data);
	}

	pData->Mode = INJECTION_MODE::IM_ManualMap;
	pData->Flags |= INJ_MM_MAP_FROM_MEMORY;
	Data.Mode = INJECTION_MODE::IM_ManualMap;
	Data.Flags |= INJ_MM_MAP_FROM_MEMORY;

	if (Data.Method != LAUNCH_METHOD::LM_HijackThread)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Only HijackThread is supported in this build\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_INJ_METHOD, error_data);
	}

	if (!Data.ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid process identifier specified\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PID, error_data);
	}

	DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
	if (Data.Flags & INJ_HANDLE_HIJACKING)
	{
		// The acquired handle doubles as the scan's target-owner source for
		// the thread pass: pre-grant the duplicate rights so the target is
		// never opened a second time.
		access_mask |= PROCESS_DUP_HANDLE;
	}
	UniqueHandle hTargetProc;
	const DWORD OpenRet = OpenTargetProcess(Data.ProcessID, access_mask, Data.Flags, Data.hHandleValue, hTargetProc, error_data);
	if (OpenRet != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "OpenTargetProcess failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, OpenRet, error_data);
	}

	DWORD handle_info = 0;
	if (!GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "Invalid process handle: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	LOG(0, "Attached to target process\n");

	wchar_t szExePath[MAX_PATH * 2]{ 0 };
	DWORD size_inout = sizeof(szExePath) / sizeof(szExePath[0]);
	if (!QueryFullProcessImageNameW(hTargetProc, NULL, szExePath, &size_inout))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "QueryFullProcessImageNameW failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		

		return InitErrorStruct(Data, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

	auto ExePath	= std::wstring(szExePath);
	auto ExeNamePos = ExePath.find_last_of('\\');

	if (ExeNamePos == std::wstring::npos)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Failed to extract exe name from path\n");

		

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_EXE_PATH, error_data);
	}

	Data.TargetProcessExeFileName = ExePath.substr(ExeNamePos + 1);

	LOG(0, "Target process name = %ls\n", Data.TargetProcessExeFileName.c_str());

	LOG(0, "Validating specified file\n");

	DWORD FileErr = FILE_ERR_SUCCESS;
	DWORD wow_error = ERROR_SUCCESS;
	bool native_target = true;
	native_target = IsNativeProcess(hTargetProc, &wow_error);
	if (!native_target)
	{
		INIT_ERROR_DATA(error_data, wow_error != ERROR_SUCCESS ? wow_error : static_cast<DWORD>(INJ_ERR_ADVANCED_NOT_DEFINED));

		LOG(0, "32-bit targets not supported in this x64-only build\n");

		

		return InitErrorStruct(Data, false, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}
	FileErr = ValidateDllFileInMemory(Data.RawData, Data.RawSize, IMAGE_FILE_MACHINE_AMD64, Data.Flags);

	if (FileErr != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		LOG(0, "Invalid file specified\n");

		

		return InitErrorStruct(Data, native_target, FileErr, error_data);
	}

	LOG(0, "File validated and prepared for injection\n");

	HINSTANCE hOut = NULL;

	INJECTION_SOURCE Source;
	Source.FromMemory	= true;
	Source.RawData		= Data.RawData;
	Source.RawSize		= Data.RawSize;

	RetVal = MMAP_NATIVE::ManualMap(Source, hTargetProc, Data.Method, Data.Flags, hOut, Data.Timeout, Data.hThreadHandleValue, Data.TargetTid, error_data);

	LOG(0, "Injection finished\n");

	
	
	pData->hDllOut = hOut;

	return InitErrorStruct(Data, native_target, RetVal, error_data);
}
catch (...)
{
	if (pData)
	{
		pData->hDllOut = NULL;
	}

	LOG(0, "Memory_Inject failed with an unhandled exception\n");

	return INJ_ERR_UNHANDLED_EXCEPTION;
}

DWORD __stdcall GetSymbolState()
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	try
	{
		const DWORD initialization_state = InitializeRuntime();
		if (initialization_state != INJ_ERR_SUCCESS)
		{
			return initialization_state;
		}

		if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			return INJ_ERR_SYMBOL_INIT_NOT_DONE;
		}

		DWORD sym_ret = sym_ntdll_native_ret.get();
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			LOG(0, "Native symbol loading failed: %08X\n", sym_ret);

			return sym_ret;
		}

		LOG(0, "All symbols loaded\n");

		return SYMBOL_ERR_SUCCESS;
	}
	catch (...)
	{
		LOG(0, "Native symbol loading threw an exception\n");

		return SYMBOL_ERR_DOWNLOAD_FAILED;
	}
}

DWORD __stdcall GetImportState()
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	try
	{
		const DWORD initialization_state = InitializeRuntime();
		if (initialization_state != INJ_ERR_SUCCESS)
		{
			return initialization_state;
		}

		if (import_handler_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			return INJ_ERR_IMPORT_HANDLER_NOT_DONE;
		}

		DWORD imp_ret = import_handler_ret.get();
		if (imp_ret != INJ_ERR_SUCCESS)
		{
			LOG(0, "Import handler (native) failed: %08X\n", imp_ret);

			return imp_ret;
		}

		LOG(0, "Import handler finished\n");

		return INJ_ERR_SUCCESS;
	}
	catch (...)
	{
		LOG(0, "Import handler threw an exception\n");

		return INJ_ERR_IMPORT_HANDLER_NOT_DONE;
	}
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL(const INJECTIONDATAA * pData)
{
	DllPath				= CharArrayToStdWstring(pData->szDllPath);
	RawData				= nullptr;
	RawSize				= 0;
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	TargetTid			= pData->TargetTid;
	hThreadHandleValue	= pData->hThreadHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;
	hDllOut				= NULL;
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL(const INJECTIONDATAW * pData)
{
	DllPath				= std::wstring(pData->szDllPath);
	RawData				= nullptr;
	RawSize				= 0;
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	TargetTid			= pData->TargetTid;
	hThreadHandleValue	= pData->hThreadHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;
	hDllOut				= NULL;
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA * pData)
{
	RawData				= pData->RawData;
	RawSize				= pData->RawSize;
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	TargetTid			= pData->TargetTid;
	hThreadHandleValue	= pData->hThreadHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;
	hDllOut				= NULL;
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL()
{
	RawData				= nullptr;
	RawSize				= 0;
	ProcessID			= 0;
	Mode				= INJECTION_MODE::IM_ManualMap;
	Method				= LAUNCH_METHOD::LM_HijackThread;
	Flags				= NULL;
	Timeout				= 2000;
	hHandleValue		= 0;
	TargetTid			= 0;
	hThreadHandleValue	= 0;
	hDllOut				= NULL;
	GenerateErrorLog	= true;
}
