#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Injection/ManualMapping/ManualMappingCore.h"


using namespace NATIVE;
using namespace MMAP_NATIVE;

namespace
{
	// Last shell-reported cleanup result, exposed to the interface through
	// GetLastMapStats (see Injection.h).
	MAP_STATS g_LastMapStats{};

	PE_IMAGE::OPTIONS GetMappingOptions(DWORD flags)
	{
		PE_IMAGE::OPTIONS options;
		options.RequireDll = true;
		// The image is always allocated at an arbitrary base (the shell hands
		// NtAllocateVirtualMemory a null hint), so relocations are mandatory
		// regardless of any flag.
		options.RequireRelocations = true;
		options.ResolveImports = (flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)) != 0;
		options.ResolveDelayImports = (flags & INJ_MM_RESOLVE_DELAY_IMPORTS) != 0;
		options.EnableExceptions = (flags & INJ_MM_ENABLE_EXCEPTIONS) != 0;
		options.InitializeSecurityCookie = (flags & INJ_MM_INIT_SECURITY_COOKIE) != 0;
		options.ExecuteTls = (flags & INJ_MM_EXECUTE_TLS) != 0;
		return options;
	}

	bool ReadFileForMapping(const std::wstring & path, std::vector<BYTE> & data)
	{
		std::ifstream file(path, std::ios::binary | std::ios::ate);
		if (!file.good())
		{
			return false;
		}

		const std::streamoff file_size = file.tellg();
		if (file_size <= 0 || static_cast<unsigned long long>(file_size) > PE_IMAGE::MAX_IMAGE_SIZE)
		{
			return false;
		}

		data.resize(static_cast<size_t>(file_size));
		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<char *>(data.data()), file_size);
		return static_cast<bool>(file) && file.gcount() == file_size;
	}
}


DWORD MMAP_NATIVE::ManualMap(const INJECTION_SOURCE & Source, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	if (Method != LAUNCH_METHOD::LM_HijackThread)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Unsupported launch method for ManualMap\n");

		return INJ_ERR_INVALID_INJ_METHOD;
	}

	LOG(1, "Begin ManualMap\n");

	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		INIT_ERROR_DATA(error_data, static_cast<DWORD>(GetOSBuildVersion()));

		return INJ_ERR_WINDOWS_BUILD_UNSUPPORTED;
	}

	const DWORD remote_flags = Flags | INJ_MM_MAP_FROM_MEMORY;
	INJECTION_SOURCE source = Source;
	std::vector<BYTE> file_data;
	PE_IMAGE::VIEW source_view;
	DWORD validation_result = FILE_ERR_SUCCESS;

	try
	{
		if (source.FromMemory)
		{
			validation_result = PE_IMAGE::Validate(source.RawData, source.RawSize, IMAGE_FILE_MACHINE_AMD64, GetMappingOptions(remote_flags), source_view);
		}
		else
		{
		if (!ReadFileForMapping(source.DllPath, file_data))
		{
			INIT_ERROR_DATA(error_data, FILE_ERR_CANT_OPEN_FILE);

			return FILE_ERR_CANT_OPEN_FILE;
		}

			validation_result = PE_IMAGE::Validate(file_data.data(), file_data.size(), IMAGE_FILE_MACHINE_AMD64, GetMappingOptions(remote_flags), source_view);
			source.FromMemory = true;
			source.RawData = file_data.data();
			source.RawSize = static_cast<DWORD>(file_data.size());
		}
	}
	catch (const std::bad_alloc &)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	if (validation_result != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, validation_result);

		LOG(1, "Strict PE validation failed: %08X\n", validation_result);

		return validation_result;
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.Flags = remote_flags;
	data.RawSize = source.RawSize;
	data.OSVersion = GetOSVersion();
	data.OSBuildNumber = GetOSBuildVersion();
	// Downloaded layouts for the remote shell. Fail-closed when the PDB
	// resolve did not complete: the target has no DbgHelp, so stale static
	// LDR/TLS/inverted/KUSER guesses must never be sent.
	if (!g_DynamicOffsets.Ready)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Dynamic NT offsets not ready, refusing ManualMap\n");

		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}
	data.NtOffsets = g_DynamicOffsets;

	if (!source.DllPath.empty())
	{
		const size_t path_length = source.DllPath.length();
		const size_t maximum_path_length = sizeof(data.szPathBuffer) / sizeof(wchar_t);
		if (path_length >= maximum_path_length)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Path too long: %zu characters, buffer size: %zu\n", path_length, maximum_path_length);

			return INJ_ERR_STRING_TOO_LONG;
		}

		data.DllPath.Length = static_cast<WORD>(path_length * sizeof(wchar_t));
		data.DllPath.MaxLength = static_cast<WORD>(sizeof(data.szPathBuffer));
		source.DllPath.copy(data.szPathBuffer, path_length);
		data.szPathBuffer[path_length] = 0;
	}

	
	LOG(1, "Shell data initialized\n");

	ULONG_PTR ShellSize		= ReCa<ULONG_PTR>(MMAP_SEC_END) - ReCa<ULONG_PTR>(ManualMapping_Shell);

	// Stealth staging: the block starts RW (never RWX). Code pages are
	// promoted to RX only after every WPM completes, and data pages stay
	// RW. Shells are page-isolated so the RX promotion cannot bleed into
	// MANUAL_MAPPING_DATA / function table / raw image (which the shell
	// must write back: hRet, MapStats, ntRet).
	constexpr SIZE_T kStagePage = 0x1000;

	SIZE_T AllocationSize = 0;
	const SIZE_T allocation_parts[] =
	{
		sizeof(MANUAL_MAPPING_DATA),
		sizeof(MANUAL_MAPPING_FUNCTION_TABLE),
		static_cast<SIZE_T>(ShellSize),
		static_cast<SIZE_T>(kStagePage) * 4,
		source.FromMemory ? (static_cast<SIZE_T>(source.RawSize) + kStagePage) : 0
	};

	for (SIZE_T part : allocation_parts)
	{
		if (part > static_cast<SIZE_T>(-1) - AllocationSize)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Allocation size overflow\n");

			return INJ_ERR_OUT_OF_MEMORY_NEW;
		}

		AllocationSize += part;
	}

	BYTE * pAllocBase = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pAllocBase)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "memory allocation failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	RemoteAllocation allocation_guard(hTargetProc, pAllocBase);

	BYTE * pArg				= pAllocBase;
	BYTE * pShells			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA),				kStagePage));
	BYTE * pFunctionTable	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pShells)		+ ShellSize,								kStagePage));
	BYTE * pRawData			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pFunctionTable) + sizeof(MANUAL_MAPPING_FUNCTION_TABLE),	BASE_ALIGNMENT));

	std::unique_ptr<MANUAL_MAPPING_FUNCTION_TABLE> table_local(new(std::nothrow) MANUAL_MAPPING_FUNCTION_TABLE());

	if (!table_local)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "operator new failed: %08X\n", error_data.AdvErrorCode);

		

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	
	BYTE * mmap_sec_base = ReCa<BYTE *>(ManualMapping_Shell);

	table_local->MMP_Shell = ReCa<f_MMI_FUNCTION>(pShells);
	table_local->MMIP_MapSections			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_MapSections)				- mmap_sec_base));
	table_local->MMIP_RelocateImage			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_RelocateImage)			- mmap_sec_base));
	table_local->MMIP_InitializeCookie		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_InitializeCookie)		- mmap_sec_base));
	table_local->MMIP_LoadImports			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_LoadImports)				- mmap_sec_base));
	table_local->MMIP_LoadDelayImports		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_LoadDelayImports)		- mmap_sec_base));
	table_local->MMIP_SetPageProtections	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_SetPageProtections)		- mmap_sec_base));
	table_local->MMIP_EnableExceptions		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_EnableExceptions)		- mmap_sec_base));
	table_local->MMIP_HandleTLS				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_HandleTLS)				- mmap_sec_base));
	table_local->MMIP_ExecuteDllMain		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_ExecuteDllMain)			- mmap_sec_base));
	table_local->MMIP_CleanDataDirectories	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanDataDirectories)	- mmap_sec_base));
	table_local->MMIP_CloakHeader			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CloakHeader)				- mmap_sec_base));
	table_local->MMIP_CleanUp				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanUp)					- mmap_sec_base));
	
	table_local->MMIHP_PreprocessModuleName		= ReCa<decltype(MMIH_PreprocessModuleName)		*>(pShells + (ReCa<BYTE *>(MMIH_PreprocessModuleName)		- mmap_sec_base));
	table_local->MMIHP_LoadModule				= ReCa<decltype(MMIH_LoadModule)				*>(pShells + (ReCa<BYTE *>(MMIH_LoadModule)					- mmap_sec_base));

	if (!table_local->IsValid())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Function table contains unresolved native functions\n");

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	data.FunctionTable = ReCa<MANUAL_MAPPING_FUNCTION_TABLE *>(pFunctionTable);

	if (source.FromMemory)
	{
		data.pRawData = pRawData;
	}

	LOG(2, "Shellsize      = %08X\n", MDWD(ShellSize));
	LOG(2, "Total size     = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg           = %p\n", pArg);
	LOG(2, "pShells        = %p\n", pShells);

	LOG(2, "pFunctionTable = %p\n", pFunctionTable);

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		
		

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shelldata written to memory\n");

	if (!WriteProcessMemory(hTargetProc, pShells, mmap_sec_base, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		
		

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shells written to memory\n");

	if (!WriteProcessMemory(hTargetProc, pFunctionTable, table_local.get(), sizeof(MANUAL_MAPPING_FUNCTION_TABLE), nullptr))

	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		
		

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Function table written to memory\n");

	

	if (source.FromMemory)
	{
		if (!WriteProcessMemory(hTargetProc, pRawData, source.RawData, source.RawSize, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			

			return INJ_ERR_WPM_FAIL;
		}

		LOG(1, "Raw data written to memory\n");
	}

	// RW -> RX promotion for the code pages only. Data/table/raw pages
	// stay RW so the shell can write back hRet/MapStats. No RWX exists
	// at any point; VCheck-style RWX scans see RW + RX, never RWX.
	{
		const SIZE_T code_bytes = static_cast<SIZE_T>(ShellSize);
		if (code_bytes)
		{
			DWORD old_protect = 0;
			SIZE_T code_size = ALIGN_UP(code_bytes, kStagePage);
			void * code_base = pShells;
			if (!VirtualProtectEx(hTargetProc, code_base, code_size, PAGE_EXECUTE_READ, &old_protect))
			{
				INIT_ERROR_DATA(error_data, GetLastError());

				LOG(1, "VirtualProtectEx(RX) failed: %08X\n", error_data.AdvErrorCode);

				return INJ_ERR_UPDATE_PROTECTION_FAILED;
			}

			FlushInstructionCache(hTargetProc, code_base, code_size);
			LOG(1, "Staging code promoted RW->RX\n");
		}
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShells), pArg, Method, remote_flags, remote_ret, Timeout, SponsorThread, SponsorTid, error_data);


	LOG(1, "Return from StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine failed: %08X\n", dwRet);

		// NOTE: SR_HT_ERR_REMOTE_PENDING_TIMEOUT (0x1020000B) is deliberately
		// NOT released here. Pending means the stub never ran (State stayed
		// Pending), the thread was ForceRestored, and no image was mapped, so
		// the staging block is safe to free via the guard destructor. Only
		// TIMEOUT/RECOVERY (shell may still be live in the target) must leak.
		if (dwRet == SR_HT_ERR_REMOTE_TIMEOUT || dwRet == SR_HT_ERR_RECOVERY_REQUIRED)
		{
			allocation_guard.release();
		}

		return dwRet;

	}

	LOG(1, "Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		// StartRoutine returns SR_ERR_SUCCESS only after the remote shell has
		// reported SR_RS_ExecutionFinished and the hijacked thread context was
		// restored, so no remote code is running from the staging block here.
		// allocation_guard still owns pAllocBase (it was not released), so this
		// return reclaims the staging block - including the operator's DLL path
		// copy - through its destructor.
		//
		// What cannot be reclaimed from the host is the mapped image. If the
		// shell pipeline succeeded, pAllocationBase is a separate allocation
		// that is now a live DLL (DllMain already ran); the host cannot learn
		// its base or whether it was mapped, because the read that would carry
		// pImageBase/hRet is the one that just failed. Unmapping would need
		// MMIP_CleanUp executed in the target, whose address is only reachable
		// through that same unread result block. So this path reports
		// INJ_ERR_VERIFY_RESULT_FAIL with a possibly-loaded image left behind;
		// the operator must restart the target to reclaim it.
		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	g_LastMapStats = data.MapStats;

	

	if (remote_ret != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, (DWORD)data.ntRet);

		LOG(1, "Shell failed: %08X\n", remote_ret);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Shell failed\n");

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	LOG(1, "Shell returned successfully\n");

	hOut = data.hRet;

	LOG(1, "Imagebase = %p\n", ReCa<void *>(hOut));

	return INJ_ERR_SUCCESS;
}

#pragma region inlined dependency record functions

__forceinline MM_DEPENDENCY_RECORD * BuildDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD ** head, HANDLE DllHandle, const UNICODE_STRING * DllPath)
{
	if (!head)
	{
		return nullptr;
	}

	
	if (!(*head))
	{
		*head = NewObject<MM_DEPENDENCY_RECORD>(f);

		if (!(*head))
		{
			return nullptr;
		}

		(*head)->Next = *head;
		(*head)->Prev = *head;
		(*head)->DllHandle = DllHandle;
		
		if (DllPath)
		{
			auto len = DllPath->Length;
			if (len < sizeof(MM_DEPENDENCY_RECORD::Buffer))
			{
				(*head)->DllName.Length		= len;
				(*head)->DllName.MaxLength	= sizeof(MM_DEPENDENCY_RECORD::Buffer);
				(*head)->DllName.szBuffer	= (*head)->Buffer;

				f->memmove((*head)->Buffer, DllPath->szBuffer, len);
			}
		}

		return (*head);
	}	

	
	auto next = NewObject<MM_DEPENDENCY_RECORD>(f);
	if (next)
	{
		next->Next			= (*head);
		next->Prev			= (*head)->Prev;

		(*head)->Prev->Next	= next;
		(*head)->Prev		= next;

		next->DllHandle = DllHandle;

		if (DllPath)
		{
			auto len = DllPath->Length;
			if (len < sizeof(MM_DEPENDENCY_RECORD::Buffer))
			{
				next->DllName.Length	= len;
				next->DllName.MaxLength	= sizeof(MM_DEPENDENCY_RECORD::Buffer);
				next->DllName.szBuffer	= next->Buffer;

				f->memmove(next->Buffer, DllPath->szBuffer, len);
			}
		}
	}

	return next;
}

__forceinline MM_DEPENDENCY_RECORD * SearchDependencyRecordByHandle(MM_DEPENDENCY_RECORD * head, HANDLE hDll)
{
	if (!head)
	{
		return nullptr;
	}

	auto cur = head;

	do
	{
		if (cur->DllHandle == hDll)
		{
			return cur;
		}

		cur = cur->Next;
	} while (cur != head);

	return nullptr;
}

__forceinline void UnloadAndDeleteDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * head)
{
	if (!head)
	{
		return;
	}
	
	while (head->Prev != head)
	{
		auto cur = head->Prev;
		auto prev = cur->Prev;
		auto next = cur->Next;

		prev->Next = next;
		next->Prev = prev;

		f->LdrUnloadDll(cur->DllHandle);
		DeleteObject(f, cur);
	}

	f->LdrUnloadDll(head->DllHandle);
	DeleteObject(f, head);
}

// Success-path release: dependency nodes (with their module-path copies)
// are only needed while mapping. The modules themselves stay loaded via
// their LDR refcounts - only our bookkeeping nodes are returned to the
// loader heap, so repeated injections cannot pile residue there. Never
// unloads: unloading on success would pull the payload's own imports out
// from under it. MMI_CleanUp (failure path) keeps unload+delete together.
__forceinline void FreeDependencyNodeList(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * & head)
{
	if (!head)
	{
		return;
	}

	while (head->Prev != head)
	{
		auto cur = head->Prev;
		cur->Prev->Next = cur->Next;
		cur->Next->Prev = cur->Prev;
		DeleteObject(f, cur);
	}

	DeleteObject(f, head);
	head = nullptr;
}

#pragma endregion

#pragma region manual mapping internal helper functions

NTSTATUS __declspec(code_seg(".mmap_sec$12")) __stdcall MMIH_PreprocessModuleName(MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags)
{
	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	
	auto * ModNameA = NewObject<ANSI_STRING>(f);
	if (!ModNameA)
	{
		return STATUS_NO_MEMORY;
	}

	
	// Measure the module name in-image first: MMI_ImageStringLength returns 0
	// for an unterminated string, so this both rejects it here (defence in
	// depth - the import/delay-import callers already guard) and supplies the
	// bounded length InitAnsiString must scan within.
	const size_t module_name_length = MMI_ImageStringLength(pData, szModule);
	if (!module_name_length || !InitAnsiString(f, ModNameA, szModule, module_name_length))
	{
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
	}

	
	auto * ModNameW = NewObject<UNICODE_STRING>(f);
	if (!ModNameW)
	{
		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
	}

	
	ModNameW->szBuffer	= NewObject<wchar_t>(f, MAX_PATH);
	ModNameW->MaxLength = sizeof(wchar_t[MAX_PATH]);

	if (!ModNameW->szBuffer)
	{
		DeleteObject(f, ModNameW);
		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
	}

	
	ntRet = f->RtlAnsiStringToUnicodeString(ModNameW, ModNameA, FALSE);
	if (NT_FAIL(ntRet))
	{
		DeleteObject(f, ModNameW->szBuffer);
		DeleteObject(f, ModNameW);

		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return ntRet;
	}

	DeleteObject(f, ModNameA->szBuffer);
	DeleteObject(f, ModNameA);

	
	LDRP_UNICODE_STRING_BUNDLE * pModPathW = NewObject<LDRP_UNICODE_STRING_BUNDLE>(f);
	if (!pModPathW)
	{
		DeleteObject(f, ModNameW->szBuffer);
		DeleteObject(f, ModNameW);

		return STATUS_NO_MEMORY;
	}

	pModPathW->String.MaxLength = sizeof(pModPathW->StaticBuffer);
	pModPathW->String.szBuffer	= pModPathW->StaticBuffer;

	ntRet = f->LdrpPreprocessDllName(ModNameW, pModPathW, nullptr, CtxFlags);

	if (NT_SUCCESS(ntRet))
	{
		
		Module->Length		= pModPathW->String.Length;
		Module->MaxLength	= pModPathW->String.MaxLength;
		Module->szBuffer	= NewObject<wchar_t>(f, Module->MaxLength / sizeof(wchar_t));

		if (!Module->szBuffer)
		{
			DeleteObject(f, pModPathW);
			DeleteObject(f, ModNameW->szBuffer);
			DeleteObject(f, ModNameW);

			return STATUS_NO_MEMORY;
		}
		else
		{
			f->memmove(Module->szBuffer, pModPathW->StaticBuffer, Module->Length);
		}
	}
	else
	{
		DeleteObject(f, pModPathW);
		DeleteObject(f, ModNameW->szBuffer);
		DeleteObject(f, ModNameW);

		return ntRet;
	}

	DeleteObject(f, pModPathW);
	DeleteObject(f, ModNameW->szBuffer);
	DeleteObject(f, ModNameW);

	return STATUS_SUCCESS;
}

NTSTATUS __declspec(code_seg(".mmap_sec$13")) __stdcall MMIH_LoadModule(MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head)
{
	auto f = pData->FunctionTable;
	const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;

	NTSTATUS ntRet = STATUS_SUCCESS;

	// Opaque loader entry: field layout comes from the downloaded PDB
	// (NtOffsets), never sizeof/static offsets. Cast to void* and use
	// dynamic field access so a future LDR drift cannot misread DllBase.
	void * entry_out = nullptr;

	const DWORD ctx_size = dyno.LdrpPathSearchContextSize ? dyno.LdrpPathSearchContextSize : sizeof(LDRP_PATH_SEARCH_CONTEXT);
	const DWORD ctx_name_off = dyno.LdrpPathSearchOriginalFullDllName;
	void * ctx = NewBytes(f, ctx_size);
	if (!ctx)
	{
		return STATUS_NO_MEMORY;
	}

	if (ctx_name_off + sizeof(void *) <= ctx_size)
	{
		WritePtrField(ctx, ctx_name_off, Module->szBuffer);
	}
	else
	{
		// Static fallback shape when the PDB lacked the type: the legacy
		// reverse-engineered layout (kept only for allocation compat).
		ReCa<LDRP_PATH_SEARCH_CONTEXT *>(ctx)->OriginalFullDllName = Module->szBuffer;
	}

	f->LdrpLoadDllInternal(Module, ReCa<LDRP_PATH_SEARCH_CONTEXT *>(ctx), CtxFlag, 4, nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN11 **>(&entry_out), &ntRet, 0);

	DeleteObject(f, ctx);

	if (NT_SUCCESS(ntRet))
	{
		if (entry_out)
		{
			void * dll_base = ReadPtrField(entry_out, dyno.LdrEntryDllBase);
			*hModule = ReCa<HINSTANCE>(dll_base);

			MM_DEPENDENCY_RECORD * entry = nullptr;

			if (head)
			{
				entry = SearchDependencyRecordByHandle(*head, ReCa<HANDLE>(dll_base));
			}

			if (!entry)
			{
				const void * full_name_ptr = ReCa<const BYTE *>(entry_out) + dyno.LdrEntryFullDllName;
				entry = BuildDependencyRecord(f, head, ReCa<HANDLE>(*hModule), ReCa<const UNICODE_STRING *>(full_name_ptr));
				if (!entry && head)
				{
					f->LdrpDereferenceModule(ReCa<LDR_DATA_TABLE_ENTRY *>(entry_out));

					return STATUS_NO_MEMORY;
				}
			}

			f->LdrpDereferenceModule(ReCa<LDR_DATA_TABLE_ENTRY *>(entry_out));
		}
		else
		{
			ntRet = STATUS_DLL_NOT_FOUND;
		}
	}

	return ntRet;
}

#pragma endregion

DWORD __declspec(code_seg(".mmap_sec$01")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
{
	if (!pData || !pData->FunctionTable)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	pData->DllPath.szBuffer = pData->szPathBuffer;

	
	auto * f = pData->FunctionTable;
	if (!f->pLdrpHeap)
	{
		f->pLdrpHeap = *f->LdrpHeap;
	}

	if (!f->pLdrpHeap)
	{
		return INJ_MM_ERR_INVALID_HEAP_HANDLE;
	}

	auto ret = f->MMIP_MapSections(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_RelocateImage(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_InitializeCookie(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}
	
	ret = f->MMIP_LoadImports(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_LoadDelayImports(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_EnableExceptions(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_HandleTLS(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_ExecuteDllMain(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}
		
	
	// SetPageProtections is called AFTER CleanDataDirectories so that
	// cleanup routines can safely write to .rdata/.reloc/.tls (still RW).
	// This gives us truly read-only permissions on non-runtime data sections
	// (matching the real Windows loader's final state) while keeping
	// .data and .tls writable via the name-based fixup in MMI_MapSections.
	ret = f->MMIP_CleanDataDirectories(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_SetPageProtections(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	// CloakHeader erases the PE header only when INJ_ERASE_HEADER is set, but
	// it can still fail on the NtProtectVirtualMemory round-trip. A discarded
	// failure would let the shell report success with the header intact, so
	// treat it like every other pipeline stage: clean up and abort.
	ret = f->MMIP_CloakHeader(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	// No consumer past this point touches the dependency lists (host reads
	// only MapStats/hRet), so drop the nodes now instead of leaking one
	// LdrpHeap allocation set per injection.
	FreeDependencyNodeList(f, pData->pImportsHead);
	FreeDependencyNodeList(f, pData->pDelayImportsHead);

	pData->hRet = ReCa<HINSTANCE>(pData->pImageBase);

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$02")) __stdcall MMI_MapSections(MANUAL_MAPPING_DATA * pData)
{
	auto f = pData->FunctionTable;

	if (!(pData->Flags & INJ_MM_MAP_FROM_MEMORY) || !pData->pRawData || !pData->RawSize)
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	PE_IMAGE::OPTIONS options;
	options.RequireDll = true;
	options.RequireRelocations = true;
	options.ResolveImports = (pData->Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)) != 0;
	options.ResolveDelayImports = (pData->Flags & INJ_MM_RESOLVE_DELAY_IMPORTS) != 0;
	options.EnableExceptions = (pData->Flags & INJ_MM_ENABLE_EXCEPTIONS) != 0;
	options.InitializeSecurityCookie = (pData->Flags & INJ_MM_INIT_SECURITY_COOKIE) != 0;
	options.ExecuteTls = (pData->Flags & INJ_MM_EXECUTE_TLS) != 0;

	PE_IMAGE::VIEW view;
	if (PE_IMAGE::Validate(pData->pRawData, pData->RawSize, IMAGE_FILE_MACHINE_AMD64, options, view) != FILE_ERR_SUCCESS)
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	pData->pDosHeader = ReCa<IMAGE_DOS_HEADER *>(pData->pRawData);
	pData->pNtHeaders = ReCa<IMAGE_NT_HEADERS *>(pData->pRawData + pData->pDosHeader->e_lfanew);
	pData->pOptionalHeader = &pData->pNtHeaders->OptionalHeader;
	pData->pFileHeader = &pData->pNtHeaders->FileHeader;


	SIZE_T ImgSize = static_cast<SIZE_T>(pData->pOptionalHeader->SizeOfImage);

	// Stealth: image starts RW (never RWX). Executable sections are
	// promoted to RX just before TLS/DllMain need to execute, then
	// MMI_SetPageProtections applies the final RX/RW/RO split.
	pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), 0, &ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
	}

	
	pData->pImageBase = pData->pAllocationBase;

	
	f->memmove(pData->pImageBase, pData->pRawData, pData->pOptionalHeader->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pData->pNtHeaders);
	for (UINT i = 0; i != pData->pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			f->memmove(pData->pImageBase + pCurrentSectionHeader->VirtualAddress, pData->pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}

	pData->pDosHeader		= ReCa<IMAGE_DOS_HEADER *>(pData->pImageBase);
	pData->pNtHeaders		= ReCa<IMAGE_NT_HEADERS *>(pData->pImageBase + pData->pDosHeader->e_lfanew);
	pData->pOptionalHeader	= &pData->pNtHeaders->OptionalHeader;
	pData->pFileHeader		= &pData->pNtHeaders->FileHeader;

	// Fix section characteristics for compatibility with packed DLLs.
	// Packers strip IMAGE_SCN_MEM_WRITE from ALL data sections (.data, .rdata,
	// .tls, .reloc, .pdata). When SetPageProtections is enabled and runs AFTER
	// CleanDataDirectories (reordered pipeline), these sections would be set
	// to PAGE_READONLY. However:
	//   - .data and .tls MUST remain PAGE_READWRITE (the DLL writes to globals
	//     and TLS at runtime during normal operation)
	//   - .rdata, .reloc, .pdata should remain PAGE_READONLY (truly read-only)
	// This fixup restores MEM_WRITE ONLY to .data and .tls sections by name,
	// keeping all other data sections genuinely read-only for maximum stealth.
	if (pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			// Check section name manually (avoid CRT dependency in remote shell)
			const char *name = ReCa<const char *>(pSec->Name);

			bool is_data_section = (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0
				&& (pSec->Characteristics & IMAGE_SCN_MEM_WRITE) == 0
				&& (pSec->Characteristics & IMAGE_SCN_MEM_READ);

			if (is_data_section)
			{
				// Only .data and .tls need to stay writable at runtime
				// (the DLL writes to globals and TLS during normal operation).
				// Manual byte comparison avoids CRT function calls (this code
				// runs in the remote process where CRT is not available).
				bool is_data_name = (name[0] == '.' && name[1] == 'd' &&
					name[2] == 'a' && name[3] == 't' && name[4] == 'a');
				bool is_tls_name = (name[0] == '.' && name[1] == 't' &&
					name[2] == 'l' && name[3] == 's');

				if (is_data_name || is_tls_name)
				{
					pSec->Characteristics |= IMAGE_SCN_MEM_WRITE;
				}
				// All other read-only data sections (.rdata, .reloc, .pdata)
				// remain without MEM_WRITE → PAGE_READONLY (maximum stealth)
			}
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$03")) __stdcall MMI_RelocateImage(MANUAL_MAPPING_DATA * pData)
{
	BYTE * LocationDelta = pData->pImageBase - pData->pOptionalHeader->ImageBase;

	
	if (LocationDelta)
	{
		auto * pRelocDir = ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		if (!pRelocDir->Size || pRelocDir->Size < sizeof(IMAGE_BASE_RELOCATION))
		{
			return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
		}

		if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pRelocDir->VirtualAddress), pRelocDir->Size))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + pRelocDir->VirtualAddress);
		auto * pRelocEnd = ReCa<BYTE *>(pRelocData) + pRelocDir->Size;

		while (ReCa<BYTE *>(pRelocData) < pRelocEnd)
		{
			if (pRelocData->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
				pRelocData->SizeOfBlock > static_cast<DWORD>(pRelocEnd - ReCa<BYTE *>(pRelocData)) ||
				((pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0)
			{
				return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
			}

			WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
			UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (UINT i = 0; i < RelocCount; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					const ULONGLONG patch_rva = static_cast<ULONGLONG>(pRelocData->VirtualAddress) + (*pRelativeInfo & 0xFFF);
					if (patch_rva + sizeof(ULONG_PTR) > pData->pOptionalHeader->SizeOfImage)
					{
						return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
					}

					ULONG_PTR * pPatch = ReCa<ULONG_PTR *>(pData->pImageBase + static_cast<SIZE_T>(patch_rva));
					*pPatch += ReCa<ULONG_PTR>(LocationDelta);
				}
			}

			pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
		}

		pData->pOptionalHeader->ImageBase += ReCa<ULONG_PTR>(LocationDelta);
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$04")) __stdcall MMI_InitializeCookie(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_INIT_SECURITY_COOKIE) || !pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
	{
		

		return INJ_ERR_SUCCESS;
	}

	ULONGLONG new_cookie = ((UINT_PTR)pData->pImageBase) & 0x0000FFFFFFFFFFFF;
	if (new_cookie == 0x2B992DDFA232)
	{
		++new_cookie;
	}
	else if (!(new_cookie & 0x0000FFFF00000000))
	{
		new_cookie |= (new_cookie | 0x4711) << 0x10;
	}

	const IMAGE_DATA_DIRECTORY & load_config = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (load_config.Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONG_PTR) ||
		!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + load_config.VirtualAddress), sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	auto pLoadConfigData = ReCa<IMAGE_LOAD_CONFIG_DIRECTORY *>(pData->pImageBase + load_config.VirtualAddress);
	// LoadConfig.SecurityCookie is the VA of the cookie variable (in .data),
	// not the cookie value itself. The Windows loader writes the fresh cookie
	// to *SecurityCookie. Overwriting the field itself corrupts the directory
	// and leaves ___security_cookie at the default 0x2B992DDFA232, so /GS
	// integrity checks fail and DllMain returns FALSE (00400013).
	if (!pLoadConfigData->SecurityCookie)
	{
		return INJ_ERR_SUCCESS;
	}
	if (!MMI_InImage(pData, ReCa<void *>(pLoadConfigData->SecurityCookie), sizeof(ULONG_PTR)))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}
	*ReCa<ULONG_PTR *>(pLoadConfigData->SecurityCookie) = static_cast<ULONG_PTR>(new_cookie);

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$06")) __stdcall MMI_LoadImports(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	IMAGE_DATA_DIRECTORY	* pImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	IMAGE_IMPORT_DESCRIPTOR * pImportDescr	= nullptr;
	IMAGE_IMPORT_DESCRIPTOR * const pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size);

	if (pImportDir->Size)
	{
		pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress);

		if (!MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}
	}

	bool ErrorBreak = false;

	while (pImportDescr && pImportDescr < pImportEnd && MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)) && pImportDescr->Name)
	{
		
		auto * szModule = ReCa<const char *>(pData->pImageBase + pImportDescr->Name);

		if (!MMI_ImageStringLength(pData, szModule))
		{
			ErrorBreak = true;
			break;
		}

		UNICODE_STRING ModNameW{ 0 };

		ModNameW.MaxLength	= MAX_PATH * sizeof(wchar_t);
		ModNameW.szBuffer	= nullptr;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->MMIHP_PreprocessModuleName(pData, szModule, &ModNameW, &ctx_flags);
		if (NT_FAIL(ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (ntRet == STATUS_APISET_NOT_HOSTED)
			{
				++pImportDescr;

				if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		HINSTANCE hDll = NULL;

		pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pImportsHead);
		
		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (pData->ntRet == STATUS_APISET_NOT_HOSTED)
			{
				++pImportDescr;

				if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
				{
					break;
				}

				continue;
			}

			
			ErrorBreak = true;
			break;
		}

		// ModNameW is only consumed by LoadModule; free it on the success path
		// too. The failure paths above and the delay-import twin already do, so
		// the old code leaked one remote buffer per imported module.
		DeleteObject(f, ModNameW.szBuffer);

		
		if (!pImportDescr->FirstThunk)
		{
			ErrorBreak = true;
			break;
		}

		IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->OriginalFirstThunk);
		IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->FirstThunk);

		if (!pImportDescr->OriginalFirstThunk)
		{
			pThunk = pIAT;
		}

		// FirstThunk is written by the loop below. An out-of-image IAT makes
		// the loop's entry test false before anything is bound, so the shell
		// would report success with an unbound IAT and the payload would fault
		// later; FirstThunk == 0 aliases pIAT to the DOS/NT headers. Validation
		// rejects both shapes before mapping, but the shell must not rely on a
		// host-side check.
		if (!MMI_InImage(pData, pIAT, sizeof(*pIAT)) || !MMI_InImage(pData, pThunk, sizeof(*pThunk)))
		{
			ErrorBreak = true;
			break;
		}

		for (; pThunk && MMI_InImage(pData, pThunk, sizeof(*pThunk)) && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
		{
			UINT_PTR * pFuncRef = ReCa<UINT_PTR *>(pIAT);

			IMAGE_IMPORT_BY_NAME * pImport;
			if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
			{
				

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pThunk->u1.Ordinal), ReCa<void **>(pFuncRef));
			}
			else
			{
				
			if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pThunk->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
			{
				ErrorBreak = true;
				break;
			}

			pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pThunk->u1.AddressOfData));

			const size_t import_name_length = MMI_ImageStringLength(pData, pImport->Name);

			auto * ansi_import = NewObject<ANSI_STRING>(f);
			if (!ansi_import || !import_name_length || import_name_length > 0xFFFF)
			{
				DeleteObject(f, ansi_import);
				ErrorBreak = true;
				break;
			}

			ansi_import->szBuffer	= pImport->Name;
			ansi_import->Length		= static_cast<WORD>(import_name_length);
			ansi_import->MaxLength	= static_cast<WORD>((ansi_import->Length + 1) * sizeof(char));

				

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), ansi_import, 0, ReCa<void **>(pFuncRef));

				DeleteObject(f, ansi_import);
			}

			if (NT_FAIL(pData->ntRet))
			{
				
				ErrorBreak = true;
				break;
			}
		}

		if (ErrorBreak)
		{
			break;
		}

		++pImportDescr;

		
		if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
		{
			break;
		}
	}

	if (ErrorBreak)
	{
		return INJ_MM_ERR_IMPORT_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$07")) __stdcall MMI_LoadDelayImports(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RESOLVE_DELAY_IMPORTS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	IMAGE_DATA_DIRECTORY		* pDelayImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
	IMAGE_DELAYLOAD_DESCRIPTOR	* pDelayImportDescr = nullptr;
	IMAGE_DELAYLOAD_DESCRIPTOR	* const pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size);

	if (pDelayImportDir->Size)
	{
		pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress);

		if (!MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}
	}

	bool ErrorBreak = false;

	while (pDelayImportDescr && pDelayImportDescr < pDelayImportEnd && MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)) && pDelayImportDescr->DllNameRVA)
	{
		auto * szModule = ReCa<const char *>(pData->pImageBase + pDelayImportDescr->DllNameRVA);

		if (!MMI_ImageStringLength(pData, szModule))
		{
			ErrorBreak = true;
			break;
		}
		
		UNICODE_STRING ModNameW{ 0 };

		ModNameW.MaxLength	= MAX_PATH * sizeof(wchar_t);
		ModNameW.szBuffer	= nullptr;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->MMIHP_PreprocessModuleName(pData, szModule, &ModNameW, &ctx_flags);
		if (NT_FAIL(ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (ntRet == STATUS_APISET_NOT_HOSTED)
			{
				++pDelayImportDescr;

				if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		HINSTANCE hDll = NULL;

		pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pDelayImportsHead);
		
		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (pData->ntRet == STATUS_APISET_NOT_HOSTED)
			{
				++pDelayImportDescr;

				if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		DeleteObject(f, ModNameW.szBuffer);

		if (pDelayImportDescr->ModuleHandleRVA)
		{
			if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pDelayImportDescr->ModuleHandleRVA), sizeof(HINSTANCE)))
			{
				ErrorBreak = true;
				break;
			}

			HINSTANCE * pModule = ReCa<HINSTANCE *>(pData->pImageBase + pDelayImportDescr->ModuleHandleRVA);
			*pModule = hDll;
		}

		if (!pDelayImportDescr->ImportAddressTableRVA || !pDelayImportDescr->ImportNameTableRVA)
		{
			ErrorBreak = true;
			break;
		}

		IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportAddressTableRVA);
		IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportNameTableRVA);

		// Same guard as the classic import path: an out-of-image delay IAT
		// makes the loop's entry test false and leaves the IAT unbound while
		// the shell still reports success. Validation rejects it before
		// mapping; keep the shell safe on its own.
		if (!MMI_InImage(pData, pIAT, sizeof(*pIAT)) || !MMI_InImage(pData, pNameTable, sizeof(*pNameTable)))
		{
			ErrorBreak = true;
			break;
		}

		for (; pIAT && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && MMI_InImage(pData, pNameTable, sizeof(*pNameTable)) && pIAT->u1.Function; ++pIAT, ++pNameTable)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
			{
				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(pIAT));
			}
			else
			{
				if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pNameTable->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					ErrorBreak = true;
					break;
				}

				auto pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pNameTable->u1.AddressOfData));

				const size_t import_name_length = MMI_ImageStringLength(pData, pImport->Name);

				auto * ansi_import= NewObject<ANSI_STRING>(f);
				if (!ansi_import || !import_name_length || import_name_length > 0xFFFF)
				{
					DeleteObject(f, ansi_import);
					ErrorBreak = true;
					break;
				}

				ansi_import->szBuffer	= pImport->Name;
				ansi_import->Length		= static_cast<WORD>(import_name_length);
				ansi_import->MaxLength	= static_cast<WORD>((ansi_import->Length + 1) * sizeof(char));

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), ansi_import, 0, ReCa<void **>(pIAT));

				DeleteObject(f, ansi_import);
			}

			if (NT_FAIL(pData->ntRet))
			{
				ErrorBreak = true;
				break;
			}
		}

		if (ErrorBreak)
		{
			break;
		}

		++pDelayImportDescr;

		if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
		{
			break;
		}
	}

	if (ErrorBreak)
	{
		return INJ_MM_ERR_DELAY_IMPORT_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$08")) __stdcall MMI_SetPageProtections(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	ULONG OldProtection = 0;
	SIZE_T SizeOut = pData->pOptionalHeader->SizeOfHeaders;
	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pImageBase), &SizeOut, PAGE_READONLY, &OldProtection);

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	
	auto pCurrentSectionHeader = IMAGE_FIRST_SECTION(pData->pNtHeaders);

	for (UINT i = 0; i != pData->pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		void * pSectionBase		= pData->pImageBase + pCurrentSectionHeader->VirtualAddress;
		DWORD characteristics	= pCurrentSectionHeader->Characteristics;
		SIZE_T SectionSize		= (std::max)(static_cast<SIZE_T>(pCurrentSectionHeader->Misc.VirtualSize), static_cast<SIZE_T>(pCurrentSectionHeader->SizeOfRawData));

		if (SectionSize)
		{
			// W^X: executable sections are RX only. WRITE is stripped even
			// when IMAGE_SCN_MEM_WRITE is set (W+X -> RX). No RWX ever.
			ULONG NewProtection = PAGE_NOACCESS;

			if (characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				if (characteristics & IMAGE_SCN_MEM_READ)
				{
					NewProtection = PAGE_EXECUTE_READ;
				}
				else
				{
					NewProtection = PAGE_EXECUTE;
				}
			}
			else
			{
				if (characteristics & IMAGE_SCN_MEM_WRITE)
				{
					NewProtection = PAGE_READWRITE;
				}
				else if (characteristics & IMAGE_SCN_MEM_READ)
				{
					NewProtection = PAGE_READONLY;
				}
			}

			
			pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &pSectionBase, &SectionSize, NewProtection, &OldProtection);
			if (NT_FAIL(pData->ntRet))
			{
				break;
			}
		}
	}

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$09")) __stdcall MMI_EnableExceptions(MANUAL_MAPPING_DATA * pData)
{
	// SEH-only: inverted table + RtlAddFunctionTable + fake dir when needed.
	// Zero VEH chain entries by design (no handler, no tail, no mrdata VEH
	// retry): the VEH shim was removed as the hottest Warden walk surface.
	if (!(pData->Flags & INJ_MM_ENABLE_EXCEPTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	// W^X: image was allocated RW. Promote code RW->RX only.
	// WRITE stripped (W+X -> RX). No RWX exists at any point. Idempotent with
	// the TLS/DllMain promotions; still promotes here so an image with TLS=N
	// + DllMain=N does not stay RW until SetPageProtections.
	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				void * base = pData->pImageBase + pSec->VirtualAddress;
				SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;
				if (sec_size)
				{
					constexpr ULONG new_prot = PAGE_EXECUTE_READ;
					ULONG old_prot = 0;
					// A failed promotion leaves the section W+X, so abort rather
					// than continue with a non-W^X image.
					pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, new_prot, &old_prot);
					if (NT_FAIL(pData->ntRet))
					{
						return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
					}
				}
			}
		}
	}

	// RtlInsertInvertedFunctionTable is undocumented and its return value is
	// not a status (ntdll tail-calls the void SRW-lock release), so success is
	// confirmed by finding our entry in the table below, not by the call's
	// result. A missing entry means the exception directory was never
	// registered; the post-loop check turns that into a failure.
	f->RtlInsertInvertedFunctionTable(pData->pImageBase, pData->pOptionalHeader->SizeOfImage);

	pData->ntRet = STATUS_DLL_NOT_FOUND;
	bool partial = true;
	bool inverted_entry_found = false;

	// Download-dependent inverted-table walk: Count/Entries base and every
	// entry field come from NtOffsets (PDB), never static struct offsets.
	// KUSER cookie likewise comes from NtOffsets.KuserCookie.
	{
		const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;
		const BYTE * table_base = ReCa<const BYTE *>(f->LdrpInvertedFunctionTable);
		if (table_base && dyno.InvertedTableCount + sizeof(DWORD) <= 0x100 && dyno.InvertedTableEntries < 0x100 && dyno.InvertedEntrySize >= 8 && dyno.InvertedEntrySize < 0x100)
		{
			const DWORD inv_count = *ReCa<const DWORD *>(table_base + dyno.InvertedTableCount);
			const BYTE * entries_base = table_base + dyno.InvertedTableEntries;
			for (ULONG i = 0; i < inv_count; ++i)
			{
				const BYTE * entry = entries_base + static_cast<SIZE_T>(i) * dyno.InvertedEntrySize;
				void * entry_base = *ReCa<void * const *>(entry + dyno.InvertedEntryImageBase);
				if (entry_base != pData->pImageBase)
				{
					continue;
				}
				inverted_entry_found = true;
				const DWORD exc_size = *ReCa<const DWORD *>(entry + dyno.InvertedEntryExceptionDirectorySize);
				if (exc_size)
				{
					partial = false;
					pData->ntRet = STATUS_SUCCESS;
					break;
				}
				SIZE_T FakeDirSize = 0x800 * sizeof(void *);
				pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), &pData->pFakeSEHDirectory, 0, &FakeDirSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (NT_FAIL(pData->ntRet))
				{
					break;
				}
				UINT_PTR pRaw = ReCa<UINT_PTR>(pData->pFakeSEHDirectory);
				const DWORD cookie = *ReCa<volatile DWORD *>(ReCa<BYTE *>(static_cast<UINT_PTR>(KUSER_SHARED_DATA)) + dyno.KuserCookie);
				UINT_PTR pEncoded = bit_rotate_r(cookie ^ pRaw, cookie & 0x3F);
				f->LdrProtectMrdata(FALSE);
				*ReCa<void **>(ReCa<BYTE *>(const_cast<BYTE *>(entry)) + dyno.InvertedEntryExceptionDirectory) = ReCa<void *>(pEncoded);
				f->LdrProtectMrdata(TRUE);
				break;
			}
		}
	}

	// A missing inverted-table entry means SEH was never installed.
	if (!inverted_entry_found)
	{
		pData->ntRet = STATUS_UNSUCCESSFUL;
	}

#ifdef _WIN64
	if (NT_SUCCESS(pData->ntRet) && partial)
	{

		auto size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
		if (size)
		{
			auto * pExceptionHandlers = ReCa<RUNTIME_FUNCTION *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
			auto EntryCount = size / sizeof(RUNTIME_FUNCTION);

			if (!f->RtlAddFunctionTable(pExceptionHandlers, MDWD(EntryCount), ReCa<DWORD64>(pData->pImageBase)))
			{
				pData->ntRet = STATUS_UNSUCCESSFUL;
			}
			else
			{
				// The loader now holds a function-table entry pointing into
				// the image. Record it so MMI_CleanUp can remove it before the
				// image is freed; otherwise it dangles in the loader's list.
				pData->pDynamicFunctionTable = pExceptionHandlers;
			}
		}
		else
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
		}
	}
#endif

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_ENABLING_SEH_FAILED;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0A")) __stdcall MMI_HandleTLS(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_EXECUTE_TLS))
	{
		return INJ_ERR_SUCCESS;
	}

	if (!pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), sizeof(IMAGE_TLS_DIRECTORY)))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	// W^X: TLS callbacks execute from the image: ensure code is RX even
	// when exceptions (and their promotion above) are disabled. Idempotent.
	// WRITE stripped (W+X -> RX). No RWX.
	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				void * base = pData->pImageBase + pSec->VirtualAddress;
				SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;
				if (sec_size)
				{
					constexpr ULONG new_prot = PAGE_EXECUTE_READ;
					ULONG old_prot = 0;
					// A failed promotion leaves the section W+X, so abort rather
					// than continue with a non-W^X image.
					pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, new_prot, &old_prot);
					if (NT_FAIL(pData->ntRet))
					{
						return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
					}
				}
			}
		}
	}

	// Download-dependent dummy LDR entry: size + DllBase offset from PDB.
	const DWORD ldr_size = pData->NtOffsets.LdrEntrySize ? pData->NtOffsets.LdrEntrySize : sizeof(LDR_DATA_TABLE_ENTRY_WIN11);
	const DWORD ldr_base_off = pData->NtOffsets.LdrEntryDllBase;
	if (!ldr_size || ldr_size > 0x1000 || ldr_base_off + sizeof(void *) > ldr_size)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}
	void * pDummyLdrRaw = NewBytes(f, ldr_size);
	if (!pDummyLdrRaw)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}
	WritePtrField(pDummyLdrRaw, ldr_base_off, pData->pImageBase);
	// pDummyLdrRaw is non-null (checked above); a reinterpret_cast of a
	// non-null pointer cannot be null, so no second null check is needed.
	auto * pDummyLdr = ReCa<LDR_DATA_TABLE_ENTRY *>(pDummyLdrRaw);

	
	

	// DllBase already written via WritePtrField above (download-dependent offset).

	// LdrpHandleTlsData allocates the module's TLS slots; a discarded failure
	// would leave the DLL's TLS silently uninitialised. Surface the loader
	// status through the same clean-up path the other stages use. No dedicated
	// INJ_MM_ERR_* exists for TLS, so the raw NTSTATUS is propagated (the host
	// already reports data.ntRet as the advanced code).
	pData->ntRet = f->LdrpHandleTlsData(pDummyLdr);
	if (NT_FAIL(pData->ntRet))
	{
		// Freeing the dummy LDR entry here is safe only if LdrpHandleTlsData
		// cannot fail after linking a TLS_ENTRY whose ModuleEntry is pDummyLdr
		// into LdrpTlsList. Whether it can is an ntdll internal this source
		// cannot establish: the ordering of LdrpAllocateTlsEntry, the list
		// insertion and the later raw-data copy (each a possible failure point)
		// is not visible here. If a failure can follow the insertion, this
		// DeleteObject leaves a dangling ModuleEntry in LdrpTlsList for the life
		// of the target. Resolving it needs the target build's
		// LdrpHandleTlsData (disassembly or checked build): if insertion can
		// precede a failure return, this path must unlink the entry, mirroring
		// the success path below, before freeing. The free is not deferred on
		// that guess - the entry must not outlive the image, and freeing later
		// is not obviously safer.
		DeleteObject(f, pDummyLdr);

		return static_cast<DWORD>(pData->ntRet);
	}

	
	ULONG callback_count = 0;
	auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
	while (pCallback && MMI_InImage(pData, pCallback, sizeof(*pCallback)) && *pCallback && callback_count < 1024)
	{
		auto Callback = *pCallback;
		if (!MMI_InImage(pData, ReCa<void *>(Callback), sizeof(BYTE)))
		{
			break;
		}

		Callback(pData->pImageBase, DLL_PROCESS_ATTACH, nullptr);
		++callback_count;
		++pCallback;
	}

	
	if (f->LdrpTlsList)
	{
		auto current = f->LdrpTlsList->Flink;
		while (current && current != f->LdrpTlsList)
		{
			auto entry_bytes = ReCa<BYTE *>(current);
			current = current->Flink;
			void * tls_mod = ReadPtrField(entry_bytes, pData->NtOffsets.TlsEntryModuleEntry);
			if (tls_mod == pDummyLdr)
			{
				ReCa<LIST_ENTRY *>(entry_bytes)->Blink->Flink = ReCa<LIST_ENTRY *>(entry_bytes)->Flink;
				ReCa<LIST_ENTRY *>(entry_bytes)->Flink->Blink = ReCa<LIST_ENTRY *>(entry_bytes)->Blink;

				break;
			}
		}
	}

	
	DeleteObject(f, pDummyLdr);

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0B")) __stdcall MMI_ExecuteDllMain(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RUN_DLL_MAIN))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!pData->pOptionalHeader->AddressOfEntryPoint)
	{
		return INJ_ERR_SUCCESS;
	}

	ULONG		State	= 0;
	ULONG_PTR	Cookie	= 0;
	bool		locked	= false;

	// W^X: DllMain executes from the image: promote code RW->RX if TLS/
	// exceptions stages were skipped. Idempotent when already done.
	// WRITE stripped (W+X -> RX). No RWX.
	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				void * base = pData->pImageBase + pSec->VirtualAddress;
				SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;
				if (sec_size)
				{
					constexpr ULONG new_prot = PAGE_EXECUTE_READ;
					ULONG old_prot = 0;
					// A failed promotion leaves the section W+X, so abort rather
					// than continue with a non-W^X image.
					pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, new_prot, &old_prot);
					if (NT_FAIL(pData->ntRet))
					{
						return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
					}
				}
			}
		}
	}

	if (pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK)
	{
		pData->ntRet = f->LdrLockLoaderLock(NULL, &State, &Cookie);

		
		locked = NT_SUCCESS(pData->ntRet);
		if (!locked)
		{
			return INJ_MM_ERR_LOADER_LOCK_FAILED;
		}
	}

	f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pData->pImageBase + pData->pOptionalHeader->AddressOfEntryPoint);
	if (!DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_ATTACH, nullptr))
	{
		// Loader contract: an entry point that fails ATTACH is still notified
		// with DLL_PROCESS_DETACH before the image is unloaded, so state
		// partially initialised during ATTACH gets to unwind. The loader
		// ignores the result and holds the loader lock across both calls, so
		// this must run before the unlock below. Not a double-call bug.
		DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_DETACH, nullptr);

		if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
		{
			f->LdrUnlockLoaderLock(NULL, Cookie);
		}

		return INJ_MM_ERR_DLLMAIN_FAILED;
	}

	if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
	{
		f->LdrUnlockLoaderLock(NULL, Cookie);
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0C")) __stdcall MMI_CleanDataDirectories(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_CLEAN_DATA_DIR))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	// Record the pre-cleanup directory sizes so the host can report the real
	// result: the PE header is erased later, so the target image can no longer
	// be inspected for these values.
	pData->MapStats.ImportSize		= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	pData->MapStats.DelayImportSize	= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	pData->MapStats.DebugSize		= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	pData->MapStats.RelocSize		= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	pData->MapStats.TlsSize			= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	pData->MapStats.CleanedMask		=
		((pData->MapStats.ImportSize		? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_IMPORT) |
		((pData->MapStats.DelayImportSize	? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) |
		((pData->MapStats.DebugSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_DEBUG) |
		((pData->MapStats.RelocSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_BASERELOC) |
		((pData->MapStats.TlsSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_TLS);
	pData->MapStats.Reserved = 0;

	
	DWORD Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (Size)
	{
		auto * pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + Size);
		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr && pImportDescr < pImportEnd && MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)) && pImportDescr->Name)
		{
			const size_t mod_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pImportDescr->Name));
			// Zero the name plus its terminator only when the whole
			// [name, name + mod_length] range is provably in-image. mod_length
			// is bounded by SizeOfImage - offset, so +1 must not be assumed to
			// fit; MMI_InImage makes the write in-image for every input. size_t
			// cannot overflow here: mod_length <= SizeOfImage <= ULONG_MAX.
			if (mod_length && MMI_InImage(pData, pData->pImageBase + pImportDescr->Name, mod_length + 1))
			{
				f->RtlZeroMemory(pData->pImageBase + pImportDescr->Name, mod_length + 1);
			}
			pImportDescr->Name = 0;

			if (!pImportDescr->OriginalFirstThunk && !pImportDescr->FirstThunk)
			{
				break;
			}

			IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->OriginalFirstThunk);
			IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
			{
				pThunk = pIAT;
			}

			for (; pThunk && MMI_InImage(pData, pThunk, sizeof(*pThunk)) && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
				{
					pThunk->u1.Ordinal = 0;
				}
				else if (MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pThunk->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					auto * pImport	= ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pThunk->u1.AddressOfData));
					const size_t func_length = MMI_ImageStringLength(pData, pImport->Name);
					// Same +1 bound as the module name above: the IMAGE_IMPORT_BY_NAME
					// header was checked in-image, but Name is a trailing array that
					// can run to the tail of the image, so only zero when
					// [Name, Name + func_length] is provably in-image.
					if (func_length && MMI_InImage(pData, pImport->Name, func_length + 1))
					{
						f->RtlZeroMemory(pImport->Name, func_length + 1);
					}
				}
			}

			pImportDescr->OriginalFirstThunk = 0;
			pImportDescr->FirstThunk = 0;

			++pImportDescr;
		}

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	}

	
	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	if (Size)
	{
		auto * pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress + Size);
		auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

		while (pDelayImportDescr && pDelayImportDescr < pDelayImportEnd && MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)) && pDelayImportDescr->DllNameRVA)
		{
			const size_t mod_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pDelayImportDescr->DllNameRVA));
			// Same explicit in-image bound as the import module name above: the
			// +1 terminator write must stay inside the committed image even when
			// mod_length reaches the tail of the image.
			if (mod_length && MMI_InImage(pData, pData->pImageBase + pDelayImportDescr->DllNameRVA, mod_length + 1))
			{
				f->RtlZeroMemory(pData->pImageBase + pDelayImportDescr->DllNameRVA, mod_length + 1);
			}
			pDelayImportDescr->DllNameRVA = 0;

			pDelayImportDescr->ModuleHandleRVA = 0;

			if (!pDelayImportDescr->ImportAddressTableRVA || !pDelayImportDescr->ImportNameTableRVA)
			{
				break;
			}

			IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportAddressTableRVA);
			IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportNameTableRVA);

			for (; pIAT && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && MMI_InImage(pData, pNameTable, sizeof(*pNameTable)) && pIAT->u1.Function; ++pIAT, ++pNameTable)
			{

				if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
				{
					pNameTable->u1.Ordinal = 0;
				}
				else if (MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pNameTable->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					auto * pImport	= ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pNameTable->u1.AddressOfData));
					const size_t func_length = MMI_ImageStringLength(pData, pImport->Name);
					// Same explicit in-image bound as the import function name
					// above: the trailing Name array can reach the image tail.
					if (func_length && MMI_InImage(pData, pImport->Name, func_length + 1))
					{
						f->RtlZeroMemory(pImport->Name, func_length + 1);
					}
				}
			}

			pDelayImportDescr->ImportAddressTableRVA = 0;
			pDelayImportDescr->ImportNameTableRVA = 0;

			++pDelayImportDescr;
		}

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	}

	
	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	if (Size)
	{
		auto * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
		if (!MMI_InImage(pData, pDebugDir, sizeof(*pDebugDir)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		BYTE * pDebugData = pData->pImageBase + pDebugDir->AddressOfRawData;
		if (pDebugDir->SizeOfData && !MMI_InImage(pData, pDebugData, pDebugDir->SizeOfData))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		f->RtlZeroMemory(pDebugData, pDebugDir->SizeOfData);

		pDebugDir->SizeOfData = 0;
		pDebugDir->AddressOfRawData = 0;
		pDebugDir->PointerToRawData = 0;

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}

	
	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (Size)
	{
		auto * pRelocEnd = ReCa<BYTE *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + Size);
		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (ReCa<BYTE *>(pRelocData) + sizeof(IMAGE_BASE_RELOCATION) <= pRelocEnd && pRelocData->VirtualAddress)
		{
			if (pRelocData->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
				pRelocData->SizeOfBlock > static_cast<DWORD>(pRelocEnd - ReCa<BYTE *>(pRelocData)))
			{
				break;
			}

			WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
			UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			f->RtlZeroMemory(pRelativeInfo, RelocCount * sizeof(WORD));

			pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
		}

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	}

	
	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (Size)
	{
		if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), sizeof(IMAGE_TLS_DIRECTORY)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		auto * pTLS			= ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback	= ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
		ULONG callback_count = 0;
		for (; pCallback && MMI_InImage(pData, pCallback, sizeof(*pCallback)) && (*pCallback) && callback_count < 1024; ++pCallback, ++callback_count)
		{
			*pCallback = nullptr;
		}

		pTLS->AddressOfCallBacks	= 0;
		pTLS->AddressOfIndex		= 0;
		pTLS->EndAddressOfRawData	= 0;
		pTLS->SizeOfZeroFill		= 0;
		pTLS->StartAddressOfRawData = 0;

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress	= 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size			= 0;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0D")) __stdcall MMI_CloakHeader(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_ERASE_HEADER))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	void * base			= pData->pImageBase;
	SIZE_T header_size	= pData->pOptionalHeader->SizeOfHeaders;
	ULONG old_access	= NULL;

	
	if (pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		// W^X: header is data, never code. RW suffices to zero it.
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &header_size, PAGE_READWRITE, &old_access);

		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	// Only header erasure is supported: the whole header is zeroed so a
	// signature scan of the image base finds nothing to anchor on.
	f->RtlZeroMemory(pData->pImageBase, header_size);

	
	if (pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &header_size, old_access, &old_access);

		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0E")) __stdcall MMI_CleanUp(MANUAL_MAPPING_DATA * pData)
{
	if (!pData || !pData->FunctionTable)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	auto f = pData->FunctionTable;

	// Forensic wipe of the staging block, which carries the operator's on-disk
	// DLL path (the mapped image never does). This runs only if the shell
	// reaches MMI_CleanUp. On SR_HT_ERR_REMOTE_TIMEOUT /
	// SR_HT_ERR_RECOVERY_REQUIRED the host deliberately release()s the block
	// (ManualMapping.cpp:394 and the release() sites in ThreadHijacking.cpp)
	// because the shell may still be executing from it; if the shell never
	// reaches this point, the wipe never runs and the path stays readable in
	// the target. It is therefore best-effort, not a guarantee, and cannot be
	// hoisted earlier: the block must stay intact while remote code may still
	// run from it.
	f->RtlZeroMemory(pData->szPathBuffer, sizeof(pData->szPathBuffer));
	f->RtlZeroMemory(&pData->DllPath, sizeof(pData->DllPath));
	f->RtlZeroMemory(pData->NtPathPrefix, sizeof(pData->NtPathPrefix));

	if (pData->pFakeSEHDirectory)
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pFakeSEHDirectory), &Size, MEM_RELEASE);
	}

	if (pData->pDelayImportsHead)
	{
		UnloadAndDeleteDependencyRecord(f, pData->pDelayImportsHead);
	}

	if (pData->pImportsHead)
	{
		UnloadAndDeleteDependencyRecord(f, pData->pImportsHead);
	}

	// Loader bookkeeping that points into the image must be undone here,
	// before the image is freed below, or it dangles for the life of the
	// target.
	//
	// Dynamic function table: MMI_EnableExceptions may have registered the
	// image's .pdata with RtlAddFunctionTable (only when the loader had no
	// exception-directory entry for the image). pDynamicFunctionTable records
	// that pointer at insert time, so remove it now. Best-effort: a build
	// without the documented RtlDeleteFunctionTable export leaves the field
	// null and this is skipped - cleanup must never fail the injection, so the
	// result is deliberately ignored.
	if (pData->pDynamicFunctionTable && f->RtlDeleteFunctionTable)
	{
		f->RtlDeleteFunctionTable(pData->pDynamicFunctionTable);
	}

	// Inverted function table: RtlInsertInvertedFunctionTable added an entry
	// for this image during MMI_EnableExceptions (the fake SEH directory it
	// may point at is freed above). ntdll exposes NO removal routine for it: a
	// dumpbin /exports of ntdll.dll lists only KiUserInvertedFunctionTable and
	// has no RtlRemoveInvertedFunctionTable / RtlpRemoveInvertedFunctionTable.
	// Hand-rolling the loader's version-specific table surgery would be a new
	// crash risk, so the entry is left in place; it points into the image and
	// therefore dangles after the free below.
	//
	// TLS: LdrpHandleTlsData (MMI_HandleTLS) allocated a loader TLS index and
	// data block. MMI_HandleTLS already unlinks the TLS_ENTRY from LdrpTlsList,
	// but neither the index nor the block is reclaimed. The index is readable
	// at insert time (TLS_ENTRY.TlsIndex), yet no provably-correct release
	// exists from this shell: ntdll exports no removal routine for the loader's
	// index (only the unrelated RtlTlsAlloc/RtlTlsFree are present), TlsFree is
	// a kernel32 API the shell does not resolve, and freeing an index while
	// every thread's TEB TLS slot still holds the loader's block pointer would
	// let a later TlsAlloc hand out a stale pointer. The slot and block are
	// therefore deliberately left behind.
	//
	// Both leftovers are why a failed attempt should be followed by a target
	// restart rather than another attempt in the same process.

	if (pData->pAllocationBase)
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), &Size, MEM_RELEASE);
	}

	return 0;
}

#ifndef AMEGER_MMAP_SENTINEL
#define AMEGER_MMAP_SENTINEL 1337
#endif

DWORD __declspec(code_seg(".mmap_sec$14")) MMAP_SEC_END()
{
	return AMEGER_MMAP_SENTINEL;
}

MANUAL_MAPPING_FUNCTION_TABLE::MANUAL_MAPPING_FUNCTION_TABLE()
{
	NT_FUNC_CONSTRUCTOR_INIT(NtClose);

	NT_FUNC_CONSTRUCTOR_INIT(NtAllocateVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtFreeVirtualMemory);

	NT_FUNC_CONSTRUCTOR_INIT(memmove);
	NT_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	NT_FUNC_CONSTRUCTOR_INIT(RtlAllocateHeap);
	NT_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);
	NT_FUNC_CONSTRUCTOR_INIT(LdrGetProcedureAddress);

	NT_FUNC_CONSTRUCTOR_INIT(LdrUnloadDll);

	NT_FUNC_CONSTRUCTOR_INIT(RtlAnsiStringToUnicodeString);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	NT_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
#ifdef _WIN64
	NT_FUNC_CONSTRUCTOR_INIT(RtlAddFunctionTable);
	// Optional. May stay null if the symbol did not resolve; IsValid() does
	// not require it, and MMI_CleanUp tolerates a null field.
	NT_FUNC_CONSTRUCTOR_INIT(RtlDeleteFunctionTable);
#endif
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	NT_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	NT_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpDereferenceModule);

	NT_FUNC_CONSTRUCTOR_INIT(LdrProtectMrdata);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpTlsList);
}

void ResetMapStats()
{
	g_LastMapStats = {};
}

void __stdcall GetLastMapStats(MAP_STATS * Out)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (Out)
	{
		*Out = g_LastMapStats;
	}
}