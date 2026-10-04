#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "NT/Windows11.h"

#define DEF_STRUCT_DEFAULT(name, suffix)	\
using name		= name##suffix;				\
using P##name	= P##name##suffix;			\
using _##name	= _##name##suffix;

DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN11)
DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN11)

#pragma region function prototypes

using f_LdrUnloadDll = NTSTATUS (__stdcall *)
(
	HANDLE DllHandle
);

using f_LdrpLoadDllInternal = VOID (__fastcall *)
(
	UNICODE_STRING				*	dll_path, 
	LDRP_PATH_SEARCH_CONTEXT	*	search_path,
	LDRP_LOAD_CONTEXT_FLAGS			Flags,
	ULONG32							Unknown0,	
	LDR_DATA_TABLE_ENTRY_WIN11	*	Unknown1,	
	LDR_DATA_TABLE_ENTRY_WIN11	*	Unknown2,	
	LDR_DATA_TABLE_ENTRY_WIN11	**	ldr_out,
	NTSTATUS					*	ntRet,
	ULONG							Unknown4	
);

using f_LdrGetProcedureAddress = NTSTATUS (__stdcall *)
(
	PVOID				BaseAddress,
	ANSI_STRING		*	Name,
	ULONG				Ordinal,
	PVOID			*	ProcedureAddress
);

using f_NtQueryInformationProcess = NTSTATUS (__stdcall *)
(
	HANDLE					hTargetProc,
	PROCESSINFOCLASS		PIC,
	void				*	pBuffer,
	ULONG					BufferSize,
	ULONG				*	SizeOut
);

using f_NtQuerySystemInformation = NTSTATUS	(__stdcall *)
(
	SYSTEM_INFORMATION_CLASS		SIC,
	void						*	pBuffer,
	ULONG							BufferSize,
	ULONG						*	SizeOut
);

using f_NtQueryInformationThread = NTSTATUS (__stdcall *)
(
	HANDLE				hThread,
	THREADINFOCLASS		TIC,
	void			*	pBuffer,
	ULONG				BufferSize,
	ULONG			*	SizeOut
);

using f_LdrpPreprocessDllName = NTSTATUS (__fastcall *)
(
	UNICODE_STRING				* DllName,
	LDRP_UNICODE_STRING_BUNDLE	* OutputDllName,
	LDR_DATA_TABLE_ENTRY		* pOptParentEntry,
	LDRP_LOAD_CONTEXT_FLAGS		* LoadContextFlags
);

using f_RtlInsertInvertedFunctionTable = BOOL (__fastcall *)
(
	void *	ImageBase,
	DWORD	SizeOfImage
);

using f_RtlAddFunctionTable = BOOL (__stdcall *)
(
	RUNTIME_FUNCTION *	FunctionTable,
	DWORD				EntryCount,
	DWORD64				BaseAddress
);

// Documented ntdll API. Optional: resolved but not required, and used only by
// MMI_CleanUp to undo RtlAddFunctionTable. Same table pointer that was passed
// to RtlAddFunctionTable.
using f_RtlDeleteFunctionTable = BOOLEAN (__stdcall *)
(
	RUNTIME_FUNCTION *	FunctionTable
);

using f_LdrpHandleTlsData = NTSTATUS (__fastcall *)
(
	LDR_DATA_TABLE_ENTRY * pEntry
);

using f_LdrLockLoaderLock = NTSTATUS (__stdcall *)
(
	ULONG			Flags, 
	ULONG		*	State, 
	ULONG_PTR	*	Cookie
);

using f_LdrUnlockLoaderLock = NTSTATUS (__stdcall *)
(
	ULONG		Flags, 
	ULONG_PTR	Cookie
);

using f_LdrpDereferenceModule = NTSTATUS(__fastcall *)
(
	LDR_DATA_TABLE_ENTRY * pEntry
);

using f_memmove = VOID (__cdecl *)
(
	PVOID	UNALIGNED	Destination,
	LPCVOID	UNALIGNED	Source,
	SIZE_T				Length
);

using f_RtlZeroMemory = VOID (__stdcall *)
(
	PVOID	UNALIGNED	Destination,
	SIZE_T				Length
);

using f_RtlAllocateHeap = PVOID (__stdcall *)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	SIZE_T	Size
);

using f_RtlFreeHeap = BOOLEAN (__stdcall *)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	PVOID	BaseAddress
);

using f_RtlAnsiStringToUnicodeString = NTSTATUS (__stdcall *)
(
	UNICODE_STRING		*	DestinationString,
	const ANSI_STRING	*	SourceString,
	BOOLEAN					AllocateDestinationString
);

using f_NtClose = NTSTATUS (__stdcall *)
(
	HANDLE Handle
);

using f_NtAllocateVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE			ProcessHandle,
	PVOID		*	BaseAddress,
	ULONG_PTR		ZeroBits,
	SIZE_T		*	RegionSize,
	ULONG			AllocationType,
	ULONG			Protect
);

using f_NtFreeVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE		ProcessHandle,
	PVOID	*	BaseAddress,
	SIZE_T	*	RegionSize,
	ULONG		FreeType
);

using f_NtProtectVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE		ProcessHandle,
	PVOID	*	BaseAddress,
	SIZE_T	*	Size,
	ULONG		NewAccess,
	ULONG	*	OldAccess
);

using f_LdrProtectMrdata = VOID (__stdcall *)
(
	BOOL bProtected
);

using f_NtDelayExecution = NTSTATUS (__stdcall *)
(
	BOOLEAN			Alertable,
	LARGE_INTEGER * DelayInterval
);

using f_LdrpHeap					= PVOID *;
using f_LdrpInvertedFunctionTable	= RTL_INVERTED_FUNCTION_TABLE *;
using f_LdrpTlsList					= LIST_ENTRY *;

#pragma endregion

inline HINSTANCE g_hNTDLL;