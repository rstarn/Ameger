#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

// Every Windows offset in one place, resolved from the downloaded ntdll.pdb
// (plus in-memory disassembly for code stubs) instead of hardcoded constants.
//
// Policy:
//  - Critical drift-prone offsets (TEB/PEB/LDR/KUSER/inverted/TLS) are STRICT:
//    ResolveDynamicOffsets fails closed when the PDB lacks them. No static
//    fallback is used, so a future Windows layout can never silently use a
//    stale 0x17EE / 0x330 / 0x60 / LDR guess.
//  - Stable ABI values (x64 shadow-store 0x28, KTHREAD_STATE/WaitReason enums,
//    SYSTEM_* NTAPI header shapes) keep documented fallbacks: they have not
//    drifted since NT and are not per-build layouts. They are still resolved
//    from the PDB first when present; the fallback only fires when the PDB
//    does not carry that type.
//  - KUSER base 0x7FFE0000 is a fixed user-shared mapping (documented ABI),
//    not a per-build offset. Only the Cookie FIELD offset inside it is
//    download-dependent.
//
// The struct is plain DWORDs so it can be memcpy'd into MANUAL_MAPPING_DATA
// for the remote shell (which has no DbgHelp/PDB access in the target).
struct DYNAMIC_NT_OFFSETS
{
	DWORD Ready = 0; // 1 once ResolveDynamicOffsets succeeded

	// TEB (from PDB type TEB/_TEB)
	DWORD TebSameTebFlags = 0;          // e.g. was 0x17EE
	DWORD TebLastErrorValue = 0;        // e.g. was 0x68 (stub gs:[] disp)
	DWORD TebProcessEnvironmentBlock = 0; // e.g. was 0x60

	// PEB (from PDB type PEB/_PEB)
	DWORD PebOsMajorVersion = 0;
	DWORD PebOsMinorVersion = 0;
	DWORD PebOsBuildNumber = 0;
	DWORD PebLdr = 0;
	DWORD PebProcessHeap = 0;
	DWORD PebLoaderLock = 0;
	DWORD PebSize = 0;

	// KUSER_SHARED_DATA.Cookie field offset inside 0x7FFE0000
	DWORD KuserCookie = 0; // e.g. was 0x330

	// LDR (from PDB _LDR_DATA_TABLE_ENTRY / _LDR_DDAG_NODE)
	DWORD LdrEntryDllBase = 0;
	DWORD LdrEntrySizeOfImage = 0;
	DWORD LdrEntryFullDllName = 0;
	DWORD LdrEntryDdagNode = 0;
	DWORD LdrEntrySize = 0; // sizeof(_LDR_DATA_TABLE_ENTRY)
	DWORD LdrDdagNodeState = 0;
	DWORD LdrDdagNodeSize = 0;

	// Inverted function table (from PDB _RTL_INVERTED_FUNCTION_TABLE[_ENTRY])
	DWORD InvertedTableCount = 0;   // offset of Count within table
	DWORD InvertedTableEntries = 0; // offset of Entries within table
	DWORD InvertedEntryImageBase = 0;
	DWORD InvertedEntryImageSize = 0;
	DWORD InvertedEntryExceptionDirectory = 0;
	DWORD InvertedEntryExceptionDirectorySize = 0;
	DWORD InvertedEntrySize = 0; // sizeof(_RTL_INVERTED_FUNCTION_TABLE_ENTRY)

	// TLS entry ModuleEntry (from PDB _TLS_ENTRY variants; fallback = SDK math)
	DWORD TlsEntryModuleEntry = 0;
	DWORD TlsEntrySize = 0;

	// x64 ABI: [Rsp]=return addr + 0x20 shadow => 5th arg at +0x28. Stable by
	// calling convention, not per-build. Kept as a field for uniformity.
	DWORD MsgWaitFlagsStackOffset = 0x28;

	// Loader-worker bit inside SameTebFlags (stable bitmask, not an offset)
	DWORD SameTebFlagsLoaderWorkerMask = 0x2000;

	// Thread state enums (PDB first, stable fallback 2/5/0x0F)
	DWORD ThreadStateRunning = 2;
	DWORD ThreadStateWaiting = 5;
	DWORD WaitReasonWrQueue = 0x0F;

	// LDRP_PATH_SEARCH_CONTEXT allocation size (PDB first, static fallback)
	DWORD LdrpPathSearchContextSize = 0;
	// Offset of OriginalFullDllName inside it (PDB first, static fallback)
	DWORD LdrpPathSearchOriginalFullDllName = 0;
};

inline DYNAMIC_NT_OFFSETS g_DynamicOffsets{};

// Publication flag for g_DynamicOffsets.
//
// The struct must stay plain DWORDs: it is copied wholesale into
// MANUAL_MAPPING_DATA for the remote shell, which has no DbgHelp/PDB access.
// That copy only works while every member is trivially copyable, so readiness
// cannot be an atomic member - it is carried by this separate flag instead.
// The producer fills g_DynamicOffsets (Ready included, for the copied value)
// and then release-stores 1 here; a consumer acquire-loads here before reading
// any field. On x64 both compile to a plain mov (TSO already orders loads
// after loads), but the explicit release/acquire pair is what guarantees the
// ordering on any target/toolchain instead of relying on the incidental fact
// that the fields happen to be written before the flag.
inline std::atomic<DWORD> g_DynamicOffsetsReady{ 0 };

// Resolves every field above from the already-loaded ntdll.pdb (sym_parser
// must be Initialize()d) plus in-memory ntdll disassembly for NtWait stubs.
// Returns SYMBOL_ERR_SUCCESS when the STRICT subset is complete; the struct's
// Ready flag is set only on full success. Fail-closed: callers must refuse to
// inject when this fails instead of falling back to static offsets.
DWORD ResolveDynamicOffsets();

// Helpers exposed for testing/logging (not for injection paths).
DWORD DisassembleWaitReturnOffset(void * FunctionBase, DWORD & OffsetOut);
