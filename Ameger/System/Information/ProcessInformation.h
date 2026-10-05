#pragma once

#include "System/Import/ImportHandler.h"
#include "System/Symbol/Offsets/DynamicOffsets.h"

// All Windows offsets are download-dependent (see DynamicOffsets.h):
//  - Wait-stub return deltas are disassembled from in-memory ntdll per
//    function (no 0x14 constant anywhere).
//  - TEB SameTebFlags / loader-worker mask, PEB fields, KUSER cookie and
//    LDR/inverted/TLS layouts come from the downloaded ntdll.pdb via
//    ResolveDynamicOffsets (fail-closed when absent).
//  - MsgWait flags stack slot is x64 ABI (return addr 8 + shadow 0x20),
//    exposed as g_DynamicOffsets.MsgWaitFlagsStackOffset, not a magic 0x28.
// No per-build NT_RET_OFFSET_* / TEB_SameTebFlags_* constants remain.

class ProcessInformation
{
	SYSTEM_PROCESS_INFORMATION	* m_pCurrentProcess = nullptr;
	SYSTEM_PROCESS_INFORMATION	* m_pFirstProcess	= nullptr;
	SYSTEM_THREAD_INFORMATION	* m_pCurrentThread	= nullptr;

	ULONG m_BufferSize = 0;

	HANDLE m_hCurrentProcess = nullptr;

	DWORD m_CurrentThreadIndex = 0;

	f_NtQueryInformationProcess m_pNtQueryInformationProcess	= nullptr;
	f_NtQuerySystemInformation	m_pNtQuerySystemInformation		= nullptr;
	f_NtQueryInformationThread	m_pNtQueryInformationThread		= nullptr;

	AMEGER_PEB					* GetPEB_Native();

	UINT_PTR m_WaitFunctionReturnAddress[5] = { 0 };

	HINSTANCE m_hWin32U = NULL;

	// Optional pre-existing handle for the thread currently under inspection.
	// GetTEB/IsThreadInAlertableState otherwise OpenThread by TID, which is a
	// fresh handle on a target thread for every probe. When the caller already
	// holds a usable thread handle for that exact TID (the sponsor path holds a
	// verified duplicate), these queries reuse it instead of opening again.
	HANDLE m_hCurrentThreadHandle = nullptr;
	DWORD m_CurrentThreadHandleTid = 0;

	// Resolves the handle to use for the current thread: the cached one when it
	// matches this TID, otherwise nullptr (caller opens by TID as before).
	HANDLE BorrowCurrentThreadHandle(DWORD tid) const;

	ProcessInformation(const ProcessInformation &) = delete;
	ProcessInformation & operator=(const ProcessInformation &) = delete;

public:

	ProcessInformation();
	~ProcessInformation();

	// Publishes an already-open handle for `tid` so subsequent thread queries
	// reuse it. Pass nullptr to clear. The handle is borrowed, never closed.
	void SetCurrentThreadHandle(HANDLE thread, DWORD tid);

	bool SetProcess(HANDLE hTargetProc);
	bool NextThread();

	bool RefreshInformation();

	AMEGER_PEB					* GetPEB();

	DWORD GetThreadId();

	bool GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason);
	void * GetTEB();

	bool IsThreadInAlertableState();
	bool IsThreadWorkerThread();
};