#pragma once

#include "System/Import/ImportHandler.h"

// Wait-stub return-address heuristic: Rip == func + offset while a thread
// sits in an alertable wait. Historically measured as 0x14 on Win10 1511
// x64 ntdll. The build gate accepts four Win11 layout families whose stubs
// share the same shape today, but the value is kept per-family so drift can
// be calibrated without touching call sites. A wrong value only lowers the
// hijack-candidate score (thread not recognised as alertable); it never
// breaks correctness.
//
// The Win10 1511 value is retained for version display / legacy labelling
// only. It can never be selected at runtime: the entry gate (InitializeRuntime
// and the ManualMap path) rejects any build below 22000 (Win11 21H2), so
// GetNtWaitReturnOffset only ever receives a Win11 family and its default arm
// is unreachable in practice.
#define NT_RET_OFFSET_64_WIN10_1511 0x14
#define NT_RET_OFFSET_64_WIN11_21H2 0x14
#define NT_RET_OFFSET_64_WIN11_22H2 0x14
#define NT_RET_OFFSET_64_WIN11_24H2 0x14
#define NT_RET_OFFSET_64_WIN11_25H2 0x14

inline ULONG GetNtWaitReturnOffset(WINDOWS_LAYOUT_FAMILY layout_family)
{
	switch (layout_family)
	{
		case WINDOWS_LAYOUT_FAMILY::Windows11_21H2:
			return NT_RET_OFFSET_64_WIN11_21H2;

		case WINDOWS_LAYOUT_FAMILY::Windows11_22H2:
			return NT_RET_OFFSET_64_WIN11_22H2;

		case WINDOWS_LAYOUT_FAMILY::Windows11_24H2:
			return NT_RET_OFFSET_64_WIN11_24H2;

		case WINDOWS_LAYOUT_FAMILY::Windows11_25H2:
			return NT_RET_OFFSET_64_WIN11_25H2;

		default:
			return NT_RET_OFFSET_64_WIN10_1511;
	}
}

#define TEB_SameTebFlags_64 0x17EE

#define TEB_SAMETEB_FLAGS_LoaderWorker	0x2000

#define TEB_SameTebFlags TEB_SameTebFlags_64

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

	ProcessInformation(const ProcessInformation &) = delete;
	ProcessInformation & operator=(const ProcessInformation &) = delete;

public:

	ProcessInformation();
	~ProcessInformation();

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