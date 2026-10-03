#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Primitives/VmpMarkers.h"
#include "System/Information/ProcessInformation.h"

#define NEXT_SYSTEM_PROCESS_ENTRY(pCurrent) ReCa<SYSTEM_PROCESS_INFORMATION *>(ReCa<BYTE *>(pCurrent) + pCurrent->NextEntryOffset)

AMEGER_VMP_NOINLINE ProcessInformation::ProcessInformation()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_ctor");
	KC_WSTR_DECL(ntdll_name, L"ntdll.dll");
	HINSTANCE hNTDLL = GetModuleHandleW(ntdll_name.c_str());
	if (!hNTDLL)
	{
		return;
	}

	LOG(3, "Creating ProcessInformation\n");

	auto name_proc = XOR_STR_A("NtQueryInformationProcess");
	auto name_sys = XOR_STR_A("NtQuerySystemInformation");
	auto name_thread = XOR_STR_A("NtQueryInformationThread");
	m_pNtQueryInformationProcess	= ReCa<f_NtQueryInformationProcess>	(GetProcAddress(hNTDLL, name_proc.get()));
	m_pNtQuerySystemInformation		= ReCa<f_NtQuerySystemInformation>	(GetProcAddress(hNTDLL, name_sys.get()));
	m_pNtQueryInformationThread		= ReCa<f_NtQueryInformationThread>	(GetProcAddress(hNTDLL, name_thread.get()));

	if (!m_pNtQueryInformationProcess || !m_pNtQuerySystemInformation || !m_pNtQueryInformationThread)
	{
		return;
	}

	m_BufferSize	= 0x10000;
	m_pFirstProcess = nullptr;

	
	// Per-layout-family wait-stub offset. The 1511 fallback below is
	// unreachable: ProcessInformation is only constructed from the hijack
	// path behind the ManualMap build gate, which rejects any build below
	// 22000, so GetSupportedWindowsLayout never fails here. It is kept (every
	// family currently shares 0x14) so a mismatch can only ever degrade
	// alertable-thread scoring, never correctness.
	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	ULONG nt_ret_offset = NT_RET_OFFSET_64_WIN10_1511;
	if (GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		nt_ret_offset = GetNtWaitReturnOffset(layout_family);
	}

	auto wait_delay = XOR_STR_A("NtDelayExecution");
	auto wait_single = XOR_STR_A("NtWaitForSingleObject");
	auto wait_multi = XOR_STR_A("NtWaitForMultipleObjects");
	auto wait_signal = XOR_STR_A("NtSignalAndWaitForSingleObject");
	const FARPROC wait_functions[] =
	{
		GetProcAddress(hNTDLL, wait_delay.get()),
		GetProcAddress(hNTDLL, wait_single.get()),
		GetProcAddress(hNTDLL, wait_multi.get()),
		GetProcAddress(hNTDLL, wait_signal.get())
	};

	for (size_t i = 0; i < sizeof(wait_functions) / sizeof(wait_functions[0]); ++i)
	{
		m_WaitFunctionReturnAddress[i] = wait_functions[i] ? ReCa<UINT_PTR>(wait_functions[i]) + nt_ret_offset : 0;
	}

	if (GetOSBuildVersion() >= g_Windows10_1607)
	{
		auto win32u_name = XOR_STR_W(L"win32u.dll");
		m_hWin32U = LoadLibraryW(win32u_name.get());
		if (m_hWin32U)
		{
			auto msgwait_name = XOR_STR_A("NtUserMsgWaitForMultipleObjectsEx");
			m_WaitFunctionReturnAddress[4] = ReCa<UINT_PTR>(GetProcAddress(m_hWin32U, msgwait_name.get())) + nt_ret_offset;
		}
	}

	LOG(3, "ProcessInformation initialized\n");

	AMEGER_VMP_ULTRA_END();
}

ProcessInformation::~ProcessInformation()
{
	if (m_hWin32U)
	{
		FreeLibrary(m_hWin32U);
	}

	if (m_pFirstProcess)
	{
		delete[] ReCa<BYTE *>(m_pFirstProcess);
	}
}

AMEGER_VMP_NOINLINE bool ProcessInformation::SetProcess(HANDLE hTargetProc)
{
	AMEGER_VMP_ULTRA_BEGIN("pi_set");
	DWORD dwHandleInfo = 0;
	if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE || !GetHandleInformation(hTargetProc, &dwHandleInfo))
	{
		return false;
	}

	if (!m_pNtQueryInformationProcess || !m_pNtQuerySystemInformation || !m_pNtQueryInformationThread)
	{
		return false;
	}

	if (!m_pFirstProcess)
	{
		if (!RefreshInformation())
		{
			return false;
		}
	}

	m_hCurrentProcess = hTargetProc;

	ULONG_PTR PID = GetProcessId(m_hCurrentProcess);
	if (!PID)
	{
		m_hCurrentProcess = nullptr;
		return false;
	}

	m_pCurrentProcess = m_pFirstProcess;

	while (NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess) != m_pCurrentProcess)
	{
		if (m_pCurrentProcess->UniqueProcessId == ReCa<void *>(PID))
		{
			break;
		}

		m_pCurrentProcess = NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess);
	}

	if (m_pCurrentProcess->UniqueProcessId != ReCa<void *>(PID))
	{
		m_pCurrentProcess = m_pFirstProcess;
		return false;
	}

	m_CurrentThreadIndex = 0;
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	AMEGER_VMP_ULTRA_END();
	return true;
}

AMEGER_VMP_NOINLINE bool ProcessInformation::NextThread()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_next");
	if (!m_pFirstProcess || !m_pCurrentProcess || !m_pCurrentProcess->NumberOfThreads)
	{
		return false;
	}

	if (m_CurrentThreadIndex == m_pCurrentProcess->NumberOfThreads - 1)
	{
		return false;
	}

	m_pCurrentThread = &m_pCurrentProcess->Threads[++m_CurrentThreadIndex];

	AMEGER_VMP_ULTRA_END();
	return true;
}

AMEGER_VMP_NOINLINE bool ProcessInformation::RefreshInformation()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_refresh");
	if (!m_pFirstProcess)
	{
		m_pFirstProcess = ReCa<SYSTEM_PROCESS_INFORMATION *>(new(std::nothrow) BYTE[m_BufferSize]());
		if (!m_pFirstProcess)
		{
			return false;
		}
	}
	else
	{
		delete[] ReCa<BYTE *>(m_pFirstProcess);
		m_pFirstProcess = nullptr;

		return RefreshInformation();
	}

	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);

	while (ntRet == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Free the undersized buffer exactly once and clear the pointer before
		// any early return: the size guard below used to free it a second time
		// (double free) because the pointer was left dangling.
		delete[] ReCa<BYTE *>(m_pFirstProcess);
		m_pFirstProcess = nullptr;

		if (size_out > 64 * 1024 * 1024)
		{
			return false;
		}

		// Grow monotonically: a build that reports a smaller (or zero) required
		// size must not shrink the buffer and spin the loop without progress.
		ULONG next_size = size_out + 0x1000;
		if (next_size <= m_BufferSize)
		{
			next_size = m_BufferSize * 2;
		}
		if (next_size <= m_BufferSize)
		{
			return false;
		}

		m_BufferSize	= next_size;
		m_pFirstProcess = ReCa<SYSTEM_PROCESS_INFORMATION *>(new(std::nothrow) BYTE[m_BufferSize]);
		if (!m_pFirstProcess)
		{
			return false;
		}

		ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);
	}

	if (NT_FAIL(ntRet))
	{
		delete[] ReCa<BYTE *>(m_pFirstProcess);
		m_pFirstProcess = nullptr;

		return false;
	}

	m_pCurrentProcess	= m_pFirstProcess;
	m_pCurrentThread	= &m_pCurrentProcess->Threads[0];

	AMEGER_VMP_ULTRA_END();
	return true;
}

AMEGER_VMP_NOINLINE AMEGER_PEB * ProcessInformation::GetPEB()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_getpeb");
	AMEGER_VMP_ULTRA_END();
	return GetPEB_Native();
}

AMEGER_VMP_NOINLINE AMEGER_PEB * ProcessInformation::GetPEB_Native()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_peb");
	if (!m_pFirstProcess || !m_pNtQueryInformationProcess)
	{
		return nullptr;
	}

	PROCESS_BASIC_INFORMATION PBI{ 0 };
	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQueryInformationProcess(m_hCurrentProcess, PROCESSINFOCLASS::ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &size_out);

	if (NT_FAIL(ntRet))
	{
		return nullptr;
	}

	AMEGER_VMP_ULTRA_END();
	return PBI.pPEB;
}

AMEGER_VMP_NOINLINE DWORD ProcessInformation::GetThreadId()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_tid");
	if (!m_pCurrentThread)
	{
		return 0;
	}

	AMEGER_VMP_ULTRA_END();
	return DWORD(ReCa<ULONG_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
}

AMEGER_VMP_NOINLINE bool ProcessInformation::GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason)
{
	AMEGER_VMP_ULTRA_BEGIN("pi_state");
		if (!m_pCurrentThread)
		{
			return false;
		}

		state	= m_pCurrentThread->ThreadState;
		reason	= m_pCurrentThread->WaitReason;

		AMEGER_VMP_ULTRA_END();
		return true;
	}

AMEGER_VMP_NOINLINE void * ProcessInformation::GetTEB()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_teb");
	if (!m_pCurrentThread || !m_pNtQueryInformationThread)
	{
		return nullptr;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, MDWD(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return nullptr;
	}

	THREAD_BASIC_INFORMATION tbi{ 0 };
	auto ntRet = m_pNtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);

	CloseHandle(hThread);

	if (NT_FAIL(ntRet))
	{
		return nullptr;
	}

	AMEGER_VMP_ULTRA_END();
	return tbi.TebBaseAddress;
}

AMEGER_VMP_NOINLINE bool ProcessInformation::IsThreadInAlertableState()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_alert");
		if (!m_pCurrentThread)
		{
			return false;
		}

	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, MDWD(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return false;
	}

	CONTEXT ctx{ 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &ctx))
	{
		CloseHandle(hThread);

		return false;
	}

	CloseHandle(hThread);

	if (!ctx.Rip || !ctx.Rsp)
	{
		return false;
	}

	if (ctx.Rip == m_WaitFunctionReturnAddress[0]) 
	{
		
		return (ctx.Rcx == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[1]) 
	{
		return (ctx.Rbx == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[2] || ctx.Rip == m_WaitFunctionReturnAddress[3]) 
	{
		return (ctx.Rsi == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[4]) 
	{
		DWORD Flags = FALSE;
		if (ReadProcessMemory(m_hCurrentProcess, ReCa<void *>(ctx.Rsp + 0x28), &Flags, sizeof(Flags), nullptr))
		{
			return ((Flags & MWMO_ALERTABLE) != 0);
		}
	}

	AMEGER_VMP_ULTRA_END();
	return false;
}

AMEGER_VMP_NOINLINE bool ProcessInformation::IsThreadWorkerThread()
{
	AMEGER_VMP_ULTRA_BEGIN("pi_worker");
		if (!m_pCurrentThread)
		{
			return false;
		}

	BYTE * teb = ReCa<BYTE *>(GetTEB());
	if (!teb)
	{
		return false;
	}

	USHORT TebInfo = NULL;
	if (ReadProcessMemory(m_hCurrentProcess, teb + TEB_SameTebFlags, &TebInfo, sizeof(TebInfo), nullptr))
	{
		return ((TebInfo & TEB_SAMETEB_FLAGS_LoaderWorker) != 0);
	}

	AMEGER_VMP_ULTRA_END();
	return false;
}

