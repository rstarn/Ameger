#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Information/ProcessInformation.h"

#define NEXT_SYSTEM_PROCESS_ENTRY(pCurrent) ReCa<SYSTEM_PROCESS_INFORMATION *>(ReCa<BYTE *>(pCurrent) + pCurrent->NextEntryOffset)

ProcessInformation::ProcessInformation()
{
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

	
	// Wait-stub return addresses are fully dynamic: each stub is disassembled
	// in our own ntdll to locate its trailing ret (see DisassembleWaitReturnOffset).
	// No 0x14 constant remains. A stub that cannot be decoded gets address 0,
	// which only lowers alertable scoring (never correctness): Rip can never
	// equal 0 for a live thread.
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
		m_WaitFunctionReturnAddress[i] = 0;
		if (wait_functions[i])
		{
			DWORD stub_off = 0;
			if (DisassembleWaitReturnOffset(ReCa<void *>(wait_functions[i]), stub_off) == SYMBOL_ERR_SUCCESS)
			{
				m_WaitFunctionReturnAddress[i] = ReCa<UINT_PTR>(wait_functions[i]) + stub_off;
			}
			else
			{
				LOG(3, "ProcessInformation: wait stub %zu not decodable, scoring disabled\n", i);
			}
		}
	}

	// NtUserMsgWaitForMultipleObjectsEx is the 5th wait stub (arg3 -> R9, see
	// IsThreadInAlertableState). The build floor here is always satisfied:
	// GetSupportedWindowsLayout (enforced at startup) rejects everything below
	// Windows 11 21H2 (22000), which is already far above the 1607 that first
	// exposed this export. The guard is kept as an explicit platform floor, not
	// because it can currently be false.
	if (GetOSBuildVersion() >= g_Windows10_1607)
	{
		auto win32u_name = XOR_STR_W(L"win32u.dll");
		m_hWin32U = LoadLibraryW(win32u_name.get());
		if (m_hWin32U)
		{
			auto msgwait_name = XOR_STR_A("NtUserMsgWaitForMultipleObjectsEx");
			FARPROC msgwait = GetProcAddress(m_hWin32U, msgwait_name.get());
			m_WaitFunctionReturnAddress[4] = 0;
			if (msgwait)
			{
				DWORD stub_off = 0;
				if (DisassembleWaitReturnOffset(ReCa<void *>(msgwait), stub_off) == SYMBOL_ERR_SUCCESS)
				{
					m_WaitFunctionReturnAddress[4] = ReCa<UINT_PTR>(msgwait) + stub_off;
				}
			}
		}
	}

	LOG(3, "ProcessInformation initialized\n");

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

bool ProcessInformation::SetProcess(HANDLE hTargetProc)
{
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

	// Test the current entry first, then advance only while a next entry
	// exists. The old loop condition (NEXT(cur) != cur) was evaluated before
	// the body, so it terminated on the last entry without ever comparing its
	// UniqueProcessId - the final process in the list could never match.
	for (;;)
	{
		if (m_pCurrentProcess->UniqueProcessId == ReCa<void *>(PID))
		{
			break;
		}

		auto pNext = NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess);
		if (pNext == m_pCurrentProcess)
		{
			break;
		}

		m_pCurrentProcess = pNext;
	}

	if (m_pCurrentProcess->UniqueProcessId != ReCa<void *>(PID))
	{
		m_pCurrentProcess = m_pFirstProcess;
		return false;
	}

	m_CurrentThreadIndex = 0;
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return true;
}

bool ProcessInformation::NextThread()
{
	if (!m_pFirstProcess || !m_pCurrentProcess || !m_pCurrentProcess->NumberOfThreads)
	{
		return false;
	}

	if (m_CurrentThreadIndex == m_pCurrentProcess->NumberOfThreads - 1)
	{
		return false;
	}

	m_pCurrentThread = &m_pCurrentProcess->Threads[++m_CurrentThreadIndex];

	return true;
}

bool ProcessInformation::RefreshInformation()
{
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

	return true;
}

DWORD ProcessInformation::GetThreadId()
{
	if (!m_pCurrentThread)
	{
		return 0;
	}

	return DWORD(ReCa<ULONG_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
}

bool ProcessInformation::GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason)
{
		if (!m_pCurrentThread)
		{
			return false;
		}

		state	= m_pCurrentThread->ThreadState;
		reason	= m_pCurrentThread->WaitReason;

		return true;
	}

HANDLE ProcessInformation::BorrowCurrentThreadHandle(DWORD tid) const
{
	if (m_hCurrentThreadHandle && m_hCurrentThreadHandle != INVALID_HANDLE_VALUE && tid && m_CurrentThreadHandleTid == tid)
	{
		return m_hCurrentThreadHandle;
	}

	return nullptr;
}

void ProcessInformation::SetCurrentThreadHandle(HANDLE thread, DWORD tid)
{
	m_hCurrentThreadHandle = thread;
	m_CurrentThreadHandleTid = thread ? tid : 0;
}

void * ProcessInformation::GetTEB()
{
	if (!m_pCurrentThread || !m_pNtQueryInformationThread)
	{
		return nullptr;
	}

	// Reuse the caller's handle for this TID when available; only open when
	// we were not given one.
	const HANDLE borrowed = BorrowCurrentThreadHandle(MDWD(m_pCurrentThread->ClientId.UniqueThread));
	const bool owns_handle = borrowed == nullptr;
	HANDLE hThread = borrowed ? borrowed : OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, MDWD(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return nullptr;
	}

	THREAD_BASIC_INFORMATION tbi{ 0 };
	auto ntRet = m_pNtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);

	if (owns_handle)
	{
		CloseHandle(hThread);
	}

	if (NT_FAIL(ntRet))
	{
		return nullptr;
	}

	return tbi.TebBaseAddress;
}

bool ProcessInformation::IsThreadInAlertableState()
{
	if (!m_pCurrentThread)
	{
		return false;
	}

	const HANDLE borrowed = BorrowCurrentThreadHandle(MDWD(m_pCurrentThread->ClientId.UniqueThread));
	const bool owns_handle = borrowed == nullptr;
	HANDLE hThread = borrowed ? borrowed : OpenThread(THREAD_GET_CONTEXT, FALSE, MDWD(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return false;
	}

	CONTEXT ctx{ 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &ctx))
	{
		if (owns_handle)
		{
			CloseHandle(hThread);
		}

		return false;
	}

	if (owns_handle)
	{
		CloseHandle(hThread);
	}

	if (!ctx.Rip || !ctx.Rsp)
	{
		return false;
	}

	// Every stub in the table is the shared Win11 x64 syscall thunk
	// (mov r10,rcx / mov eax,imm / test [SharedUserData+0x308],1 / syscall /
	// ret; verified with dumpbin on the local ntdll). While a thread is parked
	// in the kernel wait its Rip is the trailing ret, and syscall has already
	// overwritten Rcx with that same return address. The syscall ABI receives
	// arg0 in R10 (the stub moved it there), so at the ret the live arguments
	// sit in R10(arg0) / Rdx(arg1) / R8(arg2) / R9(arg3). Reading callee-saved
	// Rbx/Rsi could never observe an argument.
	if (ctx.Rip == m_WaitFunctionReturnAddress[0]) 
	{
		// NtDelayExecution(BOOLEAN Alertable, ...): Alertable is arg0 -> R10.
		return (ctx.R10 == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[1]) 
	{
		// NtWaitForSingleObject(Handle, BOOLEAN Alertable, ...): arg1 -> Rdx.
		return (ctx.Rdx == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[2]) 
	{
		// NtWaitForMultipleObjects(Count, Handles, WaitType, BOOLEAN Alertable,
		// ...): Alertable is arg3 -> R9.
		return (ctx.R9 == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[3]) 
	{
		// NtSignalAndWaitForSingleObject(SignalHandle, WaitHandle,
		// BOOLEAN Alertable, ...): Alertable is arg2 -> R8.
		return (ctx.R8 == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[4])
	{
		// 5th arg (dwFlags) slot: x64 ABI return-addr(8) + shadow(0x20).
		// Not a per-build Windows offset; taken from the dynamic table for
		// uniformity instead of a magic 0x28 literal.
		const ULONG_PTR flags_off = g_DynamicOffsets.MsgWaitFlagsStackOffset ? g_DynamicOffsets.MsgWaitFlagsStackOffset : (sizeof(void *) + 0x20);
		DWORD Flags = FALSE;
		if (ReadProcessMemory(m_hCurrentProcess, ReCa<void *>(ctx.Rsp + flags_off), &Flags, sizeof(Flags), nullptr))
		{
			return ((Flags & MWMO_ALERTABLE) != 0);
		}
	}

	return false;
}

bool ProcessInformation::IsThreadWorkerThread()
{
	// Fail closed whenever the thread cannot be classified: treat it as a
	// worker so the caller skips it rather than hijacking on a guess. This
	// matches the missing-offsets guard below.
	if (!m_pCurrentThread)
	{
		return true;
	}

	// Fail-closed when the PDB offsets are not ready: treat as worker so the
	// thread is skipped rather than hijacked on a stale guess.
	if (!g_DynamicOffsetsReady.load(std::memory_order_acquire) || !g_DynamicOffsets.TebSameTebFlags)
	{
		return true;
	}
	BYTE * teb = ReCa<BYTE *>(GetTEB());
	if (!teb)
	{
		// Unreadable TEB: cannot prove this is not a loader worker.
		return true;
	}

	USHORT TebInfo = 0;
	if (ReadProcessMemory(m_hCurrentProcess, teb + g_DynamicOffsets.TebSameTebFlags, &TebInfo, sizeof(TebInfo), nullptr))
	{
		return ((TebInfo & g_DynamicOffsets.SameTebFlagsLoaderWorkerMask) != 0);
	}

	// TEB present but its flags are unreadable: same fail-closed verdict.
	return true;
}

