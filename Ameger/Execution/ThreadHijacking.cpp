#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Execution/Routine/StartRoutine.h"
#include "System/Handle/HandleHijack.h"
#include "Injection/Injection.h"

// Measured thread-hijack outcome, handed to the host via GetLastThreadExecStats.
// The host previously printed "Thread context restored automatically" as a
// fixed string, which asserted a restore that had not been checked; these are
// the values behind it.
static THREAD_EXEC_STATS g_ThreadExecStats{};

namespace
{
	// g_ThreadExecStats is written by the injection thread (field by field,
	// plus ResetThreadExecStats) and read by the export/UI thread through
	// GetLastThreadExecStats with no other synchronization, exactly like the
	// g_LastMapStats slots in ManualMapping.cpp. A plain 40-byte struct copy is
	// not atomic, so every whole-struct store/load goes through
	// InterlockedExchange / InterlockedCompareExchange, and each field store is
	// an InterlockedExchange - a compiler intrinsic on x64, no new import.
	// THREAD_EXEC_STATS is ten DWORDs (static_assert in InjectionTypes.h), so a
	// LONG-stride walk covers it exactly.
	void StoreThreadExecStat(DWORD & Field, DWORD Value)
	{
		InterlockedExchange(ReCa<volatile LONG *>(&Field), static_cast<LONG>(Value));
	}

	void StoreThreadExecStats(const THREAD_EXEC_STATS & Src)
	{
		static_assert(sizeof(THREAD_EXEC_STATS) % sizeof(LONG) == 0, "THREAD_EXEC_STATS must be a whole number of LONGs");

		volatile LONG * dst = ReCa<volatile LONG *>(&g_ThreadExecStats);
		const LONG * src = ReCa<const LONG *>(&Src);
		for (size_t i = 0; i < sizeof(THREAD_EXEC_STATS) / sizeof(LONG); ++i)
		{
			InterlockedExchange(&dst[i], src[i]);
		}
	}

	void LoadThreadExecStats(THREAD_EXEC_STATS & Dst)
	{
		volatile LONG * src = ReCa<volatile LONG *>(&g_ThreadExecStats);
		LONG * dst = ReCa<LONG *>(&Dst);
		for (size_t i = 0; i < sizeof(THREAD_EXEC_STATS) / sizeof(LONG); ++i)
		{
			dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
		}
	}

	// Secure-wipe the W^X hijack stub before its RemoteAllocation guard
	// releases it. The block holds the staged shellcode and the SR_REMOTE_DATA
	// state (pArg/pRoutine), and its code page is RX, so it is promoted to RW
	// first (never RWX; the block is released immediately after, so the
	// temporary protection is not restored). The write is bounded and
	// non-throwing: a failed protect or write leaves the block for the guard to
	// free exactly as before.
	void ScrubRemoteRegion(HANDLE hTargetProc, void * base, SIZE_T size)
	{
		if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE || !base || !size)
		{
			return;
		}

		DWORD old_protect = 0;
		if (!VirtualProtectEx(hTargetProc, base, size, PAGE_READWRITE, &old_protect))
		{
			return;
		}

		BYTE zeros[0x2000] = { 0 };
		BYTE * cursor = ReCa<BYTE *>(base);
		SIZE_T remaining = size;
		while (remaining)
		{
			const SIZE_T chunk = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
			if (!WriteProcessMemory(hTargetProc, cursor, zeros, chunk, nullptr))
			{
				return;
			}

			cursor += chunk;
			remaining -= chunk;
		}
	}

	// Handle-needing probes per search pass. GetTEB (worker check) and the
	// alertable check each OpenThread on a target thread, so an unbounded walk
	// opened a game-thread handle for every candidate in the process - a
	// handle-enumeration fingerprint far louder than any single syscall.
	// Snapshot data (state/reason/TID) needs no handle, so it filters first and
	// only this many candidates are confirmed by handle.
	constexpr DWORD kMaxHandleProbes = 4;

	DWORD FindHijackThread(ProcessInformation & processInformation, bool allow_waiting, bool alertable_only)
	{
		// Thread-state values are download-dependent (see g_DynamicOffsets,
		// resolved from ntdll.pdb enums). Fail-closed when not ready: no
		// static Running/Waiting/WrQueue fallback here.
		if (!g_DynamicOffsets.Ready)
		{
			LOG(2, "FindAcquireThread: dynamic offsets not ready, refusing\n");
			return 0;
		}
		const KWAIT_REASON wrQueue = static_cast<KWAIT_REASON>(g_DynamicOffsets.WaitReasonWrQueue);
		const KTHREAD_STATE running = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);
		DWORD probes = 0;
		do
		{
			KWAIT_REASON reason;
			KTHREAD_STATE state;
			if (!processInformation.GetThreadState(state, reason))
			{
				continue;
			}

			const DWORD candidate = processInformation.GetThreadId();
			if (!candidate || candidate == GetCurrentThreadId())
			{
				continue;
			}

			// Handle-free filter first: a WrQueue waiter never wakes on
			// PostThreadMessage, so a WrQueue thread is only ever considered
			// in the final all-inclusive tier.
			if (reason == wrQueue && !allow_waiting)
			{
				continue;
			}

			// Second handle-free filter: a tier that accepts on state alone
			// must never spend a probe proving what the snapshot already said.
			// Ordering matters - || short-circuits, so the cheap test is first.
			const bool state_qualifies = allow_waiting || state == running;
			if (state_qualifies && !alertable_only)
			{
				// The worker check reads TEB::SameTebFlags, so it needs a
				// handle too. It is counted against the same budget: a process
				// full of loader workers would otherwise open one handle per
				// worker thread just to reject each of them.
				if (probes >= kMaxHandleProbes)
				{
					break;
				}
				++probes;

				if (processInformation.IsThreadWorkerThread())
				{
					continue;
				}

				return candidate;
			}

			// Everything below needs a handle on the target thread. Once the
			// budget is spent this pass can no longer confirm alertability, so
			// it stops instead of walking the whole thread list.
			if (probes >= kMaxHandleProbes)
			{
				break;
			}
			++probes;

			if (processInformation.IsThreadWorkerThread())
			{
				continue;
			}

			if (processInformation.IsThreadInAlertableState())
			{
				return candidate;
			}
		}
		while (processInformation.NextThread());

		return 0;
	}
}

DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_AcquireThread\n");

	ProcessInformation processInformation;
	if (!processInformation.SetProcess(hTargetProc))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Can't initialize ProcessInformation class\n");

		return SR_HT_ERR_PROC_INFO_FAIL;
	}

	const DWORD threadAccess = THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME;
	// The hijack duplicate carries the query bits too: verification itself
	// (GetThreadId needs QUERY_INFORMATION, GetProcessIdOfThread needs
	// QUERY_LIMITED_INFORMATION) would fail on a correctly-duplicated
	// minimal handle. The direct OpenThread below stays minimal on purpose -
	// a wider request there could be denied where the narrow one is granted.
	const DWORD hijackAccess = threadAccess | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION;

	DWORD ThreadID = 0;
	UniqueHandle hThread;

	// Sponsor fast-path: the caller pre-opened a specific target thread in
	// this very process. Duplicate it directly when it is actually
	// hijackable; otherwise discard it and fall through to the runtime
	// search below. The pre-pick (Interface PickHijackThreadTid) scores on
	// Waiting-vs-Running only and cannot know alertable/worker state, so an
	// unvalidated sponsor is how a never-scheduled TID burns the full
	// timeout as SR_HT_ERR_REMOTE_PENDING_TIMEOUT (0x1020000B, State stays
	// Pending). Stealth flags are untouched by this check.
	if ((Flags & INJ_HANDLE_HIJACKING) && SponsorThread && SponsorTid)
	{
		const HANDLE Sponsor = ReCa<HANDLE>(SponsorThread);
		const DWORD TargetPidForSponsor = GetProcessId(hTargetProc);
		const DWORD SponsorTidActual = GetThreadId(Sponsor);
		bool sponsor_usable = false;
		HANDLE Duplicated = nullptr;
		if (TargetPidForSponsor && SponsorTidActual && GetProcessIdOfThread(Sponsor) == TargetPidForSponsor
			&& SponsorTidActual == SponsorTid && SponsorTidActual != GetCurrentThreadId()
			&& DuplicateHandle(GetCurrentProcess(), Sponsor, GetCurrentProcess(),
				&Duplicated, hijackAccess, FALSE, 0) && Duplicated)
		{
			// Same bar as the runtime search tier 2: not a loader worker,
			// and either already alertable or Running. A Waiting WrQueue or
			// worker thread never wakes on PostThreadMessage, so hijacking
			// it guarantees Pending. Reject it here and let the 3-tier
			// search pick an alertable candidate instead.
			//
			// The Running value is the SAME dynamically-resolved enum the
			// search uses (FindHijackThread). Using the hardcoded
			// KTHREAD_STATE::Running here would let the two acceptance rules
			// drift: a sponsor the search would accept could be rejected by
			// this check (or vice versa) if the PDB ever resolved Running to
			// a different value. Fail-closed either way - a sponsor still
			// must be alertable or Running.
			const KTHREAD_STATE running_state = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);
			sponsor_usable = false;
			if (processInformation.SetProcess(hTargetProc))
			{
				// Publish the duplicate we already validated so GetTEB and the
				// alertable check reuse it instead of opening a second handle on
				// the same target thread.
				processInformation.SetCurrentThreadHandle(Duplicated, SponsorTidActual);
				do
				{
					// Only the enumeration entry whose TID matches the sponsor is
					// interesting. Written as a positive test rather than
					// "continue" on mismatch: continue re-evaluates the while
					// condition, which does advance the enumeration and is
					// bounded by the thread count, but reads like a loop-next
					// and invites a real spin if the condition ever changes.
					if (processInformation.GetThreadId() == SponsorTidActual)
					{
						if (processInformation.IsThreadWorkerThread())
						{
							LOG(2, "Sponsor TID %06X is a loader worker; ignoring sponsor\n", SponsorTidActual);
							break;
						}
						KTHREAD_STATE st{};
						KWAIT_REASON wr{};
						const bool have_state = processInformation.GetThreadState(st, wr);
						const bool alertable = processInformation.IsThreadInAlertableState();
						if (alertable || (have_state && st == running_state))
						{
							sponsor_usable = true;
						}
						else
						{
							LOG(2, "Sponsor TID %06X not alertable/Running (state=%d reason=%d); ignoring sponsor\n",
								SponsorTidActual, have_state ? static_cast<int>(st) : -1, have_state ? static_cast<int>(wr) : -1);
						}
						break;
					}
				}
				while (processInformation.NextThread());
			}
			else
			{
				// Snapshot unusable: cannot prove the sponsor is safe, so
				// do not burn the timeout on it. Fall through to search.
				LOG(2, "Sponsor validation snapshot failed; ignoring sponsor\n");
			}

			processInformation.SetCurrentThreadHandle(nullptr, 0);

			if (sponsor_usable)
			{
				ThreadID = SponsorTidActual;
				hThread.reset(Duplicated);
				Duplicated = nullptr;

				HijackStats Stats{ };
				Stats.Attempted = 1;
				Stats.Success = 1;
				Stats.Source = static_cast<DWORD>(HijackSource::Sponsor);
				Stats.DonorPid = GetCurrentProcessId();
				Stats.DonorHandle = PtrToUlong(Sponsor);
				Stats.GrantedAccess = hijackAccess;
				Stats.NewHandle = PtrToUlong(hThread.get());
				// Same sponsor telemetry shape as the process path
				// (Injection.cpp): the identity/state check passed, the
				// sponsor was used, and its probe ran (unless the caller
				// opted out of the sponsor roundtrip).
				Stats.SponsorState = 2;
				Stats.SponsorValidated = 1;
				Stats.SponsorProbed = (Flags & INJ_SKIP_SPONSOR_ROUNDTRIP) ? 0 : 1;
				Stats.FailCode = INJ_ERR_SUCCESS;
				RecordHijackOutcome(Stats, true);
				LOG(2, "Acquired target thread handle from sponsor\n");
			}
			else if (Duplicated)
			{
				CloseHandle(Duplicated);
				Duplicated = nullptr;
			}
		}
		else
		{
			if (Duplicated)
			{
				CloseHandle(Duplicated);
			}

			LOG(2, "Sponsor thread failed validation\n");
		}
	}

	if (!ThreadID)
	{
		// Sponsor validation above moved the ProcessInformation cursor (it
		// walks the thread list looking for the sponsor TID). Reset it so
		// the tiered search below starts at Threads[0], not mid-list.
		processInformation.SetProcess(hTargetProc);
		for (int attempt = 0; attempt < 8 && !ThreadID; ++attempt)
		{
			if (attempt > 0)
			{
				Sleep(25);

				if (!processInformation.RefreshInformation() || !processInformation.SetProcess(hTargetProc))
				{
					break;
				}
			}

			ThreadID = FindHijackThread(processInformation, false, true);

			if (!ThreadID && processInformation.SetProcess(hTargetProc))
			{
				ThreadID = FindHijackThread(processInformation, false, false);
			}

			if (!ThreadID && processInformation.SetProcess(hTargetProc))
			{
				ThreadID = FindHijackThread(processInformation, true, false);
			}
		}

		if (!ThreadID)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "No compatible thread found\n");

			return SR_HT_ERR_NO_THREADS;
		}
	}

	LOG(2, "Target thread %06X\n", ThreadID);

	if (!hThread)
	{
		// Seed the scan record. It is only recorded if no handle is acquired
		// below; a successful scan records its own ScanStats instead, and a
		// missing INJ_HANDLE_HIJACKING flag takes the Direct branch. So the UI
		// can tell "flag set but scan produced nothing" from "flag never
		// arrived".
		if (Flags & INJ_HANDLE_HIJACKING)
		{
			HijackStats Stats{ };
			Stats.Attempted = 1;
			Stats.Source = static_cast<DWORD>(HijackSource::Scan);
			Stats.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;

			if (!(Flags & INJ_NO_DONOR_SCAN))
			{
				HANDLE Hijacked = nullptr;
				const DWORD TargetPid = GetProcessId(hTargetProc);
				HijackStats ScanStats{ };
				ScanStats.Attempted = 1;
				const DWORD HijackRet = TargetPid
					? HijackThreadHandle(TargetPid, ThreadID, hijackAccess, Hijacked, &ScanStats, hTargetProc)
					: INJ_ERR_HANDLE_HIJACK_FAILED;
				if (HijackRet == INJ_ERR_SUCCESS && Hijacked)
				{
					ScanStats.Source = static_cast<DWORD>(HijackSource::Scan);
					RecordHijackOutcome(ScanStats, true);
					hThread.reset(Hijacked);
					LOG(2, "Acquired target thread handle via acquisition\n");
				}
				else
				{
					if (ScanStats.FailCode == INJ_ERR_SUCCESS)
					{
						ScanStats.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
					}
					ScanStats.Source = static_cast<DWORD>(HijackSource::Scan);
					// Carry the final scan counters into Stats; the single
					// RecordHijackOutcome below records them once, rather
					// than recording ScanStats and then Stats again.
					Stats = ScanStats;
					LOG(2, "Thread handle acquisition found no donor\n");
				}
			}

			if (!hThread)
			{
				// No donor: fail closed. There is no direct OpenThread
				// fallback - a fresh OpenThread is the loudest acquisition
				// telemetry and the whole point of this path is to avoid it.
				Stats.Source = static_cast<DWORD>(HijackSource::Scan);
				RecordHijackOutcome(Stats, true);

				INIT_ERROR_DATA(error_data, INJ_ERR_HANDLE_HIJACK_FAILED);

				LOG(2, "Thread handle acquisition found no donor; refusing (no direct fallback)\n");

				return SR_HT_ERR_OPEN_REFUSED;
			}
		}
		else
		{
			HijackStats Entry{ };
			Entry.Attempted = 1;
			Entry.Source = static_cast<DWORD>(HijackSource::Direct);
			Entry.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
			RecordHijackOutcome(Entry, true);
		}
	}

	if (!hThread)
	{
		// Reached only when INJ_HANDLE_HIJACKING is clear (the explicit
		// direct-open mode); the hijacking path above never falls through
		// without a handle.
		hThread.reset(OpenThread(threadAccess, FALSE, ThreadID));
	}
	if (!hThread)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "OpenThread failed: %08X\n", error_data.AdvErrorCode);

		return SR_HT_ERR_OPEN_THREAD_FAIL;
	}

	// W^X: 2-page split -- page0 RX code, page1 RW state. No RWX ever.
	// Layout: single 0x2000 reservation keeps RIP-relative reach (<2GB).
	// Code [0, state_offset) at pCode, state at 0x1000 boundary at pState.
	// lea rbx,[State] + jmp [ReturnTarget] disp32 are patched by +pad.
	constexpr size_t kWxCodePage = 0x1000;
	constexpr size_t kWxAllocSize = 0x2000;

	// Allocate both staging vectors BEFORE suspending the victim. std::vector's
	// allocator can throw std::bad_alloc, and an exception unwinding past a live
	// SuspendThread would reach Inject_Internal's catch(...) and leave the target
	// thread suspended forever. Nothing between the suspend below and the final
	// resume allocates, so no throw can escape while the thread is held. The
	// buffers are filled in place below; the sizes computed here equal the
	// shellcode_size/state_offset/data_size recomputed there.
	const size_t pre_shellcode_size = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd) - reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin));
	const size_t pre_state_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin));
	const size_t pre_data_size = pre_shellcode_size > pre_state_offset ? pre_shellcode_size - pre_state_offset : 0;
	std::vector<BYTE> shellcode(pre_shellcode_size);
	std::vector<BYTE> staged(kWxCodePage + pre_data_size, 0xCC);

	// Timing: the remote staging allocation plus all host-side stub
	// preparation complete BEFORE the victim is suspended, so the frozen
	// window holds only GetThreadContext, one WPM, one RX promotion and
	// SetThreadContext (four syscalls). A GetTickCount64 delta heuristic
	// keys on frozen-thread time, so every remote round-trip moved out of
	// the window directly shrinks the observable stall. QueueUserAPC was
	// evaluated and rejected for this stub: it terminates with jmp to the
	// saved ReturnTarget instead of ret, which would abandon the kernel APC
	// dispatch (RtlDispatchAPC expects the routine to return) and corrupt
	// the thread. Suspend-then-minimal-window is the stealth-maximum for
	// this stub contract. No C++ allocation happens below that could throw
	// past a live suspend: VirtualAllocEx/WPM/memcpy cannot throw.
	void * pMem = VirtualAllocEx(hTargetProc, nullptr, kWxAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	// pMem is only the W^X hijack stub: a code page plus an SR_REMOTE_DATA
	// state page whose pArg/pRoutine fields merely point at the caller's
	// argument block (allocated and owned by ManualMapping's own guard). The
	// operator's DLL path lives in that argument block, not here, so freeing
	// pMem would not scrub the path. The guard is released on the recovery
	// paths below whenever the remote stub may still be executing from pMem,
	// or when the thread is parked with RIP inside it; in both cases the
	// memory must stay mapped and is deliberately leaked (reclaimed only when
	// the target exits).
	RemoteAllocation allocation_guard(hTargetProc, pMem);

	// Wipe the stub before the guard releases it, but only when the guard will
	// actually free it: on the recovery paths below the guard is release()d
	// (the stub may still be executing from the block, or the thread is parked
	// inside it) and the wipe is skipped, preserving the documented leak.
	auto scrub_guard = MakeScopeExit([&]() noexcept {
		if (allocation_guard.get())
		{
			ScrubRemoteRegion(hTargetProc, pMem, kWxAllocSize);
		}
	});

	const ULONG_PTR shellcode_begin = reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin);
	const ULONG_PTR shellcode_end = reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd);
	const size_t shellcode_size = static_cast<size_t>(shellcode_end - shellcode_begin);
	if (!shellcode_size || shellcode_size > 0x1000)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	memcpy(shellcode.data(), RemoteThreadHijackBegin, shellcode_size);

	const size_t return_target_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadReturnTarget) - shellcode_begin);
	const size_t state_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - shellcode_begin);
	if (return_target_offset + sizeof(ULONG_PTR) > shellcode_size || state_offset + sizeof(SR_REMOTE_DATA) > shellcode_size)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	// Split: code_size = bytes before state, data_size = state..end.
	const size_t code_size = state_offset;
	const size_t data_size = shellcode_size - state_offset;
	const size_t pad = kWxCodePage - code_size;
	if (code_size >= kWxCodePage || data_size > kWxCodePage)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	memcpy(staged.data(), shellcode.data(), code_size);
	memcpy(staged.data() + kWxCodePage, shellcode.data() + state_offset, data_size);

	// Patch lea rbx,[State] (48 8D 1D disp32) and
	// jmp qword ptr [ReturnTarget] (FF 25 disp32) by +pad.
	// Note: one template cast per line to keep line debuggers clean.
	{
		bool lea_patched = false;
		bool jmp_patched = false;
		const int pad32 = static_cast<int>(pad);
		for (size_t i = 0; i + 7 <= code_size; ++i)
		{
			const bool is_lea = staged[i] == 0x48 && staged[i + 1] == 0x8D && staged[i + 2] == 0x1D;
			if (!lea_patched && is_lea)
			{
				int disp = 0;
				memcpy(&disp, staged.data() + i + 3, sizeof(disp));
				disp += pad32;
				memcpy(staged.data() + i + 3, &disp, sizeof(disp));
				lea_patched = true;
			}
		}
		for (size_t i = 0; i + 6 <= code_size; ++i)
		{
			const bool is_jmp = staged[i] == 0xFF && staged[i + 1] == 0x25;
			if (is_jmp)
			{
				int disp = 0;
				memcpy(&disp, staged.data() + i + 2, sizeof(disp));
				disp += pad32;
				memcpy(staged.data() + i + 2, &disp, sizeof(disp));
				jmp_patched = true;
				break;
			}
		}
		if (!lea_patched || !jmp_patched)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return SR_HT_ERR_STUB_PATCH_FAIL;
		}
	}

	// Patch the gs:[LastError] disp32 in the copied stub
	// (mov r11d, gs:[TEB_LAST_ERROR] = 65 44 8B 1C 25 disp32) with the
	// PDB-resolved TEB::LastErrorValue. Unlike the two RIP-relative sites
	// above this is an absolute segment offset, so the disp32 is overwritten
	// (not adjusted by +pad). Fail-closed: never let the assembled 68H
	// placeholder reach the target when the offset was not resolved.
	{
		const DWORD teb_last_error = g_DynamicOffsets.TebLastErrorValue;
		bool last_error_patched = false;
		if (g_DynamicOffsets.Ready && teb_last_error)
		{
			for (size_t i = 0; i + 9 <= code_size; ++i)
			{
				const bool is_last_error =
					staged[i] == 0x65 && staged[i + 1] == 0x44 && staged[i + 2] == 0x8B &&
					staged[i + 3] == 0x1C && staged[i + 4] == 0x25;
				if (is_last_error)
				{
					memcpy(staged.data() + i + 5, &teb_last_error, sizeof(teb_last_error));
					last_error_patched = true;
					break;
				}
			}
		}
		if (!last_error_patched)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return SR_HT_ERR_STUB_PATCH_FAIL;
		}
	}

	const DWORD sr_suspend = SuspendThread(hThread);
	if (sr_suspend == (DWORD)-1)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "SuspendThread failed: %08X\n", error_data.AdvErrorCode);

		

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	// SuspendThread returns the PREVIOUS count. Non-zero means someone else
	// already held the thread suspended: a single ResumeThread later would
	// leave it still suspended, so the stub would stay Pending until the
	// 60 s timeout (SR_HT_ERR_REMOTE_PENDING_TIMEOUT 0x1020000B) even
	// though the hijack itself was fine. Fail fast so the caller can try
	// the next TID instead of burning the full timeout on a parked thread.
	if (sr_suspend > 0)
	{
		LOG(2, "Thread was already suspended (previous count %u); skipping it\n", sr_suspend);

		ResumeThread(hThread);

		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	LOG(2, "Target thread suspended\n");

	CONTEXT OldContext{ 0 };
	OldContext.ContextFlags = CONTEXT_ALL;

	StoreThreadExecStat(g_ThreadExecStats.Attempted, 1);
	StoreThreadExecStat(g_ThreadExecStats.HijackedTid, ThreadID);

	if (!GetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "GetThreadContext failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		

		return SR_HT_ERR_GET_CONTEXT_FAIL;
	}

	// Recorded only after the capture actually succeeded, so the host reports
	// whether the original context was captured rather than asserting a
	// restore happened.
	StoreThreadExecStat(g_ThreadExecStats.ContextSaved, 1);

	// The stub body (alloc, patch) is already staged above while the victim
	// ran free; only the ReturnTarget slot needs the captured RIP, so it is
	// patched below inside the frozen window.
	const size_t staged_return_offset = kWxCodePage + (return_target_offset - state_offset);
	const size_t staged_state_offset = kWxCodePage;

	const auto OldRIP = OldContext.Rip;
	*reinterpret_cast<ULONG_PTR *>(staged.data() + staged_return_offset) = OldRIP;
	auto * remote_data = reinterpret_cast<SR_REMOTE_DATA *>(staged.data() + staged_state_offset);
	remote_data->pArg = pArg;
	remote_data->pRoutine = pRoutine;

	BYTE * pCode = ReCa<BYTE *>(pMem);
	BYTE * pState = ReCa<BYTE *>(pMem) + kWxCodePage;
	void * pRemoteFunc = pCode;
	OldContext.Rip = reinterpret_cast<ULONG_PTR>(pRemoteFunc);

	LOG(2, "Remote thread shell prepared (W^X split: code RX 0x1000, state RW)\n");

	LOG(2, "Acquiring thread with:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pArg);

	if (!WriteProcessMemory(hTargetProc, pMem, staged.data(), staged.size(), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		
		

		return SR_HT_ERR_WPM_FAIL;
	}

	// W^X promotion: code page RW->RX only. State page stays RW.
	// No RWX exists at any point; VCheck RWX scans see RW + RX.
	{
		DWORD old_protect = 0;
		if (!VirtualProtectEx(hTargetProc, pCode, kWxCodePage, PAGE_EXECUTE_READ, &old_protect))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "VirtualProtectEx(RX) failed: %08X\n", error_data.AdvErrorCode);

			ResumeThread(hThread);

			return SR_HT_ERR_WPM_FAIL;
		}

		// Best-effort: the RX promotion above is the correctness boundary, but a
		// failure here means the CPU may run stale code, so at least record it.
		if (!FlushInstructionCache(hTargetProc, pCode, code_size))
		{
			LOG(2, "FlushInstructionCache failed: %08X\n", GetLastError());
		}
		LOG(2, "Acquired code promoted RW->RX, state stays RW\n");
	}

	if (!SetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "SetThreadContext failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		
		

		return SR_HT_ERR_SET_CONTEXT_FAIL;
	}

	LOG(2, "RIP replaced\n");

	// The hijacked RIP is now live. The original RIP goes back in once the
	// remote shell has run, so from the host's point of view the context is
	// restored at that point - not here.
	const DWORD sr_resume = ResumeThread(hThread);
	if (sr_resume == (DWORD)-1)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "ResumeThread failed: %08X\n", error_data.AdvErrorCode);

		OldContext.Rip = OldRIP;
		if (!SetThreadContext(hThread, &OldContext))
		{
			LOG(2, "Thread context recovery failed; remote allocation retained\n");

			allocation_guard.release();
			return SR_HT_ERR_RECOVERY_REQUIRED;
		}

		if (ResumeThread(hThread) == (DWORD)-1)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "Recovered thread could not be resumed: %08X\n", error_data.AdvErrorCode);

			
			

			return SR_HT_ERR_RESUME_FAIL;
		}

		
		

		return SR_HT_ERR_RESUME_FAIL;
	}

	LOG(2, "Thread resumed\n");

	// 0 means the thread had actually been suspended, so the hijack is complete
	// from the loader's point of view. The RIP is restored by the remote shell.
	StoreThreadExecStat(g_ThreadExecStats.Resumed, 1);
	StoreThreadExecStat(g_ThreadExecStats.SuspendCount, sr_resume);

	(void)PostThreadMessageW(ThreadID, WM_NULL, 0, 0);

	Sleep(SR_REMOTE_DELAY);

	SR_REMOTE_DATA data{ };
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	LOG(2, "Entering wait state\n");

	// Forced recovery for the error paths below. The saved RIP is only written
	// back when the stub's own frame is provably unwound - either the thread
	// already left the code page, or its RSP is back at the captured baseline,
	// which the stub reaches only before its first push or after popping every
	// register (immediately before the final jmp [ReturnTarget]). Mid-call the
	// RSP sits in the stub's aligned scratch frame and the victim's registers
	// are clobbered, so relocating RIP there would resume the victim with a
	// corrupt stack (the "ghost thread" crash). The state read that selected
	// this path may be stale, so a bounded re-poll first gives the stub a few
	// chances to finish on its own. When the frame is not unwound the thread is
	// resumed untouched and reported not-restored, which escalates to the
	// existing recovery-required path instead of a blind forced restore. Every
	// iteration balances exactly one SuspendThread with one ResumeThread.
	constexpr int kForceRestorePolls = 3;
	auto ForceRestoreContext = [&](bool & restored, bool & resumed) -> void
	{
		restored = false;
		resumed = false;

		const ULONG_PTR code_base = ReCa<ULONG_PTR>(pCode);
		const ULONG_PTR code_end = code_base + kWxCodePage;

		for (int poll = 0; poll < kForceRestorePolls; ++poll)
		{
			if (poll > 0)
			{
				Sleep(2);
			}

			if (SuspendThread(hThread) == (DWORD)-1)
			{
				// Thread is gone: it can no longer be running our code.
				return;
			}

			CONTEXT ctx{ 0 };
			ctx.ContextFlags = CONTEXT_CONTROL;
			bool settled = false;
			if (GetThreadContext(hThread, &ctx))
			{
				if (ctx.Rip < code_base || ctx.Rip >= code_end)
				{
					// Already outside the stub: the shell restored the context itself.
					restored = true;
					settled = true;
				}
				else if (ctx.Rsp == OldContext.Rsp)
				{
					// Frame unwound (or never pushed): the only in-code-page
					// state where relocating RIP is safe.
					ctx.Rip = OldRIP;
					restored = SetThreadContext(hThread, &ctx) != FALSE;
					settled = true;
				}
				// else: still inside the stub with an inconsistent stack; leave
				// RIP alone and re-poll.
			}

			resumed = ResumeThread(hThread) != (DWORD)-1;
			if (!resumed)
			{
				restored = false;
				return;
			}

			if (settled)
			{
				return;
			}
		}
	};

	auto Timer = GetTickCount64();
	DWORD consecutive_read_failures = 0;
	while (GetTickCount64() - Timer < Timeout)
	{
		auto dwWaitRet = WaitForSingleObject(g_hInterruptEvent, 1);

		BOOL bRet = ReadProcessMemory(hTargetProc, pState, &data, sizeof(data), nullptr);
		if (bRet)
		{
			consecutive_read_failures = 0;

			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished)
			{
				LOG(2, "Shelldata retrieved\n");

				break;
			}
		}

		if (dwWaitRet == WAIT_OBJECT_0)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "Interrupt!\n");

			bool context_restored = false;
			bool resumed = false;
			if (bRet && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				ForceRestoreContext(context_restored, resumed);
			}

			if (!context_restored)
			{
				LOG(2, "Thread context recovery failed; remote allocation retained\n");
				allocation_guard.release();
			}

			// The interrupt path reinstates the saved context from here, unlike
			// the normal path where the remote shell does it. Only a restore
			// that observed the stub frame unwound counts; a thread still inside
			// the stub means the shell may still be live, so escalate to
			// recovery-required instead of claiming a clean abort.
			StoreThreadExecStat(g_ThreadExecStats.ContextRestored, context_restored ? 1 : 0);
			StoreThreadExecStat(g_ThreadExecStats.Resumed, resumed ? 1 : 0);
			StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
			StoreThreadExecStat(g_ThreadExecStats.RestoreMode, 2);
			StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? error_data.AdvErrorCode : SR_HT_ERR_RECOVERY_REQUIRED);

			SetEvent(g_hInterruptedEvent);

			return context_restored ? SR_ERR_INTERRUPT : SR_HT_ERR_RECOVERY_REQUIRED;
		}

		if (!bRet)
		{
			DWORD target_exit = 0;
			if (GetExitCodeProcess(hTargetProc, &target_exit) && target_exit != STILL_ACTIVE)
			{
				INIT_ERROR_DATA(error_data, target_exit);

				LOG(2, "Target process exited during load\n");

				allocation_guard.release();

				return SR_ERR_TARGET_EXITED;
			}

			if (++consecutive_read_failures <= 100)
			{
				continue;
			}

			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			bool context_restored = false;
			bool resumed = false;
			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				ForceRestoreContext(context_restored, resumed);
			}

		if (!context_restored)
		{
			LOG(2, "Thread context recovery failed; remote allocation retained\n");
			allocation_guard.release();
		}

		// Forced recovery is only performed when the stub frame was observed
		// unwound (see ForceRestoreContext). A thread still inside the stub is
		// left running, so the mode stays unverified and the outcome escalates
		// to recovery-required rather than reporting a restore that did not
		// happen.
		StoreThreadExecStat(g_ThreadExecStats.ContextRestored, context_restored ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.Resumed, resumed ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.RestoreMode, 2);
		StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_RPM_FAIL : SR_HT_ERR_RECOVERY_REQUIRED);

		return context_restored ? SR_HT_ERR_RPM_FAIL : SR_HT_ERR_RECOVERY_REQUIRED;
		}

	}
	if (data.State != SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		bool context_restored = false;
		bool resumed = false;
		if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
		{
			LOG(2, "Shell timed out\n");

			ForceRestoreContext(context_restored, resumed);
		}

		if (!context_restored)
		{
			LOG(2, "Thread context recovery failed; remote allocation retained\n");
			allocation_guard.release();
		}

		// Forced recovery, same as the RPM-failure path: only a restore that
		// observed the stub frame unwound is reported as pending-timeout; a
		// thread still inside the stub escalates to recovery-required because
		// the shell may still be live in the target.
		StoreThreadExecStat(g_ThreadExecStats.ContextRestored, context_restored ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.Resumed, resumed ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.RestoreMode, 2);
		StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_REMOTE_PENDING_TIMEOUT : SR_HT_ERR_RECOVERY_REQUIRED);

		if (context_restored)
		{
			return SR_HT_ERR_REMOTE_PENDING_TIMEOUT;
		}

		return SR_HT_ERR_RECOVERY_REQUIRED;
	}

	

	

	LOG(2, "pRoutine returned: %08X\n", data.Ret);

	Out	= data.Ret;

	bool context_restored = false;
	for (int check = 0; check < 5 && !context_restored; ++check)
	{
		if (check > 0)
		{
			Sleep(10);
		}

		if (SuspendThread(hThread) == (DWORD)-1)
		{
			context_restored = true;

			break;
		}

		CONTEXT check_context{ 0 };
		check_context.ContextFlags = CONTEXT_CONTROL;

		bool resumed_check = false;
		if (GetThreadContext(hThread, &check_context))
		{
			const ULONG_PTR check_rip = check_context.Rip;
			const ULONG_PTR code_base = ReCa<ULONG_PTR>(pCode);
			const ULONG_PTR code_end = code_base + kWxCodePage;
			const bool outside_code = check_rip < code_base || check_rip >= code_end;
			if (outside_code)
			{
				context_restored = true;
			}
			else if (check_context.Rsp == OldContext.Rsp)
			{
				// Frame unwound (all registers popped, or none pushed yet): the
				// only in-code-page state where relocating RIP is safe. A thread
				// mid-frame is left for the next retry, then escalates.
				check_context.Rip = OldRIP;
				context_restored = SetThreadContext(hThread, &check_context) != FALSE;
			}

			resumed_check = ResumeThread(hThread) != (DWORD)-1;
		}
		else
		{
			resumed_check = ResumeThread(hThread) != (DWORD)-1;
		}

		if (!resumed_check)
		{
			context_restored = false;
		}
	}

	if (context_restored)
	{
		LOG(2, "Thread context restored automatically\n");
	}
	else
	{
		LOG(2, "Thread context recovery failed; remote allocation retained\n");
		allocation_guard.release();
	}

	// The RIP was observed back outside the hijack code page (or the thread was
	// already gone, which also means it is no longer running our code), or an
	// in-page RIP was relocated only after the RSP baseline proved the stub
	// frame unwound. Recorded here rather than at the call site so the host
	// reports this measured outcome instead of a hardcoded "restored
	// automatically".
	StoreThreadExecStat(g_ThreadExecStats.ContextRestored, context_restored ? 1 : 0);
	StoreThreadExecStat(g_ThreadExecStats.Success, context_restored ? 1 : 0);
	StoreThreadExecStat(g_ThreadExecStats.RestoreMode, 1); // verified: RIP outside, or frame-validated in-page restore
	StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? ERROR_SUCCESS : SR_HT_ERR_RECOVERY_REQUIRED);

	return context_restored ? SR_ERR_SUCCESS : SR_HT_ERR_RECOVERY_REQUIRED;
}

void ResetThreadExecStats()
{
	const THREAD_EXEC_STATS Empty{};
	StoreThreadExecStats(Empty);
}

void __stdcall GetLastThreadExecStats(THREAD_EXEC_STATS * Out)
{
#pragma EXPORT_FUNCTION("CoreExecStats", __FUNCDNAME__)

	if (Out)
	{
		LoadThreadExecStats(*Out);
	}
}
