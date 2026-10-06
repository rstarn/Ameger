#include "Core/Utility/Header/PrecompiledHeader.h"
#include <unordered_set>
#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "System/Handle/HandleHijack.h"

namespace
{
	constexpr ULONG kSystemExtendedHandleInformation = 64;
	constexpr ULONG kSystemHandleInformation = 16;

	constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

	constexpr size_t kInitialEnumBytes = 1 << 20;
	constexpr size_t kMaxEnumBytes = 64ULL * 1024ULL * 1024ULL;

	// Scan budgets: bound the worst case to a handful of operations so a miss
	// can never degrade into a system-wide open/duplicate storm.
	constexpr size_t kMaxForeignOwners = 16;	// distinct non-target owners opened per scan
	constexpr size_t kMaxDupAttempts = 512;		// total duplicate attempts per scan

	struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL
	{
		PVOID Object;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	};

	struct SYSTEM_HANDLE_INFORMATION_EX_LOCAL
	{
		ULONG_PTR NumberOfHandles;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
	};

	struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY
	{
		USHORT UniqueProcessId;
		USHORT CreatorBackTraceIndex;
		UCHAR ObjectTypeIndex;
		UCHAR HandleAttributes;
		USHORT HandleValue;
		PVOID Object;
		ULONG GrantedAccess;
	};

	struct SYSTEM_HANDLE_INFORMATION_LEGACY
	{
		ULONG NumberOfHandles;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY Handles[1];
	};

	using f_NtQuerySystemInformationLocal = NTSTATUS(__stdcall *)(ULONG, void *, ULONG, ULONG *);
	using f_NtDuplicateObjectLocal = NTSTATUS(__stdcall *)(HANDLE, HANDLE, HANDLE, HANDLE *, ACCESS_MASK, ULONG, ULONG);

	struct NtdllHandles
	{
		f_NtQuerySystemInformationLocal NtQuerySystemInformation = nullptr;
		f_NtDuplicateObjectLocal NtDuplicateObject = nullptr;
	};

	__forceinline bool NtOk(NTSTATUS Status)
	{
		return Status >= 0;
	}

	bool ResolveNtdll(NtdllHandles & Out)
	{
		// Zero-literal construction: no "ntdll.dll" bytes of any kind in
		// .rdata, not even ciphertext. Each char is a template parameter.
		// Direct arity (not the COUNT dispatch): deterministic expansion.
		wchar_t ntdll_mod[10];
		do {
			constexpr auto stack_key = KC_STACK_KEY_;
			KC_SWC_10(ntdll_mod, stack_key, L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0');
		} while (0);
		HMODULE ntdll = GetModuleHandleW(ntdll_mod);
		if (!ntdll)
		{
			return false;
		}

		Out.NtQuerySystemInformation = ReCa<f_NtQuerySystemInformationLocal>(GetProcAddress(ntdll, XOR_STR_A("NtQuerySystemInformation").get()));
		Out.NtDuplicateObject = ReCa<f_NtDuplicateObjectLocal>(GetProcAddress(ntdll, XOR_STR_A("NtDuplicateObject").get()));

		return Out.NtQuerySystemInformation && Out.NtDuplicateObject;
	}

	bool EnableSeDebugPrivilege()
	{
		HANDLE RawToken = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &RawToken))
		{
			return false;
		}

		UniqueHandle Token(RawToken);

		LUID Luid{ 0 };
		// SE_DEBUG_NAME is a plaintext SDK literal ("SeDebugPrivilege") that
		// would otherwise persist in .rdata; decrypt it onto the stack for
		// the duration of this call only.
		if (!LookupPrivilegeValueW(nullptr, XOR_STR_W(L"SeDebugPrivilege").get(), &Luid))
		{
			return false;
		}

		TOKEN_PRIVILEGES Privileges{ 0 };
		Privileges.PrivilegeCount = 1;
		Privileges.Privileges[0].Luid = Luid;
		Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(Token.get(), FALSE, &Privileges, sizeof(Privileges), nullptr, nullptr))
		{
			return false;
		}

		return GetLastError() == ERROR_SUCCESS;
	}

	// Object-type indices are boot-stable: calibrate once per process
	// lifetime and reuse (0 = not calibrated yet).
	std::atomic<USHORT> g_CachedProcessType{ 0 };
	std::atomic<USHORT> g_CachedThreadType{ 0 };

	// SeDebugPrivilege is enabled lazily - only after an owner open fails -
	// and at most once per process lifetime. Common paths (target-owned and
	// self-owned donors) never need it, so the AdjustTokenPrivileges call
	// disappears from the default acquisition.
	std::atomic<bool> g_DebugPrivilegeAttempted{ false };

	void EnsureSeDebugPrivilege()
	{
		bool expected = false;
		if (g_DebugPrivilegeAttempted.compare_exchange_strong(expected, true))
		{
			EnableSeDebugPrivilege();
		}
	}

	struct EnumSnapshot
	{
		std::vector<BYTE> Buffer;
		bool Extended = true;
	};

	DWORD QueryHandleSnapshot(const NtdllHandles & Ntdll, ULONG InfoClass, bool Extended, EnumSnapshot & Out, NTSTATUS & LastStatus)
	{
		size_t Size = kInitialEnumBytes;
		LastStatus = 0;

		for (;;)
		{
			try
			{
				Out.Buffer.resize(Size);
			}
			catch (...)
			{
				return INJ_ERR_OUT_OF_MEMORY_NEW;
			}

			ULONG Returned = 0;
			const NTSTATUS Status = Ntdll.NtQuerySystemInformation(InfoClass, Out.Buffer.data(),
				static_cast<ULONG>(Size), &Returned);
			LastStatus = Status;

			if (Status == kStatusInfoLengthMismatch)
			{
				if (Size >= kMaxEnumBytes)
				{
					return INJ_ERR_OUT_OF_MEMORY_EXT;
				}

				size_t Next = Returned > 0 ? (static_cast<size_t>(Returned) + 0x10000) : (Size * 2);
				if (Next <= Size)
				{
					Next = Size * 2;
				}
				if (Next > kMaxEnumBytes)
				{
					Next = kMaxEnumBytes;
				}

				Size = Next;
				continue;
			}

			if (!NtOk(Status))
			{
				return INJ_ERR_HANDLE_HIJACK_FAILED;
			}

			Out.Extended = Extended;
			return INJ_ERR_SUCCESS;
		}
	}

	DWORD QueryAnySnapshot(const NtdllHandles & Ntdll, EnumSnapshot & Out, NTSTATUS & LastStatus)
	{
		DWORD Result = QueryHandleSnapshot(Ntdll, kSystemExtendedHandleInformation, true, Out, LastStatus);
		if (Result == INJ_ERR_SUCCESS)
		{
			return Result;
		}

		if (Result == INJ_ERR_OUT_OF_MEMORY_NEW || Result == INJ_ERR_OUT_OF_MEMORY_EXT)
		{
			return Result;
		}

		return QueryHandleSnapshot(Ntdll, kSystemHandleInformation, false, Out, LastStatus);
	}

	// Self-calibration: locate our own known handle inside the snapshot and
	// read back its ObjectTypeIndex. Indices vary per boot, so hardcoding
	// them is the classic reason hijack scans "find nothing".
	bool FindOwnEntryType(const EnumSnapshot & Snapshot, DWORD SelfPid, ULONG_PTR HandleValue, USHORT & TypeIndexOut)
	{
		if (Snapshot.Extended)
		{
			if (Snapshot.Buffer.size() < sizeof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL))
			{
				return false;
			}

			const auto * Info = ReCa<const SYSTEM_HANDLE_INFORMATION_EX_LOCAL *>(Snapshot.Buffer.data());
			const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles);
			if (Header >= Snapshot.Buffer.size())
			{
				return false;
			}

			size_t Capacity = (Snapshot.Buffer.size() - Header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL);
			size_t Count = static_cast<size_t>(Info->NumberOfHandles);
			if (Count > Capacity)
			{
				Count = Capacity;
			}

			for (size_t Index = 0; Index < Count; ++Index)
			{
				const auto & Entry = Info->Handles[Index];
				if (static_cast<DWORD>(Entry.UniqueProcessId) == SelfPid && Entry.HandleValue == HandleValue)
				{
					TypeIndexOut = Entry.ObjectTypeIndex;
					return true;
				}
			}
		}
		else
		{
			if (Snapshot.Buffer.size() < sizeof(SYSTEM_HANDLE_INFORMATION_LEGACY))
			{
				return false;
			}

			const auto * Info = ReCa<const SYSTEM_HANDLE_INFORMATION_LEGACY *>(Snapshot.Buffer.data());
			const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_LEGACY, Handles);
			if (Header >= Snapshot.Buffer.size())
			{
				return false;
			}

			size_t Capacity = (Snapshot.Buffer.size() - Header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY);
			size_t Count = static_cast<size_t>(Info->NumberOfHandles);
			if (Count > Capacity)
			{
				Count = Capacity;
			}

			for (size_t Index = 0; Index < Count; ++Index)
			{
				const auto & Entry = Info->Handles[Index];
				if (static_cast<DWORD>(Entry.UniqueProcessId) == SelfPid &&
					static_cast<ULONG_PTR>(Entry.HandleValue) == HandleValue)
				{
					TypeIndexOut = static_cast<USHORT>(Entry.ObjectTypeIndex);
					return true;
				}
			}
		}

		return false;
	}

	// Functional rights probes. NtQueryObject(BasicInformation) is filtered
	// on protected targets, so rights are proven by doing, not by asking.
	// Dup-with-explicit-mask success already proves the source carried the
	// rights (the kernel refuses otherwise); the probes below confirm the
	// duplicated handle is honestly usable. All probes leave zero lasting
	// effect in the target.
	bool ProbeQueryUsable(HANDLE Candidate, DWORD TargetPid)
	{
		if (GetProcessId(Candidate) != TargetPid)
		{
			return false;
		}

		wchar_t Name[MAX_PATH * 2]{ 0 };
		DWORD Length = static_cast<DWORD>(sizeof(Name) / sizeof(Name[0]));
		return QueryFullProcessImageNameW(Candidate, 0, Name, &Length) != FALSE && Length > 0;
	}

	bool ProbeVmOperation(HANDLE Candidate)
	{
		void * Page = VirtualAllocEx(Candidate, nullptr, 0x1000, MEM_RESERVE, PAGE_NOACCESS);
		if (!Page)
		{
			return false;
		}

// Retried once: a release that fails while the reserve is still live is
	// occasionally transient, and a retry reclaims the page instead of leaving
	// a permanently reserved hole in the candidate. Still fails closed if the
	// second attempt fails.
	for (int attempt = 0; attempt < 2; ++attempt)
	{
		if (VirtualFreeEx(Candidate, Page, 0, MEM_RELEASE))
		{
			return true;
		}
	}

	// The reserve succeeded on this same handle, so a persistently failed
	// release is unexpected. The probe page then stays reserved in the target -
	// bounded by the scan budget, but genuinely unreclaimable. The return value
	// is unchanged: a candidate that cannot release the probe is rejected
	// exactly as before.
	LOG(1, "ProbeVmOperation: release failed twice (%lu)\n", GetLastError());
	return false;
}

	bool VerifyProcessDonor(HANDLE Candidate, DWORD TargetPid)
	{
		if (!Candidate || Candidate == INVALID_HANDLE_VALUE || !TargetPid)
		{
			return false;
		}

		return ProbeQueryUsable(Candidate, TargetPid) && ProbeVmOperation(Candidate);
	}

	bool VerifyThreadDonor(HANDLE Candidate, DWORD TargetPid, DWORD TargetTid)
	{
		if (!Candidate || Candidate == INVALID_HANDLE_VALUE || !TargetTid)
		{
			return false;
		}

		return GetThreadId(Candidate) == TargetTid && GetProcessIdOfThread(Candidate) == TargetPid;
	}

	// Opens (and caches) a handle to an owner process for duplication.
	// Failures are cached too, so one unreachable owner cannot be re-opened
	// for each of its entries. SeDebugPrivilege is enabled on the first
	// failure and the open retried once.
	HANDLE OpenOwnerCached(std::vector<std::pair<DWORD, UniqueHandle>> & Owners, DWORD OwnerPid)
	{
		for (auto & Owner : Owners)
		{
			if (Owner.first == OwnerPid)
			{
				return Owner.second ? Owner.second.get() : nullptr;
			}
		}

		UniqueHandle Owner(OpenProcess(PROCESS_DUP_HANDLE, FALSE, OwnerPid));
		if (!Owner)
		{
			EnsureSeDebugPrivilege();
			Owner.reset(OpenProcess(PROCESS_DUP_HANDLE, FALSE, OwnerPid));
		}

		HANDLE Raw = Owner ? Owner.get() : nullptr;
		try
		{
			Owners.emplace_back(OwnerPid, std::move(Owner));
		}
		catch (...)
		{
			return nullptr;
		}

		return Raw;
	}

	DWORD ScanSnapshot(const NtdllHandles & Ntdll, const EnumSnapshot & Snapshot, DWORD SelfPid,
		DWORD TargetPid, DWORD TargetTid, bool ThreadScan, USHORT WantedType, bool HaveType, DWORD DesiredAccess,
		HANDLE TargetOwnerHandle, HANDLE & Out, HijackStats & Detail)
	{
		Out = nullptr;
		// NOTE: fills only scan-owned fields. Attempted/Source/SnapStatus/
		// Calibrated belong to the caller (HijackImpl) - resetting Detail
		// here once wiped Attempted to 0 on every scan, which made the UI
		// report "no telemetry" while real counters arrived intact.
		Detail.Examined = 0;
		Detail.DonorPid = 0;
		Detail.GrantedAccess = 0;
		Detail.OwnersOpened = 0;
		Detail.DupDenied = 0;
		Detail.VerifyRejected = 0;
		Detail.DonorHandle = 0;
		Detail.NewHandle = 0;
		Detail.TotalHandles = 0;
		Detail.BudgetSkipped = 0;
		Detail.Success = 0;
		Detail.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;

		std::vector<std::pair<DWORD, UniqueHandle>> Owners;
		// Objects already proven to be the wrong target (dup succeeded, verify
		// rejected): the same object can never verify later, so later entries
		// pointing at it are skipped without another duplicate.
		std::unordered_set<ULONG_PTR> WrongObjects;
		size_t Examined = 0;
		size_t Duplicated = 0;
		size_t DupDenied = 0;
		size_t VerifyRejected = 0;
		size_t DupAttempts = 0;
		size_t BudgetSkipped = 0;
		bool BudgetHit = false;
		DWORD FoundDonorPid = 0;
		DWORD FoundGranted = 0;
		DWORD FoundDonorHandle = 0;
		DWORD FoundNewHandle = 0;

		const auto TryCandidate = [&](DWORD OwnerPid, ULONG_PTR HandleValue, PVOID Object) -> bool
		{
			if (DupAttempts >= kMaxDupAttempts)
			{
				// Budget stop: bound the worst case so a miss can never
				// degrade into a system-wide duplicate storm.
				++BudgetSkipped;
				BudgetHit = true;
				return false;
			}

			++DupAttempts;

			const HANDLE SourceValue = ReCa<HANDLE>(HandleValue);
			if (!SourceValue)
			{
				return false;
			}

			// Our own table: duplicate directly, no owner open needed.
			if (OwnerPid == SelfPid)
			{
				HANDLE DirectRaw = nullptr;
				if (!DuplicateHandle(GetCurrentProcess(), SourceValue, GetCurrentProcess(),
					&DirectRaw, DesiredAccess, FALSE, 0) || !DirectRaw)
				{
					++DupDenied;
					if (DirectRaw)
					{
						CloseHandle(DirectRaw);
					}

					return false;
				}

				// RAII from the moment of acquisition: every later exit -
				// including an exception thrown while recording the rejected
				// object - closes the duplicate instead of leaking it.
				UniqueHandle Direct(DirectRaw);

				++Duplicated;
				const bool Ok = ThreadScan
					? VerifyThreadDonor(Direct.get(), TargetPid, TargetTid)
					: VerifyProcessDonor(Direct.get(), TargetPid);
				if (!Ok)
				{
					++VerifyRejected;
					if (Object)
					{
						WrongObjects.insert(ReCa<ULONG_PTR>(Object));
					}
					return false;
				}

				FoundDonorPid = OwnerPid;
				FoundGranted = DesiredAccess;
				FoundDonorHandle = static_cast<DWORD>(HandleValue);
				FoundNewHandle = PtrToUlong(Direct.get());
				Out = Direct.release();
				return true;
			}

			// Owner resolution: target-owned entries duplicate from the
			// caller-supplied handle to the target when available (the target
			// is never opened a second time); foreign owners go through the
			// bounded, negatively-cached owner cache.
			HANDLE Owner = nullptr;
			if (OwnerPid == TargetPid && TargetOwnerHandle)
			{
				Owner = TargetOwnerHandle;
			}
			else
			{
				if (OwnerPid != TargetPid)
				{
					bool known = false;
					size_t foreign_opened = 0;
					for (auto & CachedOwner : Owners)
					{
						if (CachedOwner.first == OwnerPid)
						{
							known = true;
							break;
						}
						if (CachedOwner.first != TargetPid)
						{
							++foreign_opened;
						}
					}

					if (!known && foreign_opened >= kMaxForeignOwners)
					{
						++BudgetSkipped;
						BudgetHit = true;
						return false;
					}
				}

				Owner = OpenOwnerCached(Owners, OwnerPid);
			}

			if (!Owner)
			{
				return false;
			}

			// Explicit-mask duplication is itself the rights proof: the kernel
			// refuses unless the donor carried at least the requested mask.
			HANDLE DuplicatedRaw = nullptr;
			if (!NtOk(Ntdll.NtDuplicateObject(Owner, SourceValue, GetCurrentProcess(),
				&DuplicatedRaw, DesiredAccess, 0, 0)) || !DuplicatedRaw)
			{
				++DupDenied;
				if (DuplicatedRaw)
				{
					CloseHandle(DuplicatedRaw);
				}

				return false;
			}

			// RAII from the moment of acquisition: every later exit - including
			// an exception thrown while recording the rejected object - closes
			// the duplicate instead of leaking it.
			UniqueHandle DuplicatedHandle(DuplicatedRaw);

			++Duplicated;
			const bool Ok = ThreadScan
				? VerifyThreadDonor(DuplicatedHandle.get(), TargetPid, TargetTid)
				: VerifyProcessDonor(DuplicatedHandle.get(), TargetPid);
			if (!Ok)
			{
				++VerifyRejected;
				if (Object)
				{
					// Same object = same underlying target; never re-dup it.
					WrongObjects.insert(ReCa<ULONG_PTR>(Object));
				}
				return false;
			}

			FoundDonorPid = OwnerPid;
			FoundGranted = DesiredAccess;
			FoundDonorHandle = static_cast<DWORD>(HandleValue);
			FoundNewHandle = PtrToUlong(DuplicatedHandle.get());
			Out = DuplicatedHandle.release();
			return true;
		};

		// Extract the raw table size and the type-matching candidates in one
		// walk (the raw snapshot stays untouched for calibration callers).
		struct Candidate
		{
			DWORD		OwnerPid;
			ULONG_PTR	HandleValue;
			PVOID		Object;
		};

		std::vector<Candidate> Candidates;
		size_t TotalCount = 0;

		if (Snapshot.Extended)
		{
			const auto * Info = ReCa<const SYSTEM_HANDLE_INFORMATION_EX_LOCAL *>(Snapshot.Buffer.data());
			const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles);
			size_t Count = static_cast<size_t>(Info->NumberOfHandles);
			const size_t Capacity = Header < Snapshot.Buffer.size()
				? (Snapshot.Buffer.size() - Header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL)
				: 0;
			if (Count > Capacity)
			{
				Count = Capacity;
			}

			TotalCount = Count;
			Candidates.reserve(Count);
			for (size_t Index = 0; Index < Count; ++Index)
			{
				const auto & Entry = Info->Handles[Index];
				if (HaveType && Entry.ObjectTypeIndex != WantedType)
				{
					continue;
				}

				Candidates.push_back(Candidate{ static_cast<DWORD>(Entry.UniqueProcessId), Entry.HandleValue, Entry.Object });
			}
		}
		else
		{
			const auto * Info = ReCa<const SYSTEM_HANDLE_INFORMATION_LEGACY *>(Snapshot.Buffer.data());
			const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_LEGACY, Handles);
			size_t Count = static_cast<size_t>(Info->NumberOfHandles);
			const size_t Capacity = Header < Snapshot.Buffer.size()
				? (Snapshot.Buffer.size() - Header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY)
				: 0;
			if (Count > Capacity)
			{
				Count = Capacity;
			}

			TotalCount = Count;
			Candidates.reserve(Count);
			for (size_t Index = 0; Index < Count; ++Index)
			{
				const auto & Entry = Info->Handles[Index];
				if (HaveType && static_cast<USHORT>(Entry.ObjectTypeIndex) != WantedType)
				{
					continue;
				}

				Candidates.push_back(Candidate{ static_cast<DWORD>(Entry.UniqueProcessId),
					static_cast<ULONG_PTR>(Entry.HandleValue), Entry.Object });
			}
		}

		// Raw table size, recorded before filtering.
		Detail.TotalHandles = static_cast<DWORD>(TotalCount);

		// Owner-first passes: 0 = target-owned entries (the real-world winner
		// almost always lives here - the target's own handle to itself), then
		// our own table, then foreign owners (bounded by the budgets). The
		// scan stops at the first verified hit.
		for (DWORD Pass = 0; Pass < 3 && !Out && !BudgetHit; ++Pass)
		{
			for (const auto & Entry : Candidates)
			{
				const bool is_target = Entry.OwnerPid == TargetPid;
				const bool is_self = Entry.OwnerPid == SelfPid;
				const bool belongs = Pass == 0 ? is_target
					: Pass == 1 ? (is_self && !is_target)
					: (!is_self && !is_target);
				if (!belongs)
				{
					continue;
				}

				if (Entry.Object && WrongObjects.find(ReCa<ULONG_PTR>(Entry.Object)) != WrongObjects.end())
				{
					continue;
				}

				++Examined;
				if (TryCandidate(Entry.OwnerPid, Entry.HandleValue, Entry.Object))
				{
					Detail.Examined = static_cast<DWORD>(Examined);
					Detail.DonorPid = FoundDonorPid;
					Detail.GrantedAccess = FoundGranted;
					Detail.DonorHandle = FoundDonorHandle;
					Detail.NewHandle = FoundNewHandle;
					Detail.OwnersOpened = static_cast<DWORD>(Owners.size());
					Detail.DupDenied = static_cast<DWORD>(DupDenied);
					Detail.VerifyRejected = static_cast<DWORD>(VerifyRejected);
					Detail.BudgetSkipped = static_cast<DWORD>(BudgetSkipped);
					Detail.Success = 1;
					Detail.FailCode = INJ_ERR_SUCCESS;
					return INJ_ERR_SUCCESS;
				}

				if (BudgetHit)
				{
					break;
				}
			}
		}

		LOG(1, "HandleAcq: no donor (examined %llu, duplicated %llu, filtered %d, budget_hit %d)\n",
			static_cast<unsigned long long>(Examined),
			static_cast<unsigned long long>(Duplicated),
			HaveType ? 1 : 0,
			BudgetHit ? 1 : 0);

		Detail.Examined = static_cast<DWORD>(Examined);
		Detail.OwnersOpened = static_cast<DWORD>(Owners.size());
		Detail.DupDenied = static_cast<DWORD>(DupDenied);
		Detail.VerifyRejected = static_cast<DWORD>(VerifyRejected);
		Detail.BudgetSkipped = static_cast<DWORD>(BudgetSkipped);
		Detail.Success = 0;
		Detail.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
		return INJ_ERR_HANDLE_HIJACK_FAILED;
	}

	DWORD HijackImpl(DWORD TargetPid, DWORD TargetTid, bool ThreadScan, DWORD DesiredAccess,
		HANDLE TargetOwnerHandle, HANDLE & Out, HijackStats * Detail)
	{
		Out = nullptr;

		HijackStats Local{ };
		Local.Attempted = 1;
		Local.Source = static_cast<DWORD>(HijackSource::Scan);

		const auto Finish = [&](DWORD Code) -> DWORD
		{
			if (!Local.Success)
			{
				Local.FailCode = Code;
			}

			if (Detail)
			{
				*Detail = Local;
			}

			return Code;
		};

		if (!TargetPid || !DesiredAccess || (ThreadScan && !TargetTid))
		{
			return Finish(INJ_ERR_HANDLE_HIJACK_FAILED);
		}

		NtdllHandles Ntdll{ };
		if (!ResolveNtdll(Ntdll))
		{
			return Finish(INJ_ERR_HANDLE_HIJACK_FAILED);
		}

		const DWORD SelfPid = GetCurrentProcessId();
		if (!ThreadScan && TargetPid == SelfPid)
		{
			return Finish(INJ_ERR_HANDLE_HIJACK_FAILED);
		}

		// Object-type indices are boot-stable: calibrate once per process
		// lifetime and reuse from the cache afterwards. The cache is read
		// first so the self-calibration handles below are opened only when a
		// calibration is actually needed.
		USHORT WantedType = (ThreadScan ? g_CachedThreadType : g_CachedProcessType).load(std::memory_order_acquire);
		bool HaveType = WantedType != 0;

		// Calibrators are opened BEFORE the single enumeration so they are
		// guaranteed to exist in it (a fresh Open* value cannot be found in
		// an older snapshot): one enumeration instead of two. SeDebugPrivilege
		// is intentionally NOT enabled here - the owner cache enables it
		// lazily on the first open failure, so the common path never touches
		// the token at all.
		UniqueHandle SelfProc;
		UniqueHandle SelfThread;
		if (!HaveType)
		{
			if (ThreadScan)
			{
				SelfThread.reset(OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId()));
			}
			else
			{
				SelfProc.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, SelfPid));
			}
		}

		EnumSnapshot Snap{ };
		NTSTATUS SnapStatus = 0;
		const DWORD SnapshotRet = QueryAnySnapshot(Ntdll, Snap, SnapStatus);
		if (SnapshotRet != INJ_ERR_SUCCESS)
		{
			Local.SnapStatus = static_cast<DWORD>(SnapStatus);
			return Finish(SnapshotRet);
		}

		Local.SnapStatus = static_cast<DWORD>(SnapStatus);

		if (!HaveType && !ThreadScan && SelfProc)
		{
			HaveType = FindOwnEntryType(Snap, SelfPid, ReCa<ULONG_PTR>(SelfProc.get()), WantedType);
		}
		else if (!HaveType && ThreadScan && SelfThread)
		{
			HaveType = FindOwnEntryType(Snap, SelfPid, ReCa<ULONG_PTR>(SelfThread.get()), WantedType);
		}

		if (HaveType)
		{
			(ThreadScan ? g_CachedThreadType : g_CachedProcessType).store(WantedType, std::memory_order_release);
		}
		else
		{
			LOG(1, "HandleAcq: type calibration failed, falling back to unfiltered scan\n");
		}

		Local.Calibrated = HaveType ? 1 : 0;

		const DWORD ScanRet = ScanSnapshot(Ntdll, Snap, SelfPid, TargetPid, TargetTid, ThreadScan, WantedType, HaveType, DesiredAccess, TargetOwnerHandle, Out, Local);
		if (Detail)
		{
			*Detail = Local;
		}

		return ScanRet;
	}
}

HijackStats g_ProcessHijackStats{ };
HijackStats g_ThreadHijackStats{ };

namespace
{
	// These two slots are written by the injection thread and read by the
	// UI/export thread with no other synchronization. A plain 80-byte struct
	// assignment is not atomic, so a concurrent reader races with it (C++ UB)
	// and can observe a half-updated record. Every field is a DWORD, so copy
	// field-by-field through InterlockedExchange - a compiler intrinsic on
	// x64, no new import - and load through InterlockedCompareExchange so no
	// read/write pair is a data race.
	void StoreHijackStats(HijackStats & Dst, const HijackStats & Src)
	{
		static_assert(sizeof(HijackStats) % sizeof(LONG) == 0, "HijackStats must be a whole number of LONGs");

		LONG * dst = ReCa<LONG *>(&Dst);
		const LONG * src = ReCa<const LONG *>(&Src);
		for (size_t i = 0; i < sizeof(HijackStats) / sizeof(LONG); ++i)
		{
			InterlockedExchange(&dst[i], src[i]);
		}
	}

	void LoadHijackStats(HijackStats & Src, HijackStats & Dst)
	{
		volatile LONG * src = ReCa<volatile LONG *>(&Src);
		LONG * dst = ReCa<LONG *>(&Dst);
		for (size_t i = 0; i < sizeof(HijackStats) / sizeof(LONG); ++i)
		{
			dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
		}
	}
}

	bool ValidateProcessDonorHandle(HANDLE Candidate, DWORD TargetPid, DWORD DesiredAccess)
	{
	if (!Candidate || Candidate == INVALID_HANDLE_VALUE || !TargetPid)
	{
		return false;
	}

	// Identity first: the handle must reference the requested process, and its
	// image name must be readable (that proves PROCESS_QUERY_LIMITED_INFORMATION).
	// Rights are proven by doing, never by NtQueryObject, which protected
	// targets filter.
	const DWORD ActualPid = GetProcessId(Candidate);
	if (ActualPid != TargetPid)
	{
		LOG(1, "ValidateSponsor: pid mismatch (actual=%lu want=%lu)\n", ActualPid, TargetPid);
		return false;
	}

	wchar_t Name[MAX_PATH * 2]{ 0 };
	DWORD Length = static_cast<DWORD>(sizeof(Name) / sizeof(Name[0]));
	if (!QueryFullProcessImageNameW(Candidate, 0, Name, &Length) || !Length)
	{
		LOG(1, "ValidateSponsor: name query failed (pid=%lu, err=%lu)\n", TargetPid, GetLastError());
		return false;
	}

	// Access: when the caller asks for VM_OPERATION, prove it with the existing
	// reserve/release probe. This is the conservative correct check - it
	// exercises a requested right directly (the injection path cannot run
	// without VM_OPERATION) using the lightest probe in this file. A full
	// alloc/write/read roundtrip is deliberately NOT done here: the call site
	// already enforces the full mask with an explicit-mask DuplicateHandle and
	// runs ProbeMemoryRoundtrip unless INJ_SKIP_SPONSOR_ROUNDTRIP is set, so
	// roundtripping unconditionally would duplicate that probe and reject
	// handles the path intentionally allows.
	if ((DesiredAccess & PROCESS_VM_OPERATION) && !ProbeVmOperation(Candidate))
	{
		return false;
	}

	return true;
}

// Full roundtrip on a single committed page: proves VM_OPERATION (alloc),
// VM_WRITE, VM_READ and QUERY_* together with zero lasting effect - the page
// is released before returning. Used for the sponsor dup only (per-candidate
// use inside the scan loop would churn the target's address space).
	bool ProbeMemoryRoundtrip(HANDLE Candidate)
	{
	void * Page = VirtualAllocEx(Candidate, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!Page)
	{
		LOG(1, "ProbeRoundtrip: alloc failed (%lu)\n", GetLastError());
		return false;
	}

	BYTE Written = 0xA5;
	BYTE Readout = 0;
	SIZE_T Done = 0;
	const bool Ok = WriteProcessMemory(Candidate, Page, &Written, sizeof(Written), &Done) && Done == sizeof(Written)
		&& ReadProcessMemory(Candidate, Page, &Readout, sizeof(Readout), &Done) && Done == sizeof(Readout)
		&& Readout == Written;

	bool released = false;
	for (int attempt = 0; attempt < 2; ++attempt)
	{
		if (VirtualFreeEx(Candidate, Page, 0, MEM_RELEASE))
		{
			released = true;
			break;
		}
	}
	if (!released)
	{
		LOG(1, "ProbeRoundtrip: release failed twice (%lu)\n", GetLastError());
		return false;
	}

	if (!Ok)
	{
		LOG(1, "ProbeRoundtrip: read/write mismatch\n");
	}

	return Ok;
}

void ResetHijackStats()
{
	StoreHijackStats(g_ProcessHijackStats, HijackStats{});
	StoreHijackStats(g_ThreadHijackStats, HijackStats{});
}

void RecordHijackOutcome(const HijackStats & Stats, bool IsThread)
{
	StoreHijackStats(IsThread ? g_ThreadHijackStats : g_ProcessHijackStats, Stats);
}

void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut)
{
#pragma EXPORT_FUNCTION("CoreAcqStats", __FUNCDNAME__)

	if (ProcessOut)
	{
		LoadHijackStats(g_ProcessHijackStats, *ProcessOut);
	}

	if (ThreadOut)
	{
		LoadHijackStats(g_ThreadHijackStats, *ThreadOut);
	}
}

DWORD HijackProcessHandle(DWORD TargetPid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail, HANDLE TargetOwnerHandle)
{
	DWORD Result = INJ_ERR_OUT_OF_MEMORY_NEW;
	try
	{
		Result = HijackImpl(TargetPid, 0, false, DesiredAccess, TargetOwnerHandle, OutHandle, Detail);
		if (Result == INJ_ERR_SUCCESS)
		{
			LOG(0, "HandleAcq: acquired process handle for PID %lu\n", TargetPid);
		}
	}
	catch (...)
	{
		OutHandle = nullptr;
		Result = INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	return Result;
}

DWORD HijackThreadHandle(DWORD TargetPid, DWORD TargetTid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail, HANDLE TargetOwnerHandle)
{
	DWORD Result = INJ_ERR_OUT_OF_MEMORY_NEW;
	try
	{
		Result = HijackImpl(TargetPid, TargetTid, true, DesiredAccess, TargetOwnerHandle, OutHandle, Detail);
		if (Result == INJ_ERR_SUCCESS)
		{
			LOG(0, "HandleAcq: acquired thread handle %lu in PID %lu\n", TargetTid, TargetPid);
		}
	}
	catch (...)
	{
		OutHandle = nullptr;
		Result = INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	return Result;
}
