#pragma once

#include <Windows.h>

#ifndef AMEGER_INJECTION_MODE_DEFINED
#define AMEGER_INJECTION_MODE_DEFINED
enum class INJECTION_MODE
{
	IM_ManualMap
};
#endif

#ifndef AMEGER_LAUNCH_METHOD_DEFINED
#define AMEGER_LAUNCH_METHOD_DEFINED
enum class LAUNCH_METHOD
{
	LM_HijackThread
};
#endif

// Handle-acquisition strategy flag (General group, shared by the public
// runtime header and the internal one; defined once here so every TU,
// runtime PCH or interface, sees the same value).
// Macros cannot be PascalCase - identifiers that the preprocessor owns
// (INJ_*, INJ_MM_*, SR_*, FILE_*) keep their existing screaming-caps form.
#define INJ_HANDLE_HIJACKING			0x0040

// Which path actually produced the working handle. The values are ordered by
// how "hijacked" the result is, so callers can rank results with a plain
// comparison (Sponsor > Scan > Direct) instead of an ad-hoc switch.
enum class HijackSource : DWORD
{
	Direct = 0,  // direct OpenProcess / OpenThread (not a hijack)
	Scan = 1,    // duplicated a qualifying handle owned by a foreign process
	Sponsor = 2  // reused the cooperating pre-open held by the injector
};

// Full record of the last handle-acquisition attempt, one slot per handle kind
// (process / thread). Pure DWORD layout so it can cross the DLL boundary and be
// consumed by the interface (see GetLastHijackStats). All fields are DWORD
// unsigned values, so the same PascalCase rules apply as elsewhere.
struct HijackStats
{
	// Outcome
	DWORD Attempted = 0;      // 1 when a hijack path was entered
	DWORD Success = 0;        // 1 when a handle was acquired
	DWORD Source = static_cast<DWORD>(HijackSource::Direct);
	DWORD FailCode = 0;       // injector error code when Success == 0

	// Provenance: which process owned the handle, which value was taken,
	// which value we ended up with, and what rights it carries.
	DWORD DonorPid = 0;       // owner of the source handle
	DWORD DonorHandle = 0;    // source handle value inside the donor
	DWORD NewHandle = 0;      // duplicated value inside our own process
	DWORD GrantedAccess = 0;  // mask the acquired handle actually carries

	// Foreign-donor scan accounting
	DWORD TotalHandles = 0;     // raw table entries before filtering
	DWORD Examined = 0;         // entries that passed the type filter
	DWORD Duplicated = 0;       // successful duplications
	DWORD DupDenied = 0;        // duplications refused (donor lacked rights)
	DWORD VerifyRejected = 0;   // dups that failed functional verification
	DWORD OwnersOpened = 0;     // distinct donor processes opened (failures included)
	DWORD Calibrated = 0;       // 1 when the object-type index self-calibrated
	DWORD SnapStatus = 0;       // NTSTATUS of the enumeration (0 = fine or N/A)
	DWORD BudgetSkipped = 0;    // candidates skipped by the owner/dup-attempt budgets

	// Sponsor pre-open accounting (process handle; threads are pre-opened by
	// the interface too and recorded here when the sponsor thread is used)
	DWORD SponsorState = 0;      // 0 = absent, 1 = present but invalid, 2 = used
	DWORD SponsorValidated = 0;  // identity + name query passed
	DWORD SponsorProbed = 0;     // full alloc/write/read/release roundtrip passed
};

static_assert(sizeof(HijackStats) == 80);

// What the thread-hijack shell did to the victim thread, recorded in the target
// and read back by the host (see GetLastThreadExecStats).
//
// The host used to print "Thread context restored automatically" as a fixed
// string with nothing behind it: it asserted a restore that may never have
// happened, and said nothing about which thread was used or whether the saved
// context was actually reinstated.
struct THREAD_EXEC_STATS
{
	DWORD Attempted = 0;        // 1 when the thread-hijack path was entered
	DWORD Success = 0;          // 1 when the thread is back on its own code
	DWORD HijackedTid = 0;      // thread that was hijacked
	DWORD ContextSaved = 0;     // 1 when the original CONTEXT was captured
	DWORD ContextRestored = 0;  // 1 when it was reinstated
	DWORD Resumed = 0;          // 1 when the thread was resumed afterwards
	DWORD SuspendCount = 0;     // ResumeThread return at the end: 0 = was suspended
	DWORD FailCode = 0;         // injector error code when Success == 0
	// How the RIP was put back. The normal path watches the thread until RIP
	// lands outside the hijack code page; the abort/timeout paths relocate the
	// saved RIP only after observing the stub frame unwound (RSP back at the
	// captured baseline) or the thread already left the code page. Reporting
	// both as "restored" without this distinction would blur a direct
	// observation with a frame-validated forced restore.
	DWORD RestoreMode = 0;      // 1 = verified (RIP observed outside), 2 = forced (frame-validated)
	DWORD Reserved = 0;
};

static_assert(sizeof(THREAD_EXEC_STATS) == 40);

// What the manual-map shell actually cleaned from the mapped image, recorded by
// the shell in the target and read back by the host after the shell returns.
// This is the only way to report the post-cleanup state, because the PE header
// (which holds the data directories) is erased before the interface inspects
// the target.
//   CleanedMask - bit i set => data directory i was non-zero and got zeroed.
//   *Size       - the pre-cleanup size of that directory (0 = was absent).
//   ExportSize reuses the former Reserved slot: export names ("ManualEntry"
//   style) are the last plaintext strings in a mapped image, so the shell
//   wipes the export directory exactly like the import ones.
struct MAP_STATS
{
	DWORD CleanedMask = 0;
	DWORD ImportSize = 0;
	DWORD DelayImportSize = 0;
	DWORD DebugSize = 0;
	DWORD RelocSize = 0;
	DWORD TlsSize = 0;
	DWORD ExportSize = 0;
};

static_assert(sizeof(MAP_STATS) == 28);

// What the string tiers actually did at import-resolve time, recorded by the
// runtime in the target and read back by the host (see GetLastStringStats).
//
// The host used to print hardcoded claims here ("30+ symbols", "22 hook names",
// "5 tiers"), which asserted things it had no way of observing. These counters
// are the measured values behind those lines, so the host reports facts.
struct STRING_STATS
{
	DWORD SymbolsDeclared = 0;  // encrypted NT names the runtime declares
	DWORD SymbolsResolved = 0;  // of those, successfully resolved at runtime
	DWORD HookNamesBuilt = 0;   // hook names built from ciphertext
	DWORD TiersTotal = 0;       // tiers covered by the round-trip self-test
	DWORD TiersPassed = 0;      // of those, that round-tripped correctly
	DWORD Reported = 0;         // 1 once the runtime has filled this in
	DWORD Reserved = 0;
};

static_assert(sizeof(STRING_STATS) == 28);
