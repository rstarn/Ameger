#pragma once

#include <Windows.h>

#include "Core/Foundation/Error.h"
#include "Core/Foundation/Primitives/InjectionTypes.h"

// Handle hijacking: duplicate a usable handle to the target process/thread
// owned by another process instead of calling OpenProcess/OpenThread on the
// target directly (which is the most-hooked telemetry point).
//
// Acquisition order used by the runtime when INJ_HANDLE_HIJACKING is set:
//   1. Sponsor handle (hHandleValue): a cooperating process - normally the
//      injector itself, which runs this DLL in-process - pre-opens the target
//      and passes the value in. Zero enumeration noise, always "found" when
//      the pre-open itself succeeded. This is the reliable path on targets
//      (PPL / Ob-callback-stripped, e.g. Overwatch under EAC) where no
//      foreign donor with full rights exists.
//   2. Foreign-donor scan (SystemExtendedHandleInformation): duplicates a
//      qualifying handle owned by an unrelated process.
//   3. Direct OpenProcess/OpenThread fallback - only when the caller allows
//      it (INJ_NO_DIRECT_FALLBACK makes failures close instead).
//
// Scan shape (stealth):
//   - Candidate passes run owner-first: target-owned entries, then our own
//     table, then foreign owners. Real-world winners are almost always
//     target-owned, so the scan terminates in single-digit duplications
//     instead of hammering the whole system handle table.
//   - The object-type index is self-calibrated from one of our own handles
//     and cached for the boot; exactly ONE enumeration is taken per scan
//     (calibrator handles are opened before it, so they are guaranteed to be
//     present in it).
//   - Foreign owner opens are capped (kMaxForeignOwners), total duplicate
//     attempts are capped (kMaxDupAttempts), owners are negatively cached,
//     and objects already proven to be the wrong target are remembered -
//     skipped candidates are counted in HijackStats::BudgetSkipped.
//   - SeDebugPrivilege is enabled lazily, only after an owner open fails.
//
// Why naive scans find nothing:
//  1. Wrong info class (SystemProcessInformation instead of
//     SystemExtendedHandleInformation). This module uses class 64 with
//     fallback to class 16.
//  2. Truncated PIDs/handles (legacy WORD struct). This module uses the
//     extended ULONG_PTR layout.
//  3. Hardcoded object-type indices (vary per boot). This module
//     self-calibrates indices from its own known handles per enumeration.
//  4. Missing SeDebugPrivilege (cannot open donor SYSTEM processes for
//     duplication). This module enables it lazily, on first owner-open failure.
//  5. NtQueryObject-based rights checks (filtered on protected targets, so
//     every donor fails). This module never queries rights metadata: rights
//     are proven functionally - dup-with-explicit-mask success, name query,
//     reserve/release, and (sponsor only) a commit/write/read/release
//     roundtrip with zero lasting effect.
//
// The last attempt per kind (process / thread) is recorded in HijackStats and
// can be retrieved in-process via GetLastHijackStats for UI display. The
// runtime DLL runs inside the injector process, so the interface queries it
// directly with GetProcAddress (tolerating absence on older DLLs).

// Returns INJ_ERR_SUCCESS with a valid *OutHandle on success, or
// INJ_ERR_HANDLE_HIJACK_FAILED with *OutHandle = nullptr when no donor
// qualifies. When Detail is provided it receives scan counters (examined /
// duplicated) and, on success, the donor PID and granted mask. Never throws.
// TargetOwnerHandle (optional): an already-open handle to the target that
// carries PROCESS_DUP_HANDLE; target-owned entries are duplicated from it
// instead of opening the target again.
DWORD HijackProcessHandle(DWORD TargetPid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail = nullptr, HANDLE TargetOwnerHandle = nullptr);

DWORD HijackThreadHandle(DWORD TargetPid, DWORD TargetTid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail = nullptr, HANDLE TargetOwnerHandle = nullptr);

// Validates a caller-owned (sponsor) handle by identity (PID + name query).
// Rights are proven by duplication itself plus ProbeMemoryRoundtrip - never
// by NtQueryObject, which protected targets filter. Used for hHandleValue.
bool ValidateProcessDonorHandle(HANDLE Candidate, DWORD TargetPid, DWORD DesiredAccess);

// Single committed-page roundtrip (alloc/write/read/release): proves the
// full injection mask on one handle with zero lasting effect. Sponsor path
// only; per-candidate use inside scans would churn the target.
bool ProbeMemoryRoundtrip(HANDLE Candidate);

// Snapshot helpers for OpenTargetProcess-style callers.
void RecordHijackOutcome(const HijackStats & Stats, bool IsThread);
void GetProcessHijackStats(HijackStats & Out);
void GetThreadHijackStats(HijackStats & Out);

// Exported for the interface (see GetLastHijackStats in Injection.h).
void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut);
