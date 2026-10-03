#pragma once

// VMProtect SDK Ultra markers for host-side hot paths (x64 Release only).
//
// Enabled with AMEGER_ENABLE_VMP_MARKERS (runtime vcxproj sets it unless
// /p:AmegerVmpMarkers=0; SDK from $(AmegerVmpSdk)/%AMEGER_VMP_SDK%). Disabled
// -> zero-cost no-ops, so unprotected builds (AMEGER_SKIP_VMP=1) and machines
// without the SDK behave identically (SDK header is never included).
//
// Coverage (single Begin..End range per function; early returns inside the
// range stay covered, so no per-return End is needed):
//   HijackImpl      (System/Handle/HandleHijack.cpp)      "hdl_scan"
//   SR_HijackThread (Execution/ThreadHijacking.cpp)        "sr_hijack"
//   ResolveImports  (System/Import/ImportHandler.cpp)      "imp_resolve"
//   ManualMap       (Injection/ManualMapping/ManualMapping.cpp) "mm_core"
//
// NEVER annotate remote-executed code: ManualMapping_Shell, MMI_*, MMIH_*
// (.mmap_sec$*), RemoteThreadHijack.asm.
// Those bytes are memcpy'd into the target and run there WITHOUT the
// VMProtect VM runtime - a marker inside them would crash the target.
//
// ALSO do not annotate an EXPORTED function: CompileVmp -AutoProcedures
// already emits one Ultra/100 procedure per export name, so a marker would
// place two protection regions on one address and VMProtect aborts the build
// with 'Address is already used by function "<name>"' (observed on
// StartDownload). Apply AMEGER_VMP_NOINLINE to every marked function for the
// same class of reason: an inlined helper's marker lands inside its caller.
//
// Marker tags are short neutral labels: they land in .rdata as-is, so no
// inject/hijack Loader-style keywords that aid signature scans.
#ifdef AMEGER_ENABLE_VMP_MARKERS
#include "VMProtectSDK.h"
#define AMEGER_VMP_ULTRA_BEGIN(tag) VMProtectBeginUltra(tag)
#define AMEGER_VMP_ULTRA_END() VMProtectEnd()
// A marked function must own a distinct address. Small helpers (GetOSVersion,
// IsNativeProcess, the ProcessInformation accessors, ...) are otherwise
// inlined INTO their callers - the marker then lands inside the caller and
// VMProtect rejects the build: 'Address is already used by function X'
// (observed with tl_osver vs the InitializeRuntime export). noinline keeps
// one marker per real function. Only applied when markers are on, so
// unprotected builds keep full inlining.
#define AMEGER_VMP_NOINLINE __declspec(noinline)
#else
#define AMEGER_VMP_ULTRA_BEGIN(tag) ((void)0)
#define AMEGER_VMP_ULTRA_END() ((void)0)
#define AMEGER_VMP_NOINLINE
#endif
