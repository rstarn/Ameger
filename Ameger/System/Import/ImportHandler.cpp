#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "System/Import/ImportHandler.h"
#include "System/Symbol/Offsets/DynamicOffsets.h"

#include <utility>

using namespace NATIVE;

namespace
{
	// Bind-only wrapper for an encrypted symbol name. The constructor is
	// constrained to holders exposing c_str(), so a raw string literal has no
	// viable overload and fails to compile rather than silently reintroducing
	// a plaintext .rdata entry. This is the whole point: the previous
	// `const char *` parameter accepted a bare literal, and one call site
	// (LdrpInvertedFunctionTables) used exactly that.
	class encrypted_symbol_name
	{
		const char * m_name;

	public:
		template <typename Holder, typename = decltype(std::declval<const Holder &>().c_str())>
		explicit encrypted_symbol_name(const Holder & holder) noexcept : m_name(holder.c_str()) {}

		const char * c_str() const noexcept { return m_name; }
	};
}

// Symbol names go through the layered tier (XOR + XTEA + shuffle, six keys per
// site) rather than the single-tier XOR, which /O2 constant-folds back to
// plaintext - see KcStrings/Core/DomainKey.h. The temporary lives through the
// LoadSymbolNative call; the callee uses it synchronously. Debug LOG inside
// prints the transient plaintext only when a print callback is attached.
#define S_FUNC(f) NATIVE::f, encrypted_symbol_name(KC_STR_LAYERED(#f))

// Same, for the symbols whose export name differs from the variable name.
#define S_FUNC_AS(f, sym) NATIVE::f, encrypted_symbol_name(KC_STR_LAYERED(sym))

// Measured string-suite counters, handed to the interface via
// GetLastStringStats. The host used to print hardcoded numbers here; these are
// the values behind them, counted at the only place a native name is built.
static STRING_STATS g_string_stats{};

// CountDeclaration is false only for the retry half of the
// LdrpInvertedFunctionTable plural/singular fallback (see ResolveImports):
// the two spellings name one logical symbol, so the pair must count once.
// Every other call site takes the default and counts its own symbol.
template <typename T>
DWORD LoadSymbolNative(T & Function, const encrypted_symbol_name & name, bool CountDeclaration = true)
{
	if (CountDeclaration)
	{
		// Attempted is bumped before the lookup, so a hard failure still shows
		// the host how far resolution got instead of reporting a bare zero.
		++g_string_stats.SymbolsDeclared;

		// The name is materialised from ciphertext for this call only and dies
		// with it; nothing keeps a static table of decoded names alive. Count it
		// here, before the lookup can fail: HookNamesBuilt means "hook names
		// built from ciphertext", not "symbols resolved" (that is SymbolsResolved).
		++g_string_stats.HookNamesBuilt;
	}

	DWORD RVA = 0;
	DWORD sym_ret = sym_parser.GetSymbolAddress(name.c_str(), RVA);

	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG(1, "Failed to load native function: %s\n", name.c_str());

		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	Function = ReCa<T>(ReCa<UINT_PTR>(g_hNTDLL) + RVA);

	++g_string_stats.SymbolsResolved;

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports(ERROR_DATA & error_data)
{
	LOG(1, "ResolveImports called\n");

	DWORD err = ERROR_SUCCESS;
	if (!GetOSVersion(&err))
	{
		INIT_ERROR_DATA(error_data, err);

		LOG(1, "Failed to determine Windows version\n");

		return INJ_ERR_WINDOWS_VERSION;
	}

	
	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		INIT_ERROR_DATA(error_data, static_cast<DWORD>(GetOSBuildVersion()));

		LOG(1, "Unsupported Windows build: %u\n", GetOSBuildVersion());

		return INJ_ERR_WINDOWS_BUILD_UNSUPPORTED;
	}

	auto ntdll_name = XOR_STR_W(L"ntdll.dll");
	g_hNTDLL	= GetModuleHandle(ntdll_name.get());
	if (!g_hNTDLL)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetModuleHandle failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_GET_MODULE_HANDLE_FAIL;
	}

	// No literal module name here: an instrumented build's LOG format strings
	// land in .rdata as plaintext and are caught by the interface's
	// string-encryption gate. The name itself is already known from the line
	// above.
	LOG(1, "native OS module    loaded at %p\n", g_hNTDLL);
	LOG(1, "OSVersion = %lu\nOSBuildVersion = %lu\n", GetOSVersion(), GetOSBuildVersion());

	auto k32_name = XOR_STR_W(L"kernel32.dll");
	HINSTANCE hK32 = GetModuleHandle(k32_name.get());
	if (!hK32)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetModuleHandle failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_KERNEL32_MISSING;
	}

	WIN32_FUNC_INIT(GetModuleHandleW, hK32);

	WIN32_FUNC_INIT(GetProcAddress, hK32);

	WIN32_FUNC_INIT(GetLastError, hK32);

	if (!NATIVE::pGetModuleHandleW || !NATIVE::pGetProcAddress || !NATIVE::pGetLastError)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetProcAddress failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	LOG(1, "Waiting for native symbol parser to finish initialization\n");

	while (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		if (WaitForSingleObject(g_hInterruptImport, 10) == WAIT_OBJECT_0)
		{
			return INJ_ERR_IMPORT_INTERRUPT;
		}
	}
	
	DWORD sym_ret = sym_ntdll_native_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "Native symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_LOAD_FAIL;
	}

	sym_ret = sym_parser.Initialize(&sym_ntdll_native);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "Native symbol parsing failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_PARSE_FAIL;
	}

	// The PDB is now mapped and the parser is live. Every early return below
	// (the LoadSymbolNative failures in particular) must release the DbgHelp
	// module, delete the cached PDB, and carry a real AdvErrorCode instead of
	// a zero indistinguishable from success. ScopeExit covers all paths; the
	// specific codes set by the dynamic-offset and self-test paths are kept,
	// and the success path dismisses this guard and tears down explicitly.
	auto pdb_guard = MakeScopeExit([&]() noexcept {
		sym_ntdll_native.Cleanup();
		sym_parser.Cleanup();
		sym_ntdll_native.PurgePdb();

		if (error_data.AdvErrorCode == INJ_ERR_ADVANCED_NOT_DEFINED)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_GET_SYMBOL_ADDRESS_FAILED);
		}
	});

	LOG(1, "Start loading native OS symbols\n");

	if (LoadSymbolNative(S_FUNC(LdrUnloadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrGetProcedureAddress)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(memmove)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED; 
	if (LoadSymbolNative(S_FUNC(RtlZeroMemory)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlAllocateHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlFreeHeap)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlAnsiStringToUnicodeString)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtClose)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtAllocateVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtFreeVirtualMemory)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtProtectVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlInsertInvertedFunctionTable)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpHandleTlsData)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrLockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrUnlockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtDelayExecution)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrpHeap)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpTlsList)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	
	
	// LdrpInvertedFunctionTable was renamed to the plural
	// LdrpInvertedFunctionTables in 22H2+. The build hint picks the try-order,
	// but both names are attempted so a backport / future rename does not
	// hard-fail the entire import resolve on a single symbol.
	{
		const bool prefer_plural = GetOSBuildVersion() >= g_Windows11_22H2;
		DWORD table_ret = INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (prefer_plural)
		{
			table_ret = LoadSymbolNative(S_FUNC_AS(LdrpInvertedFunctionTable, "LdrpInvertedFunctionTables"));
			if (table_ret != INJ_ERR_SUCCESS)
			{
				LOG(1, "Plural entry missing, trying singular\n");
				// Same declared symbol under its other spelling: count it
				// once. Counting the retry again made SymbolsResolved <
				// SymbolsDeclared on a fully successful resolve, which the
				// interface printed as (import PARTIAL).
				table_ret = LoadSymbolNative(S_FUNC(LdrpInvertedFunctionTable), false);
			}
		}
		else
		{
			table_ret = LoadSymbolNative(S_FUNC(LdrpInvertedFunctionTable));
			if (table_ret != INJ_ERR_SUCCESS)
			{
				LOG(1, "Singular entry missing, trying plural\n");
				table_ret = LoadSymbolNative(S_FUNC_AS(LdrpInvertedFunctionTable, "LdrpInvertedFunctionTables"), false);
			}
		}
		if (table_ret != INJ_ERR_SUCCESS)
		{
			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		}
	}

	
	if (LoadSymbolNative(S_FUNC(LdrProtectMrdata)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpLoadDllInternal)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpDereferenceModule)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlAddFunctionTable)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	// Optional, best-effort: MMI_CleanUp uses it to undo RtlAddFunctionTable
	// after a failed attempt. A build whose ntdll does not expose it must
	// still inject, so the result is deliberately ignored - the field stays
	// null and cleanup skips the delete rather than failing the injection.
	LoadSymbolNative(S_FUNC(RtlDeleteFunctionTable));

	// Every Windows struct offset is now resolved from the downloaded PDB
	// while it is still mapped (sym_parser holds the DbgHelp table).
	// Fail-closed: a future layout without a known PDB field must refuse to
	// inject rather than fall back to a stale 0x17EE / 0x330 / LDR guess.
	{
		const DWORD dyno_ret = ResolveDynamicOffsets();
		if (dyno_ret != SYMBOL_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, dyno_ret);

			LOG(1, "Dynamic OS offsets failed: %08X\n", dyno_ret);

			// pdb_guard releases the mapped table and deletes the cached PDB.
			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		}
	}

	// Success: the failure guard is no longer needed; tear down explicitly so
	// the unmap happens before the string self-test and the purge before the
	// run continues (the order the comments below describe).
	pdb_guard.dismiss();

	sym_ntdll_native.Cleanup();

	LOG(1, "Native OS symbols loaded\n");

	sym_parser.Cleanup();

	// Every symbol has been resolved and the PDB is unmapped, so the cached
	// file is now pure on-disk evidence. Remove it before the run continues;
	// the cost is a re-download on the next run, which is the right trade for
	// not leaving a multi-megabyte ntdll.pdb behind.
	sym_ntdll_native.PurgePdb();

	// String-suite round-trip proof, same LOG print process as every other
	// module (muted by QuietPrint in production). Fail closed: broken
	// string crypto would silently corrupt loader lookups.
	const unsigned kc_test = kc_strings::KcStringsSelfTest();
	LOG(1, "KcStrings self-test: %08X\n", kc_test);
	g_string_stats.TiersTotal = kc_strings::KcTierCount;
	g_string_stats.TiersPassed = kc_strings::KcTiersPassed(kc_test);
	if (kc_test != 0)
	{
		INIT_ERROR_DATA(error_data, kc_test);

		LOG(1, "KcStrings self-test failed: %08X\n", kc_test);

		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	g_string_stats.Reported = 1;
	g_LibraryState = true;

	return INJ_ERR_SUCCESS;
}

void __stdcall GetLastStringStats(STRING_STATS * Out)
{
#pragma EXPORT_FUNCTION("CoreStrStats", __FUNCDNAME__)

	if (Out)
	{
		*Out = g_string_stats;
	}
}