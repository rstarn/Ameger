#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

// KernelCloak string suite, faithfully replicated for usermode.
//
// Source: ck0i/Kernelcloak (MIT), strings/{encrypted_string,
// encrypted_wstring, stack_string, layered_string}.h + crypto XTEA core.
// Key schedules, keystream formulas, Fisher-Yates shuffle, XTEA-32 rounds,
// and the lambda + static-constexpr + make_decrypted deduction pattern are
// copied exactly; only the kernel dependencies are adapted away. Layout:
// suite entry point lives in KcStrings/Core/, one tier per sibling header
// next to it (KcNarrow/KcWide/KcStack/KcLayered.h).
//
// Deliberate deltas from upstream (all documented, none silent):
//  1. No config.h / KC_ENABLE_* gates: always on. Gates would fork the
//     Configuration.ini behavior matrix; usermode has no IRQL-gated paths
//     that need compile-time removal.
//  2. No WDK: std::index_sequence instead of kernelcloak::detail::
//     index_sequence, <cstdint>/<cstddef> instead of core/types.h,
//     __forceinline directly instead of KC_FORCEINLINE.
//  3. Wipe-on-destruction added to every decrypted temporary. Upstream
//     leaves stack plaintext after use; usermode crash dumps make that
//     strictly worse, so every dtor volatile-zeroes its buffer.
//  4. No layered re-key holder (InterlockedIncrement + __rdtsc thread
//     machinery). Our longest-lived secrets are heap-copied once at load;
//     re-keying buys nothing there and adds a concurrency surface.
//  5. Wide layered strings added (KC ships narrow-only). Our highest-value
//     static secret, the symbol-server URL, is wide, so the triple layer
//     operates byte-wise over the UTF-16 encoding.
//
// Usage rules (violations broke the build before; see KcStack.h dispatch):
//  - Single-expression temporaries only: GetProcAddress(h, KC_STR("x"))
//  - Named hoisted form for anything else: KC_STR_DECL(name, "...")
//  - Static tables must NEVER store .c_str() from a temporary; heap-copy
//    once (see hook-table handling).
//  - KC_STACK_* / DECL macros are statements, never call arguments.
#include "../KcNarrow.h"
#include "../KcWide.h"
#include "../KcStack.h"
#include "../KcLayered.h"

namespace kc_strings
{
// Number of tiers KcStringsSelfTest round-trips, and the only place that number
// is defined. On failure the self-test returns the 1-based index of the tier
// that broke, so the passing count is derivable without a second tally:
// 0 => all passed, n => tiers 1..n-1 passed.
inline constexpr unsigned KcTierCount = 5;

__forceinline constexpr unsigned KcTiersPassed(unsigned self_test_result) noexcept
{
	return self_test_result == 0 ? KcTierCount : self_test_result - 1;
}

// Round-trip self-test over every tier. Host-side only: runs once at
// import-resolve time, prints through the standard LOG process (same
// print-callback pipeline as every other module; muted by QuietPrint in
// production). Returns INJ-style 0 on success, tier index otherwise.
// Test literals are single common chars, also present in hex tables.
inline unsigned KcStringsSelfTest() noexcept
{
	{
		auto probe = KC_STR("Kc");
		const char * text = probe.c_str();
		if (text[0] != 'K' || text[1] != 'c' || text[2] != 0)
		{
			return 1;
		}
	}

	{
		auto probe = KC_WSTR(L"Kc");
		const wchar_t * text = probe.c_str();
		if (text[0] != L'K' || text[1] != L'c' || text[2] != 0)
		{
			return 2;
		}
	}

	{
		// Direct arity (not the COUNT dispatch): deterministic under every
		// preprocessor while still exercising key derivation + Decode.
		char buf[3];
		const char ref[3] = { 'K', 'c', 0 };
		constexpr auto stack_key = KC_STACK_KEY_;
		KC_SC_3(buf, stack_key, 'K', 'c', '\0');
		if (std::memcmp(buf, ref, sizeof(buf)) != 0)
		{
			return 3;
		}
		volatile char * wipe = buf;
		for (std::size_t i = 0; i < sizeof(buf); ++i)
		{
			wipe[i] = 0;
		}
	}

	{
		auto probe = KC_STR_LAYERED("Kc9");
		const char * text = probe.c_str();
		if (text[0] != 'K' || text[1] != 'c' || text[2] != '9' || text[3] != 0)
		{
			return 4;
		}
	}

	{
		auto probe = KC_WSTR_LAYERED(L"Kc9");
		const wchar_t * text = probe.c_str();
		if (text[0] != L'K' || text[1] != L'c' || text[2] != L'9' || text[3] != 0)
		{
			return 5;
		}
	}

	return 0;
}
} // namespace kc_strings
