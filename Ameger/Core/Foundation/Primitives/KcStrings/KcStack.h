#pragma once

#include <cstddef>
#include <cstdint>

#include "Core/DomainKey.h"

// Char-by-char stack strings: KernelCloak stack_string.h replica.
// No literal of any kind reaches the binary: each character is a template
// parameter, XORed at compile time, decoded through a volatile so the
// compiler cannot fold it back to a constant. Max 20 characters.
//
// NOTE vs upstream: Decode() casts explicitly through int so the shed
// /W4 /WX build stays clean (C4244). Semantics unchanged.
namespace kc_strings
{
template <typename CharT, CharT C, std::uint32_t Key, std::size_t Idx>
struct KcObfuscatedChar
{
	static constexpr CharT KeyByte() noexcept
	{
		return static_cast<CharT>((Key >> ((Idx % 4) * 8)) ^ (Idx * 0x27D4EB2Du));
	}

	static constexpr CharT Encrypted = static_cast<CharT>(C ^ KeyByte());

	__forceinline static CharT Decode() noexcept
	{
		volatile CharT enc = Encrypted;
		return static_cast<CharT>(static_cast<int>(enc) ^ static_cast<int>(KeyByte()));
	}
};
} // namespace kc_strings

#define KC_STACK_KEY_ (static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ 0xDEADBEEFu ^ ::kc_strings::detail::kStringSeed))

#define KC_SC_(name, key, idx, c) name[idx] = ::kc_strings::KcObfuscatedChar<char, c, key, idx>::Decode()
#define KC_SWC_(name, key, idx, c) name[idx] = ::kc_strings::KcObfuscatedChar<wchar_t, c, key, idx>::Decode()

#define KC_SC_1(n, k, c0) KC_SC_(n,k,0,c0)
#define KC_SC_2(n, k, c0, c1) KC_SC_1(n,k,c0); KC_SC_(n,k,1,c1)
#define KC_SC_3(n, k, c0, c1, c2) KC_SC_2(n,k,c0,c1); KC_SC_(n,k,2,c2)
#define KC_SC_4(n, k, c0, c1, c2, c3) KC_SC_3(n,k,c0,c1,c2); KC_SC_(n,k,3,c3)
#define KC_SC_5(n, k, c0, c1, c2, c3, c4) KC_SC_4(n,k,c0,c1,c2,c3); KC_SC_(n,k,4,c4)
#define KC_SC_6(n, k, c0, c1, c2, c3, c4, c5) KC_SC_5(n,k,c0,c1,c2,c3,c4); KC_SC_(n,k,5,c5)
#define KC_SC_7(n, k, c0, c1, c2, c3, c4, c5, c6) KC_SC_6(n,k,c0,c1,c2,c3,c4,c5); KC_SC_(n,k,6,c6)
#define KC_SC_8(n, k, c0, c1, c2, c3, c4, c5, c6, c7) KC_SC_7(n,k,c0,c1,c2,c3,c4,c5,c6); KC_SC_(n,k,7,c7)
#define KC_SC_9(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8) KC_SC_8(n,k,c0,c1,c2,c3,c4,c5,c6,c7); KC_SC_(n,k,8,c8)
#define KC_SC_10(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) KC_SC_9(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8); KC_SC_(n,k,9,c9)
#define KC_SC_11(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) KC_SC_10(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9); KC_SC_(n,k,10,c10)
#define KC_SC_12(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) KC_SC_11(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10); KC_SC_(n,k,11,c11)
#define KC_SC_13(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) KC_SC_12(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11); KC_SC_(n,k,12,c12)
#define KC_SC_14(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) KC_SC_13(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12); KC_SC_(n,k,13,c13)
#define KC_SC_15(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) KC_SC_14(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13); KC_SC_(n,k,14,c14)
#define KC_SC_16(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15) KC_SC_15(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14); KC_SC_(n,k,15,c15)
#define KC_SC_17(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16) KC_SC_16(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15); KC_SC_(n,k,16,c16)
#define KC_SC_18(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17) KC_SC_17(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16); KC_SC_(n,k,17,c17)
#define KC_SC_19(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18) KC_SC_18(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17); KC_SC_(n,k,18,c18)
#define KC_SC_20(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19) KC_SC_19(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18); KC_SC_(n,k,19,c19)

#define KC_SWC_1(n, k, c0) KC_SWC_(n,k,0,c0)
#define KC_SWC_2(n, k, c0, c1) KC_SWC_1(n,k,c0); KC_SWC_(n,k,1,c1)
#define KC_SWC_3(n, k, c0, c1, c2) KC_SWC_2(n,k,c0,c1); KC_SWC_(n,k,2,c2)
#define KC_SWC_4(n, k, c0, c1, c2, c3) KC_SWC_3(n,k,c0,c1,c2); KC_SWC_(n,k,3,c3)
#define KC_SWC_5(n, k, c0, c1, c2, c3, c4) KC_SWC_4(n,k,c0,c1,c2,c3); KC_SWC_(n,k,4,c4)
#define KC_SWC_6(n, k, c0, c1, c2, c3, c4, c5) KC_SWC_5(n,k,c0,c1,c2,c3,c4); KC_SWC_(n,k,5,c5)
#define KC_SWC_7(n, k, c0, c1, c2, c3, c4, c5, c6) KC_SWC_6(n,k,c0,c1,c2,c3,c4,c5); KC_SWC_(n,k,6,c6)
#define KC_SWC_8(n, k, c0, c1, c2, c3, c4, c5, c6, c7) KC_SWC_7(n,k,c0,c1,c2,c3,c4,c5,c6); KC_SWC_(n,k,7,c7)
#define KC_SWC_9(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8) KC_SWC_8(n,k,c0,c1,c2,c3,c4,c5,c6,c7); KC_SWC_(n,k,8,c8)
#define KC_SWC_10(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) KC_SWC_9(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8); KC_SWC_(n,k,9,c9)
#define KC_SWC_11(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) KC_SWC_10(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9); KC_SWC_(n,k,10,c10)
#define KC_SWC_12(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) KC_SWC_11(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10); KC_SWC_(n,k,11,c11)
#define KC_SWC_13(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) KC_SWC_12(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11); KC_SWC_(n,k,12,c12)
#define KC_SWC_14(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) KC_SWC_13(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12); KC_SWC_(n,k,13,c13)
#define KC_SWC_15(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) KC_SWC_14(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13); KC_SWC_(n,k,14,c14)
#define KC_SWC_16(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15) KC_SWC_15(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14); KC_SWC_(n,k,15,c15)
#define KC_SWC_17(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16) KC_SWC_16(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15); KC_SWC_(n,k,16,c16)
#define KC_SWC_18(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17) KC_SWC_17(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16); KC_SWC_(n,k,17,c17)
#define KC_SWC_19(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18) KC_SWC_18(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17); KC_SWC_(n,k,18,c18)
#define KC_SWC_20(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19) KC_SWC_19(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18); KC_SWC_(n,k,19,c19)
