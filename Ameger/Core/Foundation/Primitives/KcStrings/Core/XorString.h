#pragma once

#include <cstddef>
#include <utility>

#include "DomainKey.h"

// Compile-time XOR strings: literals are encrypted at compile time via
// constexpr template metaprogramming, decrypted to a stack buffer at the
// point of use, and wiped on scope exit. Disk and .rdata hold ciphertext
// only; plaintext exists transiently on the stack.
//
// TWO independent mechanisms are required, and both were arrived at by
// measurement after the first attempt silently failed:
//
// 1. The encryption must happen inside a CONSTANT EXPRESSION that produces
//    `static constexpr` storage. A runtime constructor that loops over the
//    literal leaves the literal alive as its initializer source, and /O2 folds
//    the loop into a copy of it, emitting the plaintext to .rdata. This is why
//    the tier uses `static constexpr ... kc_enc(s, make_index_sequence<...>)`
//    exactly like the KC tiers: the literal is consumed and never referenced
//    again, so only ciphertext is ever emitted.
// 2. The decrypt must not be a pure function of compile-time constants. The
//    mask/unmask pair in Core/DomainKey.h cancels, so the optimiser can
//    otherwise prove `Buf[i] = Data[i] ^ ks` and fold that to plaintext. The
//    volatile rdtsc read is what forbids the proof. See the note in
//    Core/DomainKey.h about the volatile read being the load-bearing part.
//
// Dropping either one reintroduces plaintext in .rdata with no build error and
// no test failure, so the gate in Interface/Source/Main.cpp is the backstop.
//
// Literals only: the constructor binds to `const CharT(&)[N]`, so passing
// a pointer fails to compile instead of encrypting pointer bytes.
// Temporaries live through the full expression, so the single-expression
// form is safe for loader calls:
//   GetProcAddress(h, XOR_STR_A("NtClose").get())
// Static tables must NOT store `.get()` from a temporary (dangling).
// Build heap-owned copies once instead (see hook table handling).
namespace xor_string
{
	constexpr unsigned kGolden = 0x9E3779B1u;
	constexpr unsigned kBaseKey = 0xA53A5A5Du;

	template <typename CharT, size_t N, unsigned Key>
	struct XorEncrypted
	{
		static_assert(N > 1, "Empty string");

		CharT Data[N]{};

		static constexpr CharT EncryptByte(CharT c, std::size_t idx) noexcept
		{
			const unsigned ks = Key + static_cast<unsigned>(idx) * kGolden;
			return static_cast<CharT>(c ^ static_cast<CharT>(ks));
		}

		// index_sequence pack expansion so this is a genuine constant
		// expression; a plain loop body would require a runtime ctor and
		// reopen the literal as a live initializer (see note 1 above).
		template <size_t... Is>
		constexpr XorEncrypted(const CharT(&s)[N], std::index_sequence<Is...>) noexcept
			: Data{ EncryptByte(s[Is], Is)... }
		{
		}
	};

	template <typename CharT, size_t N, unsigned Key>
	class XorDecrypted
	{
		CharT Buf[N];

		XorDecrypted(const XorDecrypted &) = delete;
		XorDecrypted & operator=(const XorDecrypted &) = delete;

	public:
		__forceinline explicit XorDecrypted(const XorEncrypted<CharT, N, Key> & enc) noexcept
		{
			const kc_strings::detail::DomainMask mask;

			CharT staged[N];
			for (size_t i = 0; i < N; ++i)
			{
				const unsigned ks = Key + static_cast<unsigned>(i) * kGolden;
				staged[i] = static_cast<CharT>(enc.Data[i] ^ static_cast<CharT>(ks)
					^ static_cast<CharT>(mask.Byte(i)));
			}

			for (size_t i = 0; i < N; ++i)
			{
				Buf[i] = static_cast<CharT>(staged[i] ^ static_cast<CharT>(mask.Byte(i)));
			}

			kc_strings::detail::Wipe<CharT, N>(staged);
		}

		~XorDecrypted() noexcept
		{
			volatile CharT * p = Buf;
			for (size_t i = 0; i < N; ++i)
			{
				p[i] = static_cast<CharT>(0);
			}
		}

		__forceinline const CharT * get() const noexcept
		{
			return Buf;
		}
	};
}

// __COUNTER__ expands once as the IMPL argument, then the shared value
// feeds both template keys. N counts elements (null included), so the
// same form serves narrow and wide literals.
//
// The lambda returns a reference to a function-local `static constexpr`
// ciphertext blob. The literal is referenced only inside that constant
// expression, which is what keeps it out of the emitted image.
#define XOR_STR_A_IMPL(s, c)                                                                                          \
	::xor_string::XorDecrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))>( \
		[]() -> const ::xor_string::XorEncrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> & { \
			static constexpr ::xor_string::XorEncrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> kc_enc( \
				s, std::make_index_sequence<(sizeof(s) / sizeof((s)[0]))> {});                                              \
			return kc_enc;                                                                                             \
		}())
#define XOR_STR_A(s) XOR_STR_A_IMPL(s, __COUNTER__)

#define XOR_STR_W_IMPL(s, c)                                                                                          \
	::xor_string::XorDecrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))>( \
		[]() -> const ::xor_string::XorEncrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> & { \
			static constexpr ::xor_string::XorEncrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> kc_enc( \
				s, std::make_index_sequence<(sizeof(s) / sizeof((s)[0]))> {});                                              \
			return kc_enc;                                                                                             \
		}())
#define XOR_STR_W(s) XOR_STR_W_IMPL(s, __COUNTER__)
