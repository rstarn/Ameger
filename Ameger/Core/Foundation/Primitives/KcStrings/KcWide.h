#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "Core/DomainKey.h"

// Single-layer wide strings: KernelCloak encrypted_wstring.h replica.
// See Core/KcStrSuite.h for the usage rules and the usermode deltas.
namespace kc_strings
{
template <std::size_t N, std::uint32_t Key>
class KcEncryptedWString
{
	std::uint16_t m_encrypted[N]{};

	static constexpr std::uint16_t EncryptWchar(wchar_t c, std::size_t idx) noexcept
	{
		const std::uint32_t derived = Key ^ static_cast<std::uint32_t>(idx * 0x9E3779B9u);
		const std::uint16_t k = static_cast<std::uint16_t>(derived ^ (derived >> 16));
		return static_cast<std::uint16_t>(c) ^ k;
	}

public:
	template <std::size_t... Is>
	constexpr KcEncryptedWString(const wchar_t(&str)[N], std::index_sequence<Is...>) noexcept
		: m_encrypted{ EncryptWchar(str[Is], Is)... }
	{
	}

	__forceinline void Decrypt(wchar_t * out) const noexcept
	{
		const kc_strings::detail::DomainMask mask;

		std::uint16_t staged[N];
		for (std::size_t i = 0; i < N; ++i)
		{
			const std::uint32_t derived = Key ^ static_cast<std::uint32_t>(i * 0x9E3779B9u);
			const std::uint16_t k = static_cast<std::uint16_t>(derived ^ (derived >> 16));
			staged[i] = static_cast<std::uint16_t>(m_encrypted[i] ^ k
				^ static_cast<std::uint16_t>(mask.Byte(i)));
		}

		for (std::size_t i = 0; i < N; ++i)
		{
			out[i] = static_cast<wchar_t>(staged[i] ^ static_cast<std::uint16_t>(mask.Byte(i)));
		}

		kc_strings::detail::Wipe<std::uint16_t, N>(staged);
	}

	static constexpr std::size_t length() noexcept
	{
		return N - 1;
	}
};

template <std::size_t N, std::uint32_t Key>
class KcDecryptedWString
{
	wchar_t m_buf[N];

	KcDecryptedWString(const KcDecryptedWString &) = delete;
	KcDecryptedWString & operator=(const KcDecryptedWString &) = delete;

public:
	explicit KcDecryptedWString(const KcEncryptedWString<N, Key> & enc) noexcept
	{
		enc.Decrypt(m_buf);
	}

	~KcDecryptedWString() noexcept
	{
		volatile wchar_t * p = m_buf;
		for (std::size_t i = 0; i < N; ++i)
		{
			p[i] = 0;
		}
	}

	__forceinline operator const wchar_t *() const noexcept
	{
		return m_buf;
	}

	__forceinline const wchar_t * c_str() const noexcept
	{
		return m_buf;
	}
};

template <std::size_t N, std::uint32_t Key>
__forceinline KcDecryptedWString<N, Key> KcMakeDecryptedW(const KcEncryptedWString<N, Key> & enc) noexcept
{
	return KcDecryptedWString<N, Key>(enc);
}
} // namespace kc_strings

#define KC_WSTR(s) ::kc_strings::KcMakeDecryptedW([]() -> const auto & { constexpr std::size_t kc_n = sizeof(s) / sizeof(wchar_t); constexpr std::uint32_t kc_k = static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ kc_n * 0xCC9E2D51u ^ ::kc_strings::detail::kStringSeed); static constexpr ::kc_strings::KcEncryptedWString<kc_n, kc_k> kc_e(s, std::make_index_sequence<kc_n>{}); return kc_e; }())

#define KC_WSTR_DECL_IMPL_(name, s, wlen, key) static constexpr ::kc_strings::KcEncryptedWString<wlen, key> kc_wenc_##name(s, std::make_index_sequence<wlen>{}); auto name = ::kc_strings::KcMakeDecryptedW(kc_wenc_##name)
#define KC_WSTR_DECL(name, s) KC_WSTR_DECL_IMPL_(name, s, sizeof(s) / sizeof(wchar_t), static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ (sizeof(s) / sizeof(wchar_t)) * 0xCC9E2D51u ^ ::kc_strings::detail::kStringSeed))
