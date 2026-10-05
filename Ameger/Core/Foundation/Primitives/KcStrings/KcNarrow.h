#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "Core/DomainKey.h"

// Single-layer narrow strings: KernelCloak encrypted_string.h replica.
// See Core/KcStrSuite.h for the usage rules and the usermode deltas.
namespace kc_strings
{
template <std::size_t N, std::uint32_t Key>
class KcEncryptedString
{
	std::uint8_t m_encrypted[N]{};

	static constexpr std::uint8_t EncryptByte(char c, std::size_t idx) noexcept
	{
		const std::uint8_t k = static_cast<std::uint8_t>((Key >> ((idx % 4) * 8)) ^ (idx * 0x9E3779B9u));
		return static_cast<std::uint8_t>(c) ^ k;
	}

public:
	template <std::size_t... Is>
	constexpr KcEncryptedString(const char(&str)[N], std::index_sequence<Is...>) noexcept
		: m_encrypted{ EncryptByte(str[Is], Is)... }
	{
	}

	__forceinline void Decrypt(char * out) const noexcept
	{
		const kc_strings::detail::DomainMask mask;

		std::uint8_t staged[N];
		for (std::size_t i = 0; i < N; ++i)
		{
			const std::uint8_t k = static_cast<std::uint8_t>((Key >> ((i % 4) * 8)) ^ (i * 0x9E3779B9u));
			staged[i] = static_cast<std::uint8_t>(m_encrypted[i] ^ k ^ mask.Byte(i));
		}

		for (std::size_t i = 0; i < N; ++i)
		{
			out[i] = static_cast<char>(staged[i] ^ mask.Byte(i));
		}

		kc_strings::detail::Wipe<std::uint8_t, N>(staged);
	}

	static constexpr std::size_t length() noexcept
	{
		return N - 1;
	}
};

template <std::size_t N, std::uint32_t Key>
class KcDecryptedString
{
	char m_buf[N];

	KcDecryptedString(const KcDecryptedString &) = delete;
	KcDecryptedString & operator=(const KcDecryptedString &) = delete;

public:
	explicit KcDecryptedString(const KcEncryptedString<N, Key> & enc) noexcept
	{
		enc.Decrypt(m_buf);
	}

	~KcDecryptedString() noexcept
	{
		volatile char * p = m_buf;
		for (std::size_t i = 0; i < N; ++i)
		{
			p[i] = 0;
		}
	}

	__forceinline operator const char *() const noexcept
	{
		return m_buf;
	}

	__forceinline const char * c_str() const noexcept
	{
		return m_buf;
	}
};

template <std::size_t N, std::uint32_t Key>
__forceinline KcDecryptedString<N, Key> KcMakeDecrypted(const KcEncryptedString<N, Key> & enc) noexcept
{
	return KcDecryptedString<N, Key>(enc);
}
} // namespace kc_strings

#define KC_STR(s) ::kc_strings::KcMakeDecrypted([]() -> const auto & { constexpr std::uint32_t kc_k = static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ sizeof(s) * 0xCC9E2D51u ^ ::kc_strings::detail::kStringSeed); static constexpr ::kc_strings::KcEncryptedString<sizeof(s), kc_k> kc_e(s, std::make_index_sequence<sizeof(s)>{}); return kc_e; }())

#define KC_STR_DECL_IMPL_(name, s, key) static constexpr ::kc_strings::KcEncryptedString<sizeof(s), key> kc_enc_##name(s, std::make_index_sequence<sizeof(s)>{}); auto name = ::kc_strings::KcMakeDecrypted(kc_enc_##name)
#define KC_STR_DECL(name, s) KC_STR_DECL_IMPL_(name, s, static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ sizeof(s) * 0xCC9E2D51u ^ ::kc_strings::detail::kStringSeed))

#define KC_STR_N(s) KC_STR(s)
