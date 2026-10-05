#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "Core/DomainKey.h"

// Triple-layer strings: KernelCloak layered_string.h replica (XOR +
// XTEA-32 + Fisher-Yates shuffle, six keys per site). Wide layered has no
// KC upstream equivalent; it applies the identical construction byte-wise
// over the UTF-16 encoding so the XTEA block structure is preserved.
// See Core/KcStrSuite.h for the usage rules and the usermode deltas.
namespace kc_strings
{
namespace detail
{
	constexpr std::uint32_t kXteaDelta = 0x9E3779B9u;
	constexpr std::size_t kXteaRounds = 32;

	constexpr void XteaBlockEncrypt(std::uint8_t * block, const std::uint32_t tk[4]) noexcept
	{
		std::uint32_t v0 = static_cast<std::uint32_t>(block[0])
			| (static_cast<std::uint32_t>(block[1]) << 8)
			| (static_cast<std::uint32_t>(block[2]) << 16)
			| (static_cast<std::uint32_t>(block[3]) << 24);
		std::uint32_t v1 = static_cast<std::uint32_t>(block[4])
			| (static_cast<std::uint32_t>(block[5]) << 8)
			| (static_cast<std::uint32_t>(block[6]) << 16)
			| (static_cast<std::uint32_t>(block[7]) << 24);

		std::uint32_t sum = 0;
		for (std::size_t r = 0; r < kXteaRounds; ++r)
		{
			v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + tk[sum & 3]);
			sum += kXteaDelta;
			v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + tk[(sum >> 11) & 3]);
		}

		block[0] = static_cast<std::uint8_t>(v0);
		block[1] = static_cast<std::uint8_t>(v0 >> 8);
		block[2] = static_cast<std::uint8_t>(v0 >> 16);
		block[3] = static_cast<std::uint8_t>(v0 >> 24);
		block[4] = static_cast<std::uint8_t>(v1);
		block[5] = static_cast<std::uint8_t>(v1 >> 8);
		block[6] = static_cast<std::uint8_t>(v1 >> 16);
		block[7] = static_cast<std::uint8_t>(v1 >> 24);
	}

	constexpr void XteaBlockDecrypt(std::uint8_t * block, const std::uint32_t tk[4]) noexcept
	{
		std::uint32_t v0 = static_cast<std::uint32_t>(block[0])
			| (static_cast<std::uint32_t>(block[1]) << 8)
			| (static_cast<std::uint32_t>(block[2]) << 16)
			| (static_cast<std::uint32_t>(block[3]) << 24);
		std::uint32_t v1 = static_cast<std::uint32_t>(block[4])
			| (static_cast<std::uint32_t>(block[5]) << 8)
			| (static_cast<std::uint32_t>(block[6]) << 16)
			| (static_cast<std::uint32_t>(block[7]) << 24);

		std::uint32_t sum = kXteaDelta * static_cast<std::uint32_t>(kXteaRounds);
		for (std::size_t r = 0; r < kXteaRounds; ++r)
		{
			v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + tk[(sum >> 11) & 3]);
			sum -= kXteaDelta;
			v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + tk[sum & 3]);
		}

		block[0] = static_cast<std::uint8_t>(v0);
		block[1] = static_cast<std::uint8_t>(v0 >> 8);
		block[2] = static_cast<std::uint8_t>(v0 >> 16);
		block[3] = static_cast<std::uint8_t>(v0 >> 24);
		block[4] = static_cast<std::uint8_t>(v1);
		block[5] = static_cast<std::uint8_t>(v1 >> 8);
		block[6] = static_cast<std::uint8_t>(v1 >> 16);
		block[7] = static_cast<std::uint8_t>(v1 >> 24);
	}

	constexpr std::uint8_t LayerXorKey(std::uint32_t keyA, std::size_t idx) noexcept
	{
		return static_cast<std::uint8_t>((keyA >> ((idx % 4) * 8)) ^ (idx * 0x9E3779B9u));
	}

	template <std::size_t N, std::uint32_t Seed>
	struct BytePermutation
	{
		std::size_t Forward[N]{};
		std::size_t Inverse[N]{};

		constexpr BytePermutation() noexcept : Forward{}, Inverse{}
		{
			for (std::size_t i = 0; i < N; ++i)
			{
				Forward[i] = i;
			}

			std::uint32_t state = Seed;
			for (std::size_t i = N - 1; i > 0; --i)
			{
				state = state * 0x41C64E6Du + 0x3039u;
				const std::size_t j = (state >> 16) % (i + 1);
				const std::size_t tmp = Forward[i];
				Forward[i] = Forward[j];
				Forward[j] = tmp;
			}

			for (std::size_t i = 0; i < N; ++i)
			{
				Inverse[Forward[i]] = i;
			}
		}
	};
}

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
class KcLayeredString
{
	static constexpr std::size_t kPadded = ((N + 7) / 8) * 8;

	std::uint8_t m_data[kPadded]{};
	static constexpr detail::BytePermutation<kPadded, ShuffleSeed> s_perm{};

public:
	template <std::size_t... Is>
	constexpr KcLayeredString(const char(&str)[N], std::index_sequence<Is...>) noexcept
		: m_data{}
	{
		const std::uint8_t src[] = { static_cast<std::uint8_t>(str[Is])... };
		std::uint8_t buf[kPadded]{};
		for (std::size_t i = 0; i < N; ++i)
		{
			buf[i] = src[i];
		}

		for (std::size_t i = 0; i < kPadded; ++i)
		{
			buf[i] ^= detail::LayerXorKey(KeyA, i);
		}

		const std::uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
		for (std::size_t blk = 0; blk < kPadded; blk += 8)
		{
			detail::XteaBlockEncrypt(buf + blk, tk);
		}

		for (std::size_t i = 0; i < kPadded; ++i)
		{
			m_data[s_perm.Forward[i]] = buf[i];
		}
	}

	__forceinline void Decrypt(char * out) const noexcept
	{
		std::uint8_t buf[kPadded];
		for (std::size_t i = 0; i < kPadded; ++i)
		{
			buf[s_perm.Inverse[i]] = m_data[i];
		}

		const std::uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
		for (std::size_t blk = 0; blk < kPadded; blk += 8)
		{
			detail::XteaBlockDecrypt(buf + blk, tk);
		}

		const detail::DomainMask mask;

		char staged[N];
		for (std::size_t i = 0; i < N; ++i)
		{
			staged[i] = static_cast<char>(buf[i] ^ detail::LayerXorKey(KeyA, i))
				^ static_cast<char>(mask.Byte(i));
		}

		for (std::size_t i = 0; i < N; ++i)
		{
			out[i] = static_cast<char>(staged[i] ^ static_cast<char>(mask.Byte(i)));
		}

		detail::Wipe<char, N>(staged);
	}

	static constexpr std::size_t length() noexcept
	{
		return N - 1;
	}
};

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
class KcDecryptedLayered
{
	char m_buf[N];

	KcDecryptedLayered(const KcDecryptedLayered &) = delete;
	KcDecryptedLayered & operator=(const KcDecryptedLayered &) = delete;

public:
	explicit KcDecryptedLayered(const KcLayeredString<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> & enc) noexcept
	{
		enc.Decrypt(m_buf);
	}

	~KcDecryptedLayered() noexcept
	{
		volatile char * p = m_buf;
		for (std::size_t i = 0; i < N; ++i)
		{
			p[i] = 0;
		}
	}

	__forceinline const char * c_str() const noexcept
	{
		return m_buf;
	}
};

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
__forceinline KcDecryptedLayered<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> KcMakeLayered(const KcLayeredString<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> & enc) noexcept
{
	return KcDecryptedLayered<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed>(enc);
}

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
class KcLayeredWString
{
	static constexpr std::size_t kBytes = N * sizeof(wchar_t);
	static constexpr std::size_t kPadded = ((kBytes + 7) / 8) * 8;

	std::uint8_t m_data[kPadded]{};
	static constexpr detail::BytePermutation<kPadded, ShuffleSeed> s_perm{};

public:
	template <std::size_t... Is>
	constexpr KcLayeredWString(const wchar_t(&str)[N], std::index_sequence<Is...>) noexcept
		: m_data{}
	{
		const std::uint16_t src[] = { static_cast<std::uint16_t>(str[Is])... };
		std::uint8_t buf[kPadded]{};
		for (std::size_t i = 0; i < N; ++i)
		{
			buf[i * 2] = static_cast<std::uint8_t>(src[i] & 0xFFu);
			buf[i * 2 + 1] = static_cast<std::uint8_t>((src[i] >> 8) & 0xFFu);
		}

		for (std::size_t i = 0; i < kPadded; ++i)
		{
			buf[i] ^= detail::LayerXorKey(KeyA, i);
		}

		const std::uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
		for (std::size_t blk = 0; blk < kPadded; blk += 8)
		{
			detail::XteaBlockEncrypt(buf + blk, tk);
		}

		for (std::size_t i = 0; i < kPadded; ++i)
		{
			m_data[s_perm.Forward[i]] = buf[i];
		}
	}

	__forceinline void Decrypt(wchar_t * out) const noexcept
	{
		std::uint8_t buf[kPadded];
		for (std::size_t i = 0; i < kPadded; ++i)
		{
			buf[s_perm.Inverse[i]] = m_data[i];
		}

		const std::uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
		for (std::size_t blk = 0; blk < kPadded; blk += 8)
		{
			detail::XteaBlockDecrypt(buf + blk, tk);
		}

		const detail::DomainMask mask;

		wchar_t staged[N];
		for (std::size_t i = 0; i < N; ++i)
		{
			const std::uint16_t lo = static_cast<std::uint16_t>(buf[i * 2] ^ detail::LayerXorKey(KeyA, i * 2));
			const std::uint16_t hi = static_cast<std::uint16_t>(buf[i * 2 + 1] ^ detail::LayerXorKey(KeyA, i * 2 + 1));
			staged[i] = static_cast<wchar_t>(lo | (hi << 8))
				^ static_cast<wchar_t>(mask.Byte(i));
		}

		for (std::size_t i = 0; i < N; ++i)
		{
			out[i] = static_cast<wchar_t>(staged[i] ^ static_cast<wchar_t>(mask.Byte(i)));
		}

		detail::Wipe<wchar_t, N>(staged);
	}

	static constexpr std::size_t length() noexcept
	{
		return N - 1;
	}
};

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
class KcDecryptedLayeredW
{
	wchar_t m_buf[N];

	KcDecryptedLayeredW(const KcDecryptedLayeredW &) = delete;
	KcDecryptedLayeredW & operator=(const KcDecryptedLayeredW &) = delete;

public:
	explicit KcDecryptedLayeredW(const KcLayeredWString<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> & enc) noexcept
	{
		enc.Decrypt(m_buf);
	}

	~KcDecryptedLayeredW() noexcept
	{
		volatile wchar_t * p = m_buf;
		for (std::size_t i = 0; i < N; ++i)
		{
			p[i] = 0;
		}
	}

	__forceinline const wchar_t * c_str() const noexcept
	{
		return m_buf;
	}
};

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
__forceinline KcDecryptedLayeredW<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> KcMakeLayeredW(const KcLayeredWString<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> & enc) noexcept
{
	return KcDecryptedLayeredW<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed>(enc);
}
} // namespace kc_strings

#define KC_STR_LAYERED(s) ::kc_strings::KcMakeLayered([]() -> const auto & { constexpr std::uint32_t kc_cnt = static_cast<std::uint32_t>(__COUNTER__); constexpr std::uint32_t kc_ln = static_cast<std::uint32_t>(__LINE__); constexpr std::uint32_t kc_sd = ::kc_strings::detail::kStringSeed; constexpr std::uint32_t kc_ka = ((kc_cnt + 1) * 0x45D9F3Bu ^ kc_ln * 0x1B873593u) ^ kc_sd; constexpr std::uint32_t kc_kb0 = ((kc_cnt + 2) * 0xCC9E2D51u ^ kc_ln * 0x85EBCA6Bu) ^ kc_sd; constexpr std::uint32_t kc_kb1 = ((kc_cnt + 3) * 0xC2B2AE35u ^ kc_ln * 0x27D4EB2Du) ^ kc_sd; constexpr std::uint32_t kc_kb2 = ((kc_cnt + 4) * 0x165667B1u ^ kc_ln * 0xE6546B64u) ^ kc_sd; constexpr std::uint32_t kc_kb3 = ((kc_cnt + 5) * 0x9E3779B9u ^ kc_ln * 0x41C64E6Du) ^ kc_sd; constexpr std::uint32_t kc_sh = ((kc_cnt + 6) * 0x6C62272Eu ^ kc_ln * 0xBEA6E8C5u) ^ kc_sd; static constexpr ::kc_strings::KcLayeredString<sizeof(s), kc_ka, kc_kb0, kc_kb1, kc_kb2, kc_kb3, kc_sh> kc_e(s, std::make_index_sequence<sizeof(s)>{}); return kc_e; }())

#define KC_WSTR_LAYERED(s) ::kc_strings::KcMakeLayeredW([]() -> const auto & { constexpr std::size_t kc_n = sizeof(s) / sizeof(wchar_t); constexpr std::uint32_t kc_cnt = static_cast<std::uint32_t>(__COUNTER__); constexpr std::uint32_t kc_ln = static_cast<std::uint32_t>(__LINE__); constexpr std::uint32_t kc_sd = ::kc_strings::detail::kStringSeed; constexpr std::uint32_t kc_ka = ((kc_cnt + 1) * 0x45D9F3Bu ^ kc_ln * 0x1B873593u) ^ kc_sd; constexpr std::uint32_t kc_kb0 = ((kc_cnt + 2) * 0xCC9E2D51u ^ kc_ln * 0x85EBCA6Bu) ^ kc_sd; constexpr std::uint32_t kc_kb1 = ((kc_cnt + 3) * 0xC2B2AE35u ^ kc_ln * 0x27D4EB2Du) ^ kc_sd; constexpr std::uint32_t kc_kb2 = ((kc_cnt + 4) * 0x165667B1u ^ kc_ln * 0xE6546B64u) ^ kc_sd; constexpr std::uint32_t kc_kb3 = ((kc_cnt + 5) * 0x9E3779B9u ^ kc_ln * 0x41C64E6Du) ^ kc_sd; constexpr std::uint32_t kc_sh = ((kc_cnt + 6) * 0x6C62272Eu ^ kc_ln * 0xBEA6E8C5u) ^ kc_sd; static constexpr ::kc_strings::KcLayeredWString<kc_n, kc_ka, kc_kb0, kc_kb1, kc_kb2, kc_kb3, kc_sh> kc_e(s, std::make_index_sequence<kc_n>{}); return kc_e; }())
