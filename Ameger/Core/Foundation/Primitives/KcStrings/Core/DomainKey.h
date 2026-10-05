#pragma once

#include <cstddef>
#include <cstdint>
#include <intrin.h>

// Anti-constant-folding layer shared by every string tier.
//
// Why: a decrypt that is a pure XOR over a compile-time-constant key is itself
// a compile-time constant expression. MSVC /O2 evaluates it and emits the
// PLAINTEXT into .rdata, which defeats the whole suite. Measured, not
// theorised: 28 of 31 ntdll symbol names sat in the shipped runtime DLL as
// plaintext, pooled in source order by the string-literal optimiser.
//
// Fix: the decrypt output is masked with a per-call key derived from rdtsc,
// then unmasked. The two passes cancel, so caller-visible semantics are
// unchanged, but the plaintext is no longer a value the compiler can know at
// compile time and so can never reach the image. Correctness no longer depends
// on the optimiser declining to emulate the cipher.
//
// THE VOLATILE READ IS THE ACTUAL MECHANISM, and getting it wrong fails
// silently. A first attempt held the key in a plain local and routed the two
// passes through a staged buffer; that still leaked every name, because SROA
// promotes the buffer to registers and the optimiser then cancels
// `(c ^ k ^ d) ^ d` to `c ^ k` and constant-folds. Keying off a volatile member
// is what forces each pass to re-read and forbids assuming the two reads agree.
// A compiler that caches or CSEs these reads reintroduces the leak silently, so
// the gate in Interface/Source/Main.cpp is the backstop.
namespace kc_strings
{
namespace detail
{
__forceinline std::uint8_t DomainByte(std::uint32_t key, std::size_t idx) noexcept
{
    // Index-dependent so the mask is not one uniform dword, which would make
    // the two passes even more attractive to simplify.
    return static_cast<std::uint8_t>((key >> ((idx % 4) * 8)) ^ (idx * 0xC2B2AE35u));
}

class DomainMask
{
    volatile std::uint32_t m_key;

    __forceinline std::uint32_t Compute() noexcept
    {
        // rdtsc is opaque to the optimiser: it cannot constant-fold it, which
        // is what makes the construction work at all. Taken once per decrypt.
        const std::uint64_t ticks = __rdtsc();

        // Mix in this frame's address so a hoisted or replayed tick value
        // cannot serve as a stable key across call sites.
        std::uint32_t k = static_cast<std::uint32_t>(ticks ^ (ticks >> 32));
        k ^= static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&ticks));
        k *= 0x85EBCA6Bu;
        k ^= k >> 13;
        return k;
    }

public:
    __forceinline DomainMask() noexcept : m_key(Compute()) {}

    __forceinline std::uint8_t Byte(std::size_t idx) const noexcept
    {
        return DomainByte(m_key, idx);
    }
};

template <typename CharT, std::size_t N>
__forceinline void Wipe(CharT * p) noexcept
{
    volatile CharT * v = p;
    for (std::size_t i = 0; i < N; ++i)
    {
        v[i] = static_cast<CharT>(0);
    }
}
} // namespace detail
} // namespace kc_strings
