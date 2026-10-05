#pragma once

#include <Windows.h>

#include <type_traits>
#include <utility>

class UniqueHandle
{
	HANDLE m_Handle = nullptr;

public:
	UniqueHandle() = default;

	explicit UniqueHandle(HANDLE handle) : m_Handle(handle)
	{
	}

	UniqueHandle(const UniqueHandle &) = delete;
	UniqueHandle & operator=(const UniqueHandle &) = delete;

	UniqueHandle(UniqueHandle && other) noexcept : m_Handle(other.m_Handle)
	{
		other.m_Handle = nullptr;
	}

	UniqueHandle & operator=(UniqueHandle && other) noexcept
	{
		if (this != &other)
		{
			reset();
			m_Handle = other.m_Handle;
			other.m_Handle = nullptr;
		}

		return *this;
	}

	~UniqueHandle()
	{
		reset();
	}

	void reset(HANDLE handle = nullptr)
	{
		if (m_Handle && m_Handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_Handle);
		}

		m_Handle = handle;
	}

	HANDLE get() const
	{
		return m_Handle;
	}

	HANDLE release()
	{
		HANDLE handle = m_Handle;
		m_Handle = nullptr;
		return handle;
	}

	explicit operator bool() const
	{
		return m_Handle != nullptr && m_Handle != INVALID_HANDLE_VALUE;
	}

	operator HANDLE() const
	{
		return m_Handle;
	}
};

class RemoteAllocation
{
	// Failed remote releases in this process (see reset/free_failed).
	inline static unsigned long g_RemoteFreeFailures = 0;

	HANDLE m_Process = nullptr;
	void * m_Address = nullptr;

public:
	RemoteAllocation() = default;

	RemoteAllocation(HANDLE process, void * address) : m_Process(process), m_Address(address)
	{
	}

	RemoteAllocation(const RemoteAllocation &) = delete;
	RemoteAllocation & operator=(const RemoteAllocation &) = delete;

	RemoteAllocation(RemoteAllocation && other) noexcept : m_Process(other.m_Process), m_Address(other.m_Address)
	{
		other.m_Process = nullptr;
		other.m_Address = nullptr;
	}

	RemoteAllocation & operator=(RemoteAllocation && other) noexcept
	{
		if (this != &other)
		{
			reset();
			m_Process = other.m_Process;
			m_Address = other.m_Address;
			other.m_Process = nullptr;
			other.m_Address = nullptr;
		}

		return *this;
	}

	~RemoteAllocation()
	{
		reset();
	}

	void reset(HANDLE process = nullptr, void * address = nullptr)
	{
		if (m_Process && m_Process != INVALID_HANDLE_VALUE && m_Address)
		{
			// Counted, not ignored: a failed VirtualFreeEx leaves a remote
			// region mapped in the target forever, and the caller has no other
			// way to learn about it. Surfaced through free_failed().
			if (!VirtualFreeEx(m_Process, m_Address, 0, MEM_RELEASE))
			{
				++g_RemoteFreeFailures;
			}
		}

		m_Process = process;
		m_Address = address;
	}

	// Number of remote regions this process failed to release. Diagnostic only
	// (the guard has no channel back to the host), but it keeps the loss
	// observable in a debugger instead of silently discarded.
	inline static unsigned long & free_failed()
	{
		return g_RemoteFreeFailures;
	}

	void * get() const
	{
		return m_Address;
	}

	void release()
	{
		m_Process = nullptr;
		m_Address = nullptr;
	}
};

template<typename Callback>
class ScopeExit
{
	Callback m_Callback;
	bool m_Active = true;

public:
	explicit ScopeExit(Callback callback) : m_Callback(std::move(callback))
	{
		static_assert(std::is_nothrow_invocable_v<Callback &>, "ScopeExit callback must be noexcept");
	}

	ScopeExit(const ScopeExit &) = delete;
	ScopeExit & operator=(const ScopeExit &) = delete;

	~ScopeExit()
	{
		if (m_Active)
		{
			m_Callback();
		}
	}

	void dismiss()
	{
		m_Active = false;
	}
};

template<typename Callback>
ScopeExit<Callback> MakeScopeExit(Callback callback)
{
	return ScopeExit<Callback>(std::move(callback));
}
