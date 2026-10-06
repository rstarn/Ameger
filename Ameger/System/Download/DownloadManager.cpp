#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Download/DownloadManager.h"

#include <process.h>

// Free-function trampoline for the watchdog thread. Declared a friend above so
// it can reach the private WatchdogProc without a member-function pointer,
// which would bake the class name into the binary (see the header comment).
unsigned __stdcall DownloadWatchdogEntry(void * param)
{
    static_cast<DownloadManager *>(param)->WatchdogProc();

    return 0;
}

DownloadManager::DownloadManager()
{
}

DownloadManager::~DownloadManager()
{
    StopTimeout();

    if (m_hWatchdogWake)
    {
        CloseHandle(m_hWatchdogWake);
        m_hWatchdogWake = nullptr;
    }
}

bool DownloadManager::StartWatchdog()
{
    if (m_hWatchdog)
    {
        return true;
    }

    if (!m_hWatchdogWake)
    {
        m_hWatchdogWake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!m_hWatchdogWake)
        {
            LOG(2, "DownloadManager: failed to create watchdog event: %08X\n", GetLastError());

            return false;
        }
    }

    m_bWatchdogStop.store(false);

    // _beginthreadex rather than CreateThread: the thread may run LOG in
    // instrumented builds, which needs per-thread CRT state.
    const uintptr_t thread_handle = _beginthreadex(nullptr, 0, DownloadWatchdogEntry, this, 0, nullptr);
    if (!thread_handle)
    {
        LOG(2, "DownloadManager: failed to start download watchdog\n");

        return false;
    }

    m_hWatchdog = ReCa<HANDLE>(thread_handle);

    return true;
}

void DownloadManager::StopWatchdog()
{
    if (!m_hWatchdog)
    {
        return;
    }

    m_bWatchdogStop.store(true);

    if (m_hWatchdogWake)
    {
        SetEvent(m_hWatchdogWake);
    }

    WaitForSingleObject(m_hWatchdog, INFINITE);
    CloseHandle(m_hWatchdog);
    m_hWatchdog = nullptr;
}

void DownloadManager::WatchdogProc()
{
    while (!m_bWatchdogStop.load())
    {
        if (WaitForSingleObject(m_hWatchdogWake, 250) == WAIT_OBJECT_0)
        {
            break;
        }

        const ULONGLONG deadline = m_ullDeadline.load();
        if (!deadline || GetTickCount64() < deadline)
        {
            continue;
        }

        // Latch the timeout. The direct WinINet download loop polls TimedOut()
        // between reads and stops on its own, so there is no binding to abort.
        m_bTimedOut.store(true);
    }
}

bool DownloadManager::SetTimeout(DWORD milliseconds)
{
    m_bTimedOut.store(false);
    m_dwTimeoutMs.store(milliseconds);

    if (!milliseconds)
    {
        m_ullDeadline.store(0);
        StopWatchdog();

        return true;
    }

    m_ullDeadline.store(GetTickCount64() + milliseconds);

    return StartWatchdog();
}

void DownloadManager::StopTimeout()
{
    m_ullDeadline.store(0);
    StopWatchdog();
}

bool DownloadManager::TimedOut() const
{
    return m_bTimedOut.load();
}

void DownloadManager::TouchDeadline()
{
    const DWORD timeout = m_dwTimeoutMs.load();
    if (timeout)
    {
        m_ullDeadline.store(GetTickCount64() + timeout);
    }
}
