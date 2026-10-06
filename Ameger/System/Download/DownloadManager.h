#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

class DownloadManager
{
    // Bounded download. WinINet's per-call timeouts bound each read, but a
    // stalled symbol server must not block runtime initialization, so a
    // watchdog thread latches m_bTimedOut once m_ullDeadline passes. The
    // deadline is slid forward on every sign of liveness - TouchDeadline from
    // the direct download loop - making it an inactivity bound rather than a
    // total-duration cap, so a slow-but-alive transfer is never cut off. The
    // direct loop polls TimedOut() between reads, so no binding callback is
    // involved.
    std::atomic<ULONGLONG>  m_ullDeadline{0};
    std::atomic<DWORD>      m_dwTimeoutMs{0};
    std::atomic<bool>       m_bTimedOut{false};
    std::atomic<bool>       m_bWatchdogStop{false};
    HANDLE                  m_hWatchdog = nullptr;
    HANDLE                  m_hWatchdogWake = nullptr;

    bool StartWatchdog();
    void StopWatchdog();
    void WatchdogProc();

    // Free-function thread trampoline. A member-function pointer (std::thread
    // or &DownloadManager::WatchdogProc) would bake this class name into the
    // mangled template instantiation and trip the runtime string gate; a plain
    // function pointer carries no class name.
    friend unsigned __stdcall DownloadWatchdogEntry(void * param);

public:

    DownloadManager();

    ~DownloadManager();

    DownloadManager(const DownloadManager &) = delete;
    DownloadManager & operator=(const DownloadManager &) = delete;

    // Arms an inactivity bound for the download. `milliseconds` is refreshed on
    // every progress event; 0 disables the bound. Returns false if the watchdog
    // could not be armed so the caller can fail closed instead of downloading
    // unbounded. StopTimeout() ends the watchdog.
    bool SetTimeout(DWORD milliseconds);
    void StopTimeout();
    bool TimedOut() const;

    // Slides the inactivity deadline forward on a sign of liveness. The direct
    // WinINet download path has no progress callback to do this, so it calls
    // this after each successful read; without it the watchdog would degrade
    // from an inactivity bound into a total-duration cap.
    void TouchDeadline();
};
