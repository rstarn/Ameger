#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include <mutex>

class DownloadManager : public IBindStatusCallback
{
    std::atomic<HANDLE> m_hInterruptEvent{nullptr};
    std::atomic<float>  m_fOldProgress{0.0f};
    bool                m_bForceRedownload  = false;
    LONG                m_RefCount          = 1;

    // Bounded download. URLDownloadToCacheFileW carries no timeout of its own,
    // so a stalled symbol server would block runtime initialization forever.
    // A watchdog thread aborts the live IBinding once m_ullDeadline passes;
    // OnProgress/OnStartBinding slide that deadline forward on every sign of
    // liveness, making it an inactivity bound rather than a total-duration cap,
    // so a slow-but-alive transfer is never cut off. OnProgress also fails the
    // bind directly when the deadline is already past, covering a callback that
    // fires between watchdog ticks.
    std::atomic<IBinding *> m_pBinding{nullptr};
    std::atomic<ULONGLONG>  m_ullDeadline{0};
    std::atomic<DWORD>      m_dwTimeoutMs{0};
    std::atomic<bool>       m_bTimedOut{false};
    std::atomic<bool>       m_bWatchdogStop{false};
    std::mutex              m_bindingMutex;
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

    DownloadManager(bool ForceRedownload = true);

    ~DownloadManager();

    DownloadManager(const DownloadManager &) = delete;
    DownloadManager & operator=(const DownloadManager &) = delete;

    // Arms an inactivity bound for the download. `milliseconds` is refreshed on
    // every progress event; 0 disables the bound. Returns false if the watchdog
    // could not be armed so the caller can fail closed instead of downloading
    // unbounded. StopTimeout() ends the watchdog and drops the binding ref.
    bool SetTimeout(DWORD milliseconds);
    void StopTimeout();
    bool TimedOut() const;

    HRESULT __stdcall QueryInterface(const IID & riid, void ** ppvObject);

    ULONG STDMETHODCALLTYPE AddRef();

    ULONG STDMETHODCALLTYPE Release();

    virtual HRESULT STDMETHODCALLTYPE OnStartBinding(DWORD dwReserved, IBinding * pib);

    virtual HRESULT STDMETHODCALLTYPE GetPriority(LONG * pnPriority);

    virtual HRESULT STDMETHODCALLTYPE OnLowResource(DWORD reserved);

    virtual HRESULT STDMETHODCALLTYPE OnStopBinding(HRESULT hresult, LPCWSTR szError);

    virtual HRESULT STDMETHODCALLTYPE GetBindInfo(DWORD * grfBINDF, BINDINFO * pbindinfo);

    virtual HRESULT STDMETHODCALLTYPE OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC * pformatetc, STGMEDIUM * pstgmed);

    virtual HRESULT STDMETHODCALLTYPE OnObjectAvailable(const IID & riid, IUnknown * punk);

    HRESULT __stdcall OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText);

    BOOL SetInterruptEvent(HANDLE hInterrupt);
};