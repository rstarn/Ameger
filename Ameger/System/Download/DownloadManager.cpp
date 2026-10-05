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

DownloadManager::DownloadManager(bool ForceRedownload)
{
    m_bForceRedownload = ForceRedownload;
}

DownloadManager::~DownloadManager()
{
    StopTimeout();

    if (m_hWatchdogWake)
    {
        CloseHandle(m_hWatchdogWake);
        m_hWatchdogWake = nullptr;
    }

    HANDLE interrupt = m_hInterruptEvent.exchange(nullptr);
    if (interrupt)
    {
        CloseHandle(interrupt);
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

        const bool first_timeout = !m_bTimedOut.exchange(true);

        // AddRef under the lock keeps the binding alive across Abort even if
        // OnStartBinding swaps in the next attempt concurrently.
        IBinding * binding = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_bindingMutex);
            binding = m_pBinding;
            if (binding)
            {
                binding->AddRef();
            }
        }

        if (binding)
        {
            if (first_timeout)
            {
                LOG(2, "DownloadManager: download inactivity deadline elapsed, aborting binding\n");
            }

            binding->Abort();
            binding->Release();
        }
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

    IBinding * binding = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_bindingMutex);
        binding = m_pBinding;
        m_pBinding = nullptr;
    }

    if (binding)
    {
        binding->Release();
    }
}

bool DownloadManager::TimedOut() const
{
    return m_bTimedOut.load();
}

HRESULT __stdcall DownloadManager::QueryInterface(const IID & riid, void ** ppvObject)
{
    if (!ppvObject)
    {
        return E_POINTER;
    }

    if (riid == IID_IUnknown || riid == IID_IBindStatusCallback)
    {
        *ppvObject = static_cast<IBindStatusCallback *>(this);
        AddRef();

        return S_OK;
    }

    *ppvObject = nullptr;

    return E_NOINTERFACE;
}

ULONG __stdcall DownloadManager::AddRef(void)
{
    return static_cast<ULONG>(InterlockedIncrement(&m_RefCount));
}

ULONG __stdcall DownloadManager::Release(void)
{
    // Never frees, deliberately. The only instance is an embedded member of
    // SYMBOL_LOADER (m_DlMgr), so its lifetime is owned by that object, not by
    // the ref count: `delete this` here would free a member and corrupt the
    // loader. The COM contract wants the count to bottom out at zero, so clamp
    // it there instead of letting it go negative, and record the count so a
    // future heap-allocated use is visible rather than silent.
    const LONG remaining = InterlockedDecrement(&m_RefCount);
    if (remaining < 0)
    {
        InterlockedExchangeAdd(&m_RefCount, -remaining);
    }
    return static_cast<ULONG>(remaining < 0 ? 0 : remaining);
}

HRESULT __stdcall DownloadManager::OnStartBinding(DWORD dwReserved, IBinding * pib)
{
    UNREFERENCED_PARAMETER(dwReserved);

    if (pib)
    {
        pib->AddRef();

        IBinding * previous = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_bindingMutex);
            previous = m_pBinding;
            m_pBinding = pib;
        }

        if (previous)
        {
            previous->Release();
        }
    }

    // Binding start counts as liveness: slide the inactivity deadline, and if
    // it already elapsed during connect, abort at once.
    const DWORD timeout = m_dwTimeoutMs.load();
    if (timeout)
    {
        m_ullDeadline.store(GetTickCount64() + timeout);
    }

    if (pib && m_bTimedOut.load())
    {
        pib->Abort();
    }

    LOG(2, "DownloadManager: OnStartBinding\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::GetPriority(LONG * pnPriority)
{
    UNREFERENCED_PARAMETER(pnPriority);

    LOG(2, "DownloadManager: GetPriority\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnLowResource(DWORD reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    LOG(2, "DownloadManager: OnLowResource\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnStopBinding(HRESULT hresult, LPCWSTR szError)
{
    UNREFERENCED_PARAMETER(hresult);
    UNREFERENCED_PARAMETER(szError);

    LOG(2, "DownloadManager: OnStopBinding\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::GetBindInfo(DWORD * grfBINDF, BINDINFO * pbindinfo)
{
    LOG(2, "DownloadManager: GetBindInfo\n");

    UNREFERENCED_PARAMETER(grfBINDF);

    if (pbindinfo)
    {
        pbindinfo->cbSize = sizeof(BINDINFO);
    }

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC * pformatetc, STGMEDIUM * pstgmed)
{
    UNREFERENCED_PARAMETER(grfBSCF);
    UNREFERENCED_PARAMETER(dwSize);
    UNREFERENCED_PARAMETER(pformatetc);
    UNREFERENCED_PARAMETER(pstgmed);

    LOG(2, "DownloadManager: OnDataAvailable\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnObjectAvailable(const IID & riid, IUnknown * punk)
{
    UNREFERENCED_PARAMETER(riid);
    UNREFERENCED_PARAMETER(punk);

    LOG(2, "DownloadManager: OnObjectAvailable\n");

    return S_OK;
}

HRESULT __stdcall DownloadManager::OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText)
{
	UNREFERENCED_PARAMETER(ulStatusCode);
    UNREFERENCED_PARAMETER(szStatusText);

    HANDLE interrupt = m_hInterruptEvent.load();
    if (interrupt && WaitForSingleObject(interrupt, 0) == WAIT_OBJECT_0)
    {
        LOG(2, "DownloadManager: Interrupting download\n");

        return E_ABORT;
    }

    // Every progress/status event counts as liveness: slide the inactivity
    // deadline so a slow transfer is never cut off, and fail the bind if the
    // watchdog already declared a timeout.
    const DWORD timeout = m_dwTimeoutMs.load();
    if (timeout)
    {
        m_ullDeadline.store(GetTickCount64() + timeout);
    }

    if (m_bTimedOut.load())
    {
        LOG(2, "DownloadManager: download timed out, aborting\n");

        return E_ABORT;
    }

    if (ulProgressMax)
    {
        const float progress = static_cast<float>(ulProgress) / ulProgressMax;

		if (progress - m_fOldProgress >= 0.095f)
		{
			LOG(2, "DownloadManager: %2.0f%%\n", (double)100.0f * progress);
			m_fOldProgress = progress;
		}
	}

	return S_OK;
}

BOOL DownloadManager::SetInterruptEvent(HANDLE hInterrupt)
{
	HANDLE duplicated = nullptr;
    auto current_process = GetCurrentProcess();

    if (hInterrupt && !DuplicateHandle(current_process, hInterrupt, current_process, &duplicated, NULL, FALSE, DUPLICATE_SAME_ACCESS))
    {
        LOG(2, "Failed to duplicate interrupt handle object: %08X\n", GetLastError());

        return FALSE;
    }

    LOG(2, "DownloadManager: New interrupt event specified\n");

	HANDLE previous = m_hInterruptEvent.exchange(duplicated);
	if (previous)
	{
		CloseHandle(previous);
	}

	return TRUE;
}