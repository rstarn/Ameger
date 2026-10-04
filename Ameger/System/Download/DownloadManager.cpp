#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Download/DownloadManager.h"

DownloadManager::DownloadManager(bool ForceRedownload)
{
    m_bForceRedownload = ForceRedownload;
}

DownloadManager::~DownloadManager()
{
    HANDLE interrupt = m_hInterruptEvent.exchange(nullptr);
    if (interrupt)
    {
        CloseHandle(interrupt);
    }
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
    // Never frees: the only instance is an embedded member of SYMBOL_LOADER
    // (m_DlMgr), so its lifetime is owned by that object, not by the ref count.
    // If this class is ever heap-allocated, Release must delete at zero.
    return static_cast<ULONG>(InterlockedDecrement(&m_RefCount));
}

HRESULT __stdcall DownloadManager::OnStartBinding(DWORD dwReserved, IBinding * pib)
{
    UNREFERENCED_PARAMETER(dwReserved);
    UNREFERENCED_PARAMETER(pib);

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

    if (ulProgressMax)
    {
        const float progress = static_cast<float>(ulProgress) / ulProgressMax;
        m_fProgress.store(progress);

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