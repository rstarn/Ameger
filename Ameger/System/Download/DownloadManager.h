#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

class DownloadManager : public IBindStatusCallback
{
    std::atomic<HANDLE> m_hInterruptEvent{nullptr};
    std::atomic<float>  m_fProgress{0.0f};
    std::atomic<float>  m_fOldProgress{0.0f};
    bool                m_bForceRedownload  = false;
    LONG                m_RefCount          = 1;

public:

    DownloadManager(bool ForceRedownload = true);

    ~DownloadManager();

    DownloadManager(const DownloadManager &) = delete;
    DownloadManager & operator=(const DownloadManager &) = delete;

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