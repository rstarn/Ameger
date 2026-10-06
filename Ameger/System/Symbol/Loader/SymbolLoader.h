#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "System/Download/DownloadManager.h"
#include "Core/Utility/Tools/Tools.h"

class SYMBOL_LOADER
{
	HANDLE			m_hPdbFile		= NULL;
	std::wstring	m_szPdbPath		= std::wstring();
	DWORD			m_Filesize		= 0;

	HANDLE				m_hInterruptEvent = NULL;
	std::atomic<bool>	m_bInterruptEvent{false};

	DownloadManager m_DlMgr;
	std::atomic<bool>	m_bStartDownload{false};
	
	bool m_bReady = false;

	// Directory created for the cached PDB (<cache root>\Symbols). Tracked so
	// PurgePdb can best-effort remove only a directory this loader made.
	std::wstring	m_szPdbDir		= std::wstring();
	bool			m_bCreatedPdbDir = false;

	bool VerifyExistingPdb(const GUID & guid, DWORD age);

	SYMBOL_LOADER(const SYMBOL_LOADER &) = delete;
	SYMBOL_LOADER & operator=(const SYMBOL_LOADER &) = delete;

public:

	SYMBOL_LOADER();
	~SYMBOL_LOADER();

	DWORD Initialize(const std::wstring & szModulePath, const std::wstring & path, std::wstring * pdb_path_out, bool Redownload, bool WaitForConnection = false, bool AutoDownload = false);
	void Cleanup();

	// Deletes the cached PDB from disk. Called once import resolution is done
	// and the file is no longer mapped: a multi-megabyte ntdll.pdb left on
	// disk is a timestamped artifact that identifies what the tool did.
	// Call Cleanup() first (releases m_hPdbFile), then this.
	void PurgePdb();

	void SetDownload(bool bDownload);
	void Interrupt();

	const std::wstring &	GetFilepath() const;
	DWORD					GetFilesize() const;

	bool IsReady() const;
};

struct PdbInformation
{
	DWORD	Signature;
	GUID	Guid;
	DWORD	Age;
	char	PdbFileName[1];
};

struct PDBHeader7
{
	char signature[0x20];
	int page_size;
	int allocation_table_pointer;
	int file_page_count;
	int root_stream_size;
	int reserved;
	int root_stream_page_number_list_number;
};

struct RootStream7
{
	int num_streams;
	int stream_sizes[ANYSIZE_ARRAY]; 
};

struct GUID_StreamData
{
	int ver;
	int date;
	int age;
	GUID guid;
};

inline SYMBOL_LOADER				sym_ntdll_native;
inline std::shared_future<DWORD>	sym_ntdll_native_ret;