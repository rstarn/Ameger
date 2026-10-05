#include "Core/Utility/Header/PrecompiledHeader.h"

// Include the error codes directly: this TU uses SYMBOL_ERR_* but only reached
// them through the PCH, which clangd does not use.
#include "Core/Foundation/Error.h"

#include "System/Symbol/Loader/SymbolLoader.h"

SYMBOL_LOADER::SYMBOL_LOADER()
{
	m_hInterruptEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
}

SYMBOL_LOADER::~SYMBOL_LOADER()
{
	Cleanup();

	if (m_hInterruptEvent)
	{
		CloseHandle(m_hInterruptEvent);
	}
}

bool SYMBOL_LOADER::VerifyExistingPdb(const GUID & guid, DWORD age)
{
	LOG(2, "SYMBOL_LOADER::VerifyExistingPdb called\n");

	std::ifstream f(m_szPdbPath.c_str(), std::ios::binary | std::ios::ate);
	if (!f.is_open())
	{
		LOG(2, "SYMBOL_LOADER: failed to open PDB for verification\n");

		return false;
	}

	const auto file_size = f.tellg();
	if (file_size <= 0)
	{
		f.close();

		LOG(2, "SYMBOL_LOADER: invaild file size\n");

		return false;
	}

	size_t size_on_disk = static_cast<size_t>(file_size);
	if (!size_on_disk)
	{
		f.close();

		LOG(2, "SYMBOL_LOADER: invaild file size\n");

		return false;
	}

	char * pdb_raw = new(std::nothrow) char[size_on_disk];
	if (!pdb_raw)
	{
		f.close();

		LOG(2, "SYMBOL_LOADER: failed to allocate memory\n");

		return false;
	}

	f.seekg(0, std::ios::beg);
	if (!f.read(pdb_raw, static_cast<std::streamsize>(size_on_disk)) || f.gcount() != static_cast<std::streamsize>(size_on_disk))
	{
		delete[] pdb_raw;
		f.close();

		LOG(2, "SYMBOL_LOADER: failed to read PDB\n");

		return false;
	}
	f.close();

	LOG(2, "SYMBOL_LOADER: PDB loaded into memory\n");

	if (size_on_disk < sizeof(PDBHeader7))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: raw size smaller than PDBHeader7\n");

		return false;
	}

	auto * pPDBHeader = ReCa<PDBHeader7*>(pdb_raw);

	if (memcmp(pPDBHeader->signature, "Microsoft C/C++ MSF 7.00\r\n\x1A""DS\0\0\0", sizeof(PDBHeader7::signature)))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: PDB signature mismatch\n");

		return false;
	}

	if (pPDBHeader->page_size <= 0 || pPDBHeader->file_page_count <= 0 || pPDBHeader->root_stream_page_number_list_number < 0)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid PDB page metadata\n");

		return false;
	}

	const size_t page_size = static_cast<size_t>(pPDBHeader->page_size);
	if (static_cast<size_t>(pPDBHeader->file_page_count) > SIZE_MAX / page_size ||
		size_on_disk < static_cast<size_t>(pPDBHeader->file_page_count) * page_size)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: PDB size smaller than page_size * page_count\n");

		return false;
	}

	const size_t root_page_list_offset = static_cast<size_t>(pPDBHeader->root_stream_page_number_list_number) * page_size;
	if (root_page_list_offset > size_on_disk - sizeof(int))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root page list\n");

		return false;
	}

	int root_page_number = *ReCa<int *>(pdb_raw + root_page_list_offset);
	if (root_page_number < 0 || root_page_number >= pPDBHeader->file_page_count)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root page number\n");

		return false;
	}

	const size_t root_stream_offset = static_cast<size_t>(root_page_number) * page_size;
	if (root_stream_offset > size_on_disk - sizeof(RootStream7))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root stream offset\n");

		return false;
	}

	auto	* pRootStream		= ReCa<RootStream7 *>(pdb_raw + root_stream_offset);

	if (pRootStream->num_streams <= 0)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root stream\n");

		return false;
	}

	// The root stream is laid out as: the stream count, one size per stream,
	// then one page number for every allocated page of every stream. The page
	// number array therefore holds sum(ceil(size_i / page_size)) entries, which
	// is usually far more than num_streams; the previous bound assumed at most
	// one page per stream and so let a corrupt or truncated cached PDB index
	// past the mapped file. The input is a Microsoft-signed PDB fetched from
	// the symbol server, so this hardens against corruption rather than an
	// attacker-controlled payload, but the read must still be bounded.
	const size_t stream_header_bytes = sizeof(int) + static_cast<size_t>(pRootStream->num_streams) * sizeof(int);
	if (stream_header_bytes > size_on_disk - root_stream_offset)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root stream\n");

		return false;
	}

	// Prove the whole page-number array fits before the loop below indexes it.
	const size_t available_page_numbers = (size_on_disk - root_stream_offset - stream_header_bytes) / sizeof(int);
	size_t total_page_numbers = 0;

	for (int i = 0; i != pRootStream->num_streams; ++i)
	{
		const int current_size = pRootStream->stream_sizes[i] == 0xFFFFFFFF ? 0 : pRootStream->stream_sizes[i];
		if (current_size < 0)
		{
			delete[] pdb_raw;

			LOG(2, "SYMBOL_LOADER: invalid stream size\n");

			return false;
		}

		total_page_numbers += static_cast<size_t>(current_size) / page_size + (static_cast<size_t>(current_size) % page_size ? 1 : 0);
		if (total_page_numbers > available_page_numbers)
		{
			delete[] pdb_raw;

			LOG(2, "SYMBOL_LOADER: invalid root stream page list\n");

			return false;
		}
	}

	std::map<int, std::vector<int>> streams;
	int current_page_number = 0;
	
	for (int i = 0; i != pRootStream->num_streams; ++i)
	{
		int current_size = pRootStream->stream_sizes[i] == 0xFFFFFFFF ? 0 : pRootStream->stream_sizes[i];
		if (current_size < 0)
		{
			delete[] pdb_raw;

			LOG(2, "SYMBOL_LOADER: invalid stream size\n");

			return false;
		}

		int current_page_count = current_size / pPDBHeader->page_size;
		if (current_size % pPDBHeader->page_size)
		{
			++current_page_count;
		}

		std::vector<int> numbers;

		for (int j = 0; j != current_page_count; ++j, ++current_page_number)
		{
			const int page_number = pRootStream->stream_sizes[pRootStream->num_streams + current_page_number];
			if (page_number < 0 || page_number >= pPDBHeader->file_page_count)
			{
				delete[] pdb_raw;

				LOG(2, "SYMBOL_LOADER: invalid stream page\n");

				return false;
			}

			numbers.push_back(page_number);
		}

		streams.insert({ i, numbers });
	}

	LOG(2, "SYMBOL_LOADER: PDB size parsed\n");

	const auto pdb_information_stream = streams.find(1);
	if (pdb_information_stream == streams.end() || pdb_information_stream->second.empty())
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: PDB information stream missing\n");

		return false;
	}

	auto pdbInformation_page_index = pdb_information_stream->second.front();
	if (pdbInformation_page_index < 0 || pdbInformation_page_index >= pPDBHeader->file_page_count)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid PDB information page\n");

		return false;
	}

	const size_t stream_data_offset = static_cast<size_t>(pdbInformation_page_index) * page_size;
	if (stream_data_offset > size_on_disk - sizeof(GUID_StreamData))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid PDB information stream\n");

		return false;
	}

	auto * stream_data = ReCa<GUID_StreamData *>(pdb_raw + stream_data_offset);

	int guid_eq = memcmp(&stream_data->guid, &guid, sizeof(GUID));
	const int stream_age = stream_data->age;
	const bool age_eq = stream_age >= 0 && static_cast<DWORD>(stream_age) == age;

	delete[] pdb_raw;

	// GUID is the PDB identity key, not GUID+age. For Microsoft-shipped
	// binaries the module's CodeView RSDS Age and the PDB info stream Age
	// legitimately differ: the RSDS age is pinned (commonly 1) by the
	// reproducible-build toolchain while the PDB keeps its real age, and the
	// symbol server indexes its store by the RSDS age. Verified on this
	// machine: ntdll RSDS age=1 vs downloaded PDB age=4; bcrypt RSDS age=1 vs
	// PDB age=3; the server returns 302 for the RSDS age and 404 for the PDB
	// age. Requiring the ages to match therefore rejects the very PDB the
	// server just served, failing post-download verification with
	// SYMBOL_ERR_DOWNLOAD_FAILED. DbgHelp matches symbols by GUID, so accept
	// on GUID alone.
	auto ret = (guid_eq == 0);

	if (guid_eq != 0)
	{
		LOG(2, "SYMBOL_LOADER: guid mismatch\n");
	}
	else if (!age_eq)
	{
		LOG(2, "SYMBOL_LOADER: PDB age %d differs from module age %u; proceeding on GUID match\n", stream_age, age);
	}
	else
	{
		LOG(2, "SYMBOL_LOADER: guid match\n");
	}

	return ret;
}

DWORD SYMBOL_LOADER::Initialize(const std::wstring & szModulePath, const std::wstring & path, std::wstring * pdb_path_out, bool Redownload, bool WaitForConnection, bool AutoDownload)
{
	Cleanup();

	if (AutoDownload)
	{
		m_bStartDownload = true;
	}

	LOG(1, "SYMBOL_LOADER::Initialize called in thread %08lX (%lu)\n", GetCurrentThreadId(), GetCurrentThreadId());

	std::ifstream File(szModulePath.c_str(), std::ios::binary | std::ios::ate);
	if (!File.good())
	{
		LOG(1, "SYMBOL_LOADER: can't open module path\n");

		return SYMBOL_ERR_CANT_OPEN_MODULE;
	}

	auto FileSize = File.tellg();
	if (FileSize <= 0)
	{
		LOG(1, "SYMBOL_LOADER: invalid file size\n");

		return SYMBOL_ERR_FILE_SIZE_IS_NULL;
	}

	BYTE * pRawData = new(std::nothrow) BYTE[static_cast<size_t>(FileSize)];
	if (!pRawData)
	{
		delete[] pRawData;

		File.close();

		LOG(1, "SYMBOL_LOADER: can't allocate memory\n");

		return SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char *>(pRawData), FileSize);
	if (!File || File.gcount() != FileSize)
	{
		delete[] pRawData;
		File.close();

		LOG(1, "SYMBOL_LOADER: short read of module file\n");

		return SYMBOL_ERR_CANT_OPEN_MODULE;
	}
	File.close();

	LOG(1, "SYMBOL_LOADER: ready to parse PE headers\n");

	PE_IMAGE::OPTIONS module_options;
	module_options.EnableExceptions = true;
	PE_IMAGE::VIEW module_view;
	const DWORD validation_result = PE_IMAGE::Validate(pRawData, static_cast<size_t>(FileSize), IMAGE_FILE_MACHINE_AMD64, module_options, module_view);
	if (validation_result != FILE_ERR_SUCCESS)
	{
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: invalid module layout: %08X\n", validation_result);

		return SYMBOL_ERR_INVALID_FILE_ARCHITECTURE;
	}

	IMAGE_DOS_HEADER * pDos = ReCa<IMAGE_DOS_HEADER *>(pRawData);
	IMAGE_NT_HEADERS * pNT = ReCa<IMAGE_NT_HEADERS *>(pRawData + pDos->e_lfanew);
	IMAGE_FILE_HEADER * pFile = &pNT->FileHeader;
	// x64-only build: PE_IMAGE::Validate above already enforced
	// IMAGE_FILE_MACHINE_AMD64, so the 32-bit optional header is gone
	// (same eradicated-x86 doctrine as the rest of the codebase).
	IMAGE_OPTIONAL_HEADER64 * pOpt64 = ReCa<IMAGE_OPTIONAL_HEADER64 *>(&pNT->OptionalHeader);

	LOG(1, "SYMBOL_LOADER: x64 target identified\n");


	DWORD ImageSize = pOpt64->SizeOfImage;
	// W^X: parse-only mapping, never executed. RW suffices.
	BYTE * pLocalImageBase = ReCa<BYTE *>(VirtualAlloc(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pLocalImageBase)
	{
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: can't allocate memory: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_CANT_ALLOC_MEMORY;
	}

	memcpy(pLocalImageBase, pRawData, pOpt64->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT);
	for (UINT i = 0; i != pFile->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memcpy(pLocalImageBase + pCurrentSectionHeader->VirtualAddress, pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}
	
	LOG(1, "SYMBOL_LOADER: sections mapped\n");

	IMAGE_DATA_DIRECTORY * pDataDir = &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

	IMAGE_DEBUG_DIRECTORY * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pLocalImageBase + pDataDir->VirtualAddress);

	if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: no PDB debug data\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}

	PdbInformation * pdbInformation = ReCa<PdbInformation *>(pLocalImageBase + pDebugDir->AddressOfRawData);
	if (pdbInformation->Signature != 0x53445352)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: invalid PDB signature\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}
	
	m_szPdbPath = path;
	if (m_szPdbPath.empty())
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: empty download path\n");

		return SYMBOL_ERR_PATH_DOESNT_EXIST;
	}
	
	if (m_szPdbPath[m_szPdbPath.length() - 1] != '\\')
	{
		m_szPdbPath += '\\';
	}

	LOG(1, "SYMBOL_LOADER: PDB signature identified\n");

	if (!CreateDirectoryW(m_szPdbPath.c_str(), nullptr))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			LOG(1, "SYMBOL_LOADER: can't create/open download path: 0x%08X\n", GetLastError());

			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
			delete[] pRawData;

			return SYMBOL_ERR_PATH_DOESNT_EXIST;
		}
	}

	m_szPdbPath += L"Symbols\\";

	m_szPdbDir = m_szPdbPath;
	m_bCreatedPdbDir = false;
	if (CreateDirectoryW(m_szPdbPath.c_str(), nullptr))
	{
		m_bCreatedPdbDir = true;
	}
	else if (GetLastError() != ERROR_ALREADY_EXISTS)
	{
		LOG(1, "SYMBOL_LOADER: can't create/open download path: 0x%08X\n", GetLastError());

		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		delete[] pRawData;

		return SYMBOL_ERR_CANT_CREATE_DIRECTORY;
	}

	auto PdbFileName = CharArrayToStdWstring(pdbInformation->PdbFileName);
	if (PdbFileName.empty() || PdbFileName.size() > 64 ||
		PdbFileName.find_first_of(L"\\/") != std::wstring::npos ||
		PdbFileName.find(L"..") != std::wstring::npos ||
		PdbFileName.find(L':') != std::wstring::npos)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: unsafe PDB file name\n");

		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}

	m_szPdbPath += PdbFileName;

	LOG(1, "SYMBOL_LOADER: PDB path = %ls\n", m_szPdbPath.c_str());
		
	m_Filesize = 0;
	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
	if (GetFileAttributesExW(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
	{
		m_Filesize = file_attr_data.nFileSizeLow;

		if (!Redownload && !VerifyExistingPdb(pdbInformation->Guid, pdbInformation->Age))
		{
			LOG(1, "SYMBOL_LOADER: verification failed, PDB will be redownloaded\n");

			Redownload = true;
		}

		if (Redownload)
		{
			DeleteFileW(m_szPdbPath.c_str());
		}
	}	
	else
	{
		LOG(1, "SYMBOL_LOADER: file doesn't exist, PDB will be downloaded\n");

		Redownload = true;
	}

	if (Redownload)
	{
		wchar_t w_GUID[100]{ 0 };
		if (!StringFromGUID2(pdbInformation->Guid, w_GUID, 100))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to parse GUID");

			return SYMBOL_ERR_CANT_CONVERT_PDB_GUID;
		}

		LOG(1, "SYMBOL_LOADER: GUID = %ls\n", w_GUID);

		std::wstring guid_filtered;
		for (UINT i = 0; w_GUID[i]; ++i)
		{
			if ((w_GUID[i] >= '0' && w_GUID[i] <= '9') || (w_GUID[i] >= 'A' && w_GUID[i] <= 'F') || (w_GUID[i] >= 'a' && w_GUID[i] <= 'f'))
			{
				guid_filtered += w_GUID[i];
			}
		}
		
		// Symbol URL base uses the triple layer (XOR + XTEA-32 + shuffle):
		// the highest-value static secret earns the strongest tier. Stack
		// copy is wiped on scope exit; the heap wstring holds it briefly.
		std::wstring url = KC_WSTR_LAYERED(L"https://msdl.microsoft.com/download/symbols/").c_str();
		url += PdbFileName;
		url += '/';
		url += guid_filtered;
		url += std::to_wstring(pdbInformation->Age);
		url += '/';
		url += PdbFileName;

		LOG(1, "SYMBOL_LOADER: URL = %ls\n", url.c_str());

		if (WaitForConnection)
		{
			LOG(1, "SYMBOL_LOADER: checking internet connection\n");

			const ULONGLONG connection_deadline = GetTickCount64() + 60000;
			while (InternetCheckConnectionW(XOR_STR_W(L"https://msdl.microsoft.com").get(), FLAG_ICC_FORCE_CONNECTION, NULL) == FALSE)
			{
				if (GetLastError() == ERROR_INTERNET_CANNOT_CONNECT || GetTickCount64() >= connection_deadline)
				{
					VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

					delete[] pRawData;

					LOG(1, "SYMBOL_LOADER: cannot connect to Microsoft Symbol Server\n");

					return SYMBOL_ERR_CANNOT_CONNECT;
				}

				Sleep(25);

				if (m_bInterruptEvent)
				{
					VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

					delete[] pRawData;

					LOG(1, "SYMBOL_LOADER: interrupt event triggered\n");

					return SYMBOL_ERR_INTERRUPT;
				}
			}

			LOG(1, "SYMBOL_LOADER: connection verified\n");
		}

		if (m_hInterruptEvent)
		{
			m_DlMgr.SetInterruptEvent(m_hInterruptEvent);
		}

		if (!m_bStartDownload)
		{
			LOG(1, "SYMBOL_LOADER: waiting for download start\n");
		}

		while (!m_bStartDownload && !m_bInterruptEvent)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

		if (m_bInterruptEvent)
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: download interrupted\n");

			return SYMBOL_ERR_INTERRUPT;
		}

		LOG(1, "SYMBOL_LOADER: downloading PDB\n");

		// URLDownloadToCacheFileW has no timeout of its own, so a stalled symbol
		// server would block runtime initialization forever. Bound the download
		// with an inactivity deadline enforced by the bind callback's watchdog;
		// if it cannot be armed, fail closed rather than download unbounded.
		// 60s matches the connection check above.
		constexpr DWORD kDownloadInactivityTimeoutMs = 60000;
		if (!m_DlMgr.SetTimeout(kDownloadInactivityTimeoutMs))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to arm download timeout\n");

			return SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		// Transient network / CDN failures are common on msdl; a single
		// URLDownloadToCacheFileW attempt turned every blip into a fatal
		// SYMBOL_ERR_DOWNLOAD_FAILED. Retry 3x with 1s spacing, honoring
		// the interrupt event between attempts. E_ABORT stays sticky, and a
		// timeout stops the retry loop so a stalled server cannot burn the
		// remaining attempts.
		HRESULT dl_hr = E_FAIL;
		wchar_t szCacheFile[MAX_PATH]{ 0 };
		bool dl_aborted = false;
		for (int attempt = 1; attempt <= 3; ++attempt)
		{
			if (m_DlMgr.TimedOut())
			{
				dl_aborted = true;
				break;
			}

			szCacheFile[0] = L'\0';
			dl_hr = URLDownloadToCacheFileW(nullptr, url.c_str(), szCacheFile, sizeof(szCacheFile) / sizeof(szCacheFile[0]), NULL, &m_DlMgr);
			if (SUCCEEDED(dl_hr))
			{
				break;
			}
			LOG(1, "SYMBOL_LOADER: download attempt %d/3 failed: 0x%08X\n", attempt, dl_hr);
			if (dl_hr == E_ABORT || m_bInterruptEvent || m_DlMgr.TimedOut())
			{
				dl_aborted = true;
				break;
			}
			if (attempt < 3)
			{
				for (int waited = 0; waited < 100; ++waited)
				{
					if (m_bInterruptEvent || m_DlMgr.TimedOut())
					{
						dl_aborted = true;
						break;
					}
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
				}
				if (dl_aborted)
				{
					break;
				}
			}
		}

		const bool dl_timed_out = m_DlMgr.TimedOut();

		m_DlMgr.StopTimeout();

		auto hr = dl_hr;
		if (FAILED(hr))
		{
			// A timed-out or aborted URLDownloadToCacheFileW can leave a partial
			// cache file behind; drop it so failures do not accumulate artifacts.
			if (szCacheFile[0])
			{
				DeleteFileW(szCacheFile);
			}

			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to download file: 0x%08X\n", hr);

			if (dl_timed_out)
			{
				LOG(1, "SYMBOL_LOADER: PDB download timed out\n");

				return SYMBOL_ERR_DOWNLOAD_FAILED;
			}

			return (hr == E_ABORT || dl_aborted) ? SYMBOL_ERR_INTERRUPT : SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		LOG(1, "SYMBOL_LOADER: download finished\n");

		if (!CopyFileW(szCacheFile, m_szPdbPath.c_str(), FALSE))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to copy file into working directory: 0x%08X\n", GetLastError());

			DeleteFileW(szCacheFile);

			// CopyFileW is not atomic: a partial destination is ours (any
			// pre-existing PDB was removed above), so remove it too.
			DeleteFileW(m_szPdbPath.c_str());

			return SYMBOL_ERR_COPYFILE_FAILED;
		}

		DeleteFileW(szCacheFile);

		if (!VerifyExistingPdb(pdbInformation->Guid, pdbInformation->Age))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			DeleteFileW(m_szPdbPath.c_str());

			LOG(1, "SYMBOL_LOADER: downloaded PDB failed verification\n");

			return SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		m_Filesize = 0;
	}

	m_fProgress = 1.0f;

	VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

	delete[] pRawData;

	LOG(1, "SYMBOL_LOADER: PDB verified\n");

	if (Redownload || !m_Filesize)
	{
		if (!GetFileAttributesExW(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
		{
			LOG(1, "SYMBOL_LOADER: can't access PDB file: 0x%08X\n", GetLastError());

			// This path is only reachable with Redownload set, so the file was
			// downloaded this run: delete it rather than leave it on disk.
			DeleteFileW(m_szPdbPath.c_str());

			return SYMBOL_ERR_CANT_ACCESS_PDB_FILE;
		}

		m_Filesize = file_attr_data.nFileSizeLow;
	}

	m_hPdbFile = CreateFileW(m_szPdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, NULL, nullptr);
	if (m_hPdbFile == INVALID_HANDLE_VALUE)
	{
		m_hPdbFile = nullptr;

		LOG(1, "SYMBOL_LOADER: can't open PDB file: 0x%08X\n", GetLastError());

		// Downloaded this run and unusable: remove it so it is not left behind.
		DeleteFileW(m_szPdbPath.c_str());

		return SYMBOL_ERR_CANT_OPEN_PDB_FILE;
	}

	if (pdb_path_out)
	{
		*pdb_path_out = m_szPdbPath;
	}

	m_bReady = true;

	return SYMBOL_ERR_SUCCESS;
}

void SYMBOL_LOADER::Cleanup()
{
	LOG(1, "SYMBOL_LOADER::Cleanup\n");

	m_bReady = false;

	if (m_hPdbFile && m_hPdbFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hPdbFile);
	}

	m_hPdbFile = nullptr;
}

void SYMBOL_LOADER::PurgePdb()
{
	if (m_szPdbPath.empty())
	{
		return;
	}

	// Safety: only ever remove a file this loader created, i.e. one that lives
	// under the cache root we were handed and is named <pdb>. Never recurse;
	// the only directory touched is the empty Symbols directory this loader
	// itself created (handled after a successful file purge below).
	const DWORD attributes = GetFileAttributesW(m_szPdbPath.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		return;
	}

	if (m_hPdbFile)
	{
		Cleanup();
	}

	if (!DeleteFileW(m_szPdbPath.c_str()))
	{
		LOG(1, "SYMBOL_LOADER: failed to purge cached PDB: 0x%08X\n", GetLastError());
		return;
	}

	LOG(1, "SYMBOL_LOADER: cached PDB purged from disk\n");
	m_Filesize = 0;

	// Best-effort: drop the Symbols directory too, but only when this loader
	// created it and it is now empty. RemoveDirectoryW refuses a non-empty
	// directory, so a shared cache holding other entries is never disturbed,
	// and any failure is ignored - the PDB purge above already succeeded.
	if (m_bCreatedPdbDir && !m_szPdbDir.empty())
	{
		RemoveDirectoryW(m_szPdbDir.c_str());
		m_bCreatedPdbDir = false;
	}
}

void SYMBOL_LOADER::SetDownload(bool bDownload)
{
	m_bStartDownload = bDownload;
}

void SYMBOL_LOADER::Interrupt()
{
	LOG(1, "SYMBOL_LOADER::Interrupt\n");

	m_bInterruptEvent = true;

	if (m_hInterruptEvent)
	{
		if (!SetEvent(m_hInterruptEvent))
		{
			LOG(1, "SYMBOL_LOADER: SetEvent failed to trigger interrupt event: %08X\n", GetLastError());
		}
		else
		{
			LOG(1, "SYMBOL_LOADER: interrupt event set\n");
		}
	}
	else
	{
		LOG(1, "SYMBOL_LOADER: no interrupt event specified\n");
	}

}

const std::wstring & SYMBOL_LOADER::GetFilepath() const
{
	return m_szPdbPath;
}

DWORD SYMBOL_LOADER::GetFilesize() const
{
	return m_Filesize;
}

bool SYMBOL_LOADER::IsReady() const
{
	return m_bReady;
}