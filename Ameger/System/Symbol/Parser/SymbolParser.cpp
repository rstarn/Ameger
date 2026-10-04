#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Symbol/Parser/SymbolParser.h"

SYMBOL_PARSER::SYMBOL_PARSER()
{

}

SYMBOL_PARSER::~SYMBOL_PARSER()
{
	Cleanup();
}

DWORD SYMBOL_PARSER::Initialize(const SYMBOL_LOADER * pSymbolObject)
{
	LOG(1, "SYMBOL_LOADER::Initialize\n");

	m_bReady = false;

	if (!pSymbolObject)
	{
		LOG(1, "SYMBOL_PARSER: symbol object is NULL\n");

		return SYMBOL_ERR_OBJECT_IS_NULL;
	}

	if (!pSymbolObject->IsReady())
	{
		LOG(1, "SYMBOL_PARSER: symbol object isn't ready\n");

		return SYMBOL_ERR_OBJECT_NOT_READY;
	}

	if (m_SymbolTable)
	{
		SymUnloadModule64(m_hProcess, m_SymbolTable);

		m_SymbolTable = 0;
	}

	if (!m_hProcess)
	{
		m_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
		if (!m_hProcess)
		{
			LOG(1, "SYMBOL_PARSER: can't open current process: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_CANT_OPEN_PROCESS;
		}
	}

	if (!m_bInitialized)
	{
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS);

		if (!SymInitializeW(m_hProcess, nullptr, FALSE))
		{
			CloseHandle(m_hProcess);
			m_hProcess = nullptr;
			m_bInitialized = false;

			LOG(1, "SYMBOL_PARSER: SymInitializeW failed: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_SYM_INIT_FAIL;
		}

		m_bInitialized = true;
	}

	m_SymbolTable = SymLoadModuleExW(m_hProcess, nullptr, pSymbolObject->GetFilepath().c_str(), nullptr, 0x10000000, pSymbolObject->GetFilesize(), nullptr, NULL);
	if (!m_SymbolTable)
	{
		SymCleanup(m_hProcess);

		CloseHandle(m_hProcess);
		m_hProcess = nullptr;
		m_bInitialized = false;

		LOG(1, "SYMBOL_PARSER: SymLoadModuleExW failed: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_SYM_LOAD_TABLE;
	}

	m_bReady = true;

	LOG(1, "SYMBOL_PARSER: initialization finished\n");

	return SYMBOL_ERR_SUCCESS;
}

DWORD SYMBOL_PARSER::GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut)
{
	if (!m_bReady)
	{
		LOG(2, "SYMBOL_PARSER: not ready\n");

		return SYMBOL_ERR_NOT_INITIALIZED;
	}

	if (!szSymbolName)
	{
		LOG(2, "SYMBOL_PARSER: invalid symbol name\n");

		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}

	BYTE buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]{ 0 };
	auto * si = ReCa<SYMBOL_INFO *>(buffer);
	si->SizeOfStruct = sizeof(SYMBOL_INFO);
	si->MaxNameLen = MAX_SYM_NAME;
	if (!SymFromName(m_hProcess, szSymbolName, si))
	{
		LOG(2, "SYMBOL_PARSER: search failed: %08X\n", GetLastError());

		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}

	if (si->Address < si->ModBase || si->Address - si->ModBase > 0xFFFFFFFFull)
	{
		LOG(2, "SYMBOL_PARSER: address outside module\n");

		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}

	RvaOut = static_cast<DWORD>(si->Address - si->ModBase);

	LOG(2, "SYMBOL_PARSER: RVA %08X -> %s\n", RvaOut, szSymbolName);

	return SYMBOL_ERR_SUCCESS;
}

DWORD SYMBOL_PARSER::GetTypeId(const char * szTypeName, DWORD64 & TypeIdOut)
{
	TypeIdOut = 0;
	if (!m_bReady)
	{
		return SYMBOL_ERR_NOT_INITIALIZED;
	}
	if (!szTypeName || !szTypeName[0])
	{
		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}
	BYTE buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]{ 0 };
	auto * si = ReCa<SYMBOL_INFO *>(buffer);
	si->SizeOfStruct = sizeof(SYMBOL_INFO);
	si->MaxNameLen = MAX_SYM_NAME;
	if (!SymGetTypeFromName(m_hProcess, m_SymbolTable, szTypeName, si))
	{
		LOG(2, "SYMBOL_PARSER: type not found: %s (%08X)\n", szTypeName, GetLastError());
		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}
	if (!si->TypeIndex)
	{
		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}
	TypeIdOut = si->TypeIndex;
	LOG(2, "SYMBOL_PARSER: type %s -> id %08X\n", szTypeName, static_cast<DWORD>(TypeIdOut));
	return SYMBOL_ERR_SUCCESS;
}

DWORD SYMBOL_PARSER::GetTypeSize(const char * szTypeName, ULONG64 & SizeOut)
{
	SizeOut = 0;
	DWORD64 type_id = 0;
	DWORD ret = GetTypeId(szTypeName, type_id);
	if (ret != SYMBOL_ERR_SUCCESS)
	{
		return ret;
	}
	ULONG64 length = 0;
	if (!SymGetTypeInfo(m_hProcess, m_SymbolTable, static_cast<ULONG>(type_id), TI_GET_LENGTH, &length))
	{
		LOG(2, "SYMBOL_PARSER: TI_GET_LENGTH failed for %s (%08X)\n", szTypeName, GetLastError());
		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}
	if (!length || length > 0x10000)
	{
		LOG(2, "SYMBOL_PARSER: implausible size for %s: %llu\n", szTypeName, length);
		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}
	SizeOut = length;
	LOG(2, "SYMBOL_PARSER: size %s = %llu\n", szTypeName, length);
	return SYMBOL_ERR_SUCCESS;
}

DWORD SYMBOL_PARSER::GetFieldOffset(const char * szTypeName, const char * szFieldName, DWORD & OffsetOut)
{
	OffsetOut = 0;
	if (!m_bReady)
	{
		return SYMBOL_ERR_NOT_INITIALIZED;
	}
	if (!szTypeName || !szTypeName[0] || !szFieldName || !szFieldName[0])
	{
		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}
	DWORD64 type_id64 = 0;
	// GetTypeId opens+closes its own ULTRA region; never double-END on early out.
	DWORD ret = GetTypeId(szTypeName, type_id64);
	if (ret != SYMBOL_ERR_SUCCESS)
	{
		return ret;
	}
	const ULONG type_id = static_cast<ULONG>(type_id64);
	DWORD child_count = 0;
	if (!SymGetTypeInfo(m_hProcess, m_SymbolTable, type_id, TI_GET_CHILDRENCOUNT, &child_count))
	{
		LOG(2, "SYMBOL_PARSER: TI_GET_CHILDRENCOUNT failed for %s\n", szTypeName);
		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}
	if (!child_count || child_count > 512)
	{
		LOG(2, "SYMBOL_PARSER: bad child count %lu for %s\n", child_count, szTypeName);
		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}
	const size_t alloc_size = sizeof(TI_FINDCHILDREN_PARAMS) + (static_cast<size_t>(child_count) - 1) * sizeof(ULONG);
	TI_FINDCHILDREN_PARAMS * children = ReCa<TI_FINDCHILDREN_PARAMS *>(new(std::nothrow) BYTE[alloc_size]());
	if (!children)
	{
		return SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW;
	}
	children->Count = child_count;
	children->Start = 0;
	DWORD result = SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	if (SymGetTypeInfo(m_hProcess, m_SymbolTable, type_id, TI_FINDCHILDREN, children))
	{
		// Convert once: PDB child names are wide; target field is narrow UTF-8/ASCII.
		wchar_t want_w[128]{ 0 };
		const int want_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szFieldName, -1, want_w, _countof(want_w));
		if (want_len > 0)
		{
			for (ULONG i = 0; i < children->Count; ++i)
			{
				WCHAR * child_name = nullptr;
				if (!SymGetTypeInfo(m_hProcess, m_SymbolTable, children->ChildId[i], TI_GET_SYMNAME, &child_name))
				{
					continue;
				}
				const bool match = child_name && _wcsicmp(child_name, want_w) == 0;
				if (child_name)
				{
					LocalFree(child_name);
				}
				if (!match)
				{
					continue;
				}
				DWORD field_offset = 0;
				if (!SymGetTypeInfo(m_hProcess, m_SymbolTable, children->ChildId[i], TI_GET_OFFSET, &field_offset))
				{
					continue;
				}
				// Sanity: a field past 8KB inside TEB/PEB/LDR is corruption, not drift.
				if (field_offset > 0x2000)
				{
					continue;
				}
				OffsetOut = field_offset;
				LOG(2, "SYMBOL_PARSER: %s::%s = 0x%X\n", szTypeName, szFieldName, field_offset);
				result = SYMBOL_ERR_SUCCESS;
				break;
			}
		}
		if (result != SYMBOL_ERR_SUCCESS)
		{
			LOG(2, "SYMBOL_PARSER: field %s not found in %s\n", szFieldName, szTypeName);
		}
	}
	else
	{
		LOG(2, "SYMBOL_PARSER: TI_FINDCHILDREN failed for %s (%08X)\n", szTypeName, GetLastError());
	}
	delete[] ReCa<BYTE *>(children);
	return result;
}

DWORD SYMBOL_PARSER::GetFieldOffsetAny(const char * const * TypeNames, size_t TypeCount, const char * szFieldName, DWORD & OffsetOut)
{
	OffsetOut = 0;
	if (!TypeNames || !TypeCount || !szFieldName || !szFieldName[0])
	{
		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}
	for (size_t i = 0; i < TypeCount; ++i)
	{
		if (!TypeNames[i] || !TypeNames[i][0])
		{
			continue;
		}
		DWORD off = 0;
		// Each GetFieldOffset manages its own ULTRA region; no END here on retry.
		if (GetFieldOffset(TypeNames[i], szFieldName, off) == SYMBOL_ERR_SUCCESS)
		{
			OffsetOut = off;
			LOG(2, "SYMBOL_PARSER: %s::%s resolved via %s\n", TypeNames[i], szFieldName, TypeNames[i]);
			return SYMBOL_ERR_SUCCESS;
		}
	}
	return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
}

DWORD SYMBOL_PARSER::GetTypeSizeAny(const char * const * TypeNames, size_t TypeCount, ULONG64 & SizeOut)
{
	SizeOut = 0;
	if (!TypeNames || !TypeCount)
	{
		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}
	for (size_t i = 0; i < TypeCount; ++i)
	{
		if (!TypeNames[i] || !TypeNames[i][0])
		{
			continue;
		}
		ULONG64 sz = 0;
		if (GetTypeSize(TypeNames[i], sz) == SYMBOL_ERR_SUCCESS)
		{
			SizeOut = sz;
			return SYMBOL_ERR_SUCCESS;
		}
	}
	return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
}

DWORD SYMBOL_PARSER::GetEnumValueAny(const char * const * TypeNames, size_t TypeCount, const char * szConstantName, DWORD & ValueOut)
{
	ValueOut = 0;
	if (!m_bReady || !TypeNames || !TypeCount || !szConstantName || !szConstantName[0])
	{
		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}
	wchar_t want_w[128]{ 0 };
	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szConstantName, -1, want_w, _countof(want_w)) <= 0)
	{
		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}
	for (size_t t = 0; t < TypeCount; ++t)
	{
		if (!TypeNames[t] || !TypeNames[t][0])
		{
			continue;
		}
		DWORD64 type_id64 = 0;
		if (GetTypeId(TypeNames[t], type_id64) != SYMBOL_ERR_SUCCESS)
		{
			continue;
		}
		const ULONG type_id = static_cast<ULONG>(type_id64);
		DWORD child_count = 0;
		if (!SymGetTypeInfo(m_hProcess, m_SymbolTable, type_id, TI_GET_CHILDRENCOUNT, &child_count))
		{
			continue;
		}
		if (!child_count || child_count > 512)
		{
			continue;
		}
		const size_t alloc_size = sizeof(TI_FINDCHILDREN_PARAMS) + (static_cast<size_t>(child_count) - 1) * sizeof(ULONG);
		TI_FINDCHILDREN_PARAMS * children = ReCa<TI_FINDCHILDREN_PARAMS *>(new(std::nothrow) BYTE[alloc_size]());
		if (!children)
		{
			continue;
		}
		children->Count = child_count;
		children->Start = 0;
		bool found = false;
		if (SymGetTypeInfo(m_hProcess, m_SymbolTable, type_id, TI_FINDCHILDREN, children))
		{
			for (ULONG i = 0; i < children->Count && !found; ++i)
			{
				WCHAR * child_name = nullptr;
				if (!SymGetTypeInfo(m_hProcess, m_SymbolTable, children->ChildId[i], TI_GET_SYMNAME, &child_name))
				{
					continue;
				}
				const bool match = child_name && _wcsicmp(child_name, want_w) == 0;
				if (child_name)
				{
					LocalFree(child_name);
				}
				if (!match)
				{
					continue;
				}
				VARIANT value{};
				VariantInit(&value);
				if (SymGetTypeInfo(m_hProcess, m_SymbolTable, children->ChildId[i], TI_GET_VALUE, &value))
				{
					DWORD v = 0;
					if (value.vt == VT_I4) v = static_cast<DWORD>(value.lVal);
					else if (value.vt == VT_UI4) v = value.ulVal;
					else if (value.vt == VT_I8) v = static_cast<DWORD>(value.llVal);
					else if (value.vt == VT_UI8) v = static_cast<DWORD>(value.ullVal);
					else if (value.vt == VT_INT) v = static_cast<DWORD>(value.intVal);
					else if (value.vt == VT_UINT) v = value.uintVal;
					else
					{
						VariantClear(&value);
						continue;
					}
					VariantClear(&value);
					ValueOut = v;
					LOG(2, "SYMBOL_PARSER: %s::%s = %lu\n", TypeNames[t], szConstantName, v);
					found = true;
				}
				else
				{
					VariantClear(&value);
				}
			}
		}
		delete[] ReCa<BYTE *>(children);
		if (found)
		{
			return SYMBOL_ERR_SUCCESS;
		}
	}
	return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
}

void SYMBOL_PARSER::Cleanup()
{
	LOG(1, "SYMBOL_PARSER::Cleanup\n");

	m_bReady = false;

	if (m_bInitialized)
	{
		if (m_SymbolTable)
		{
			SymUnloadModule64(m_hProcess, m_SymbolTable);

			m_SymbolTable = 0;
		}

		SymCleanup(m_hProcess);

		m_bInitialized = false;
	}

	if (m_hProcess)
	{
		CloseHandle(m_hProcess);

		m_hProcess = nullptr;
	}

}