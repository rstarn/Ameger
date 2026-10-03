#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Primitives/VmpMarkers.h"
#include "System/Symbol/Parser/SymbolParser.h"

SYMBOL_PARSER::SYMBOL_PARSER()
{

}

SYMBOL_PARSER::~SYMBOL_PARSER()
{
	Cleanup();
}

AMEGER_VMP_NOINLINE DWORD SYMBOL_PARSER::Initialize(const SYMBOL_LOADER * pSymbolObject)
{
	AMEGER_VMP_ULTRA_BEGIN("symp_init");
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

	AMEGER_VMP_ULTRA_END();
	return SYMBOL_ERR_SUCCESS;
}

AMEGER_VMP_NOINLINE DWORD SYMBOL_PARSER::GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut)
{
	AMEGER_VMP_ULTRA_BEGIN("symp_addr");
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

	AMEGER_VMP_ULTRA_END();
	return SYMBOL_ERR_SUCCESS;
}

AMEGER_VMP_NOINLINE void SYMBOL_PARSER::Cleanup()
{
	AMEGER_VMP_ULTRA_BEGIN("symp_cleanup");
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

	AMEGER_VMP_ULTRA_END();
}