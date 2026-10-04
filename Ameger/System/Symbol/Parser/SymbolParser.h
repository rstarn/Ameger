#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Symbol/Loader/SymbolLoader.h"

class SYMBOL_PARSER
{
	HANDLE m_hProcess		= NULL;
	bool m_bInitialized		= false;
	bool m_bReady			= false;
	DWORD64 m_SymbolTable	= 0;

	SYMBOL_PARSER(const SYMBOL_PARSER &) = delete;
	SYMBOL_PARSER & operator=(const SYMBOL_PARSER &) = delete;

public:

	SYMBOL_PARSER();
	~SYMBOL_PARSER();

	DWORD Initialize(const SYMBOL_LOADER * pSymbolObject);
	void Cleanup();

	DWORD GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut);

	// PDB type queries: every Windows struct offset is resolved from the
	// downloaded ntdll.pdb instead of a hardcoded constant. All three are
	// fail-closed (non-zero SYMBOL_ERR_* when the type/field is absent).
	DWORD GetTypeId(const char * szTypeName, DWORD64 & TypeIdOut);
	DWORD GetTypeSize(const char * szTypeName, ULONG64 & SizeOut);
	DWORD GetFieldOffset(const char * szTypeName, const char * szFieldName, DWORD & OffsetOut);
	// Try several PDB spellings in order (e.g. "TEB", "_TEB"); first hit wins.
	DWORD GetFieldOffsetAny(const char * const * TypeNames, size_t TypeCount, const char * szFieldName, DWORD & OffsetOut);
	DWORD GetTypeSizeAny(const char * const * TypeNames, size_t TypeCount, ULONG64 & SizeOut);
	// Enum constant (e.g. _KTHREAD_STATE::Running). Tries each type spelling.
	DWORD GetEnumValueAny(const char * const * TypeNames, size_t TypeCount, const char * szConstantName, DWORD & ValueOut);
};

inline SYMBOL_PARSER sym_parser;