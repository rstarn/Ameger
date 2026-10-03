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
};

inline SYMBOL_PARSER sym_parser;