#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Injection/Injection.h"
#include "System/Import/ImportHandler.h"

namespace
{
	volatile LONG g_RuntimeInitializationState = 0;

	void CloseEventHandle(HANDLE & handle)
	{
		if (handle)
		{
			CloseHandle(handle);
			handle = nullptr;
		}
	}

	void CloseRuntimeEvents()
	{
		CloseEventHandle(g_hRunningEvent);
		CloseEventHandle(g_hInterruptEvent);
		CloseEventHandle(g_hInterruptedEvent);
		CloseEventHandle(g_hInterruptImport);
	}

	DWORD RuntimeInitializationFailed(DWORD error_code)
	{
		CloseRuntimeEvents();
		InterlockedExchange(&g_RuntimeInitializationState, 3);

		return error_code;
	}
}

DWORD __stdcall InitializeRuntime()
{
#pragma EXPORT_FUNCTION("CoreStart", __FUNCDNAME__)

	const LONG previous_state = InterlockedCompareExchange(&g_RuntimeInitializationState, 1, 0);
	if (previous_state == 2)
	{
		return INJ_ERR_SUCCESS;
	}
	if (previous_state == 1)
	{
		return INJ_ERR_ALREADY_RUNNING;
	}
	if (previous_state != 0)
	{
		return INJ_ERR_NOT_IMPLEMENTED;
	}

	if (!GetOSVersion())
	{
		return RuntimeInitializationFailed(INJ_ERR_WINDOWS_VERSION);
	}

	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		return RuntimeInitializationFailed(INJ_ERR_WINDOWS_BUILD_UNSUPPORTED);
	}

	if (!GetOwnModulePathW(g_RootPathW))
	{
		LOG(0, "Couldn't resolve own module path (unicode)\n");

		return RuntimeInitializationFailed(INJ_ERR_CANT_GET_MODULE_PATH);
	}

	g_hRunningEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptedEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptImport = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	if (!g_hRunningEvent || !g_hInterruptEvent || !g_hInterruptedEvent || !g_hInterruptImport)
	{
		LOG(0, "Failed to create synchronization events: %08X\n", GetLastError());

		return RuntimeInitializationFailed(INJ_ERR_OUT_OF_MEMORY_EXT);
	}

	wchar_t * windows_directory = nullptr;
	if (_wdupenv_s(&windows_directory, nullptr, XOR_STR_W(L"WINDIR").get()) || !windows_directory)
	{
		LOG(0, "Couldn't resolve %%WINDIR%%\n");

		return RuntimeInitializationFailed(INJ_ERR_CANT_GET_TEMP_DIR);
	}

	std::wstring native_ntdll_path = windows_directory;
	{
		// Raw L"\\System32\\ntdll.dll" here survived into .rdata as UTF-16 and
		// tripped the 'ntdll.dll' marker in the interface gate. KC_WSTR is the
		// block-scoped expression form, so it introduces no name to collide.
		auto suffix = KC_WSTR(L"\\System32\\ntdll.dll");
		native_ntdll_path += suffix.c_str();
	}
	free(windows_directory);

	// Symbol cache lives in a neutral per-user directory, never beside the
	// runtime DLL: a large ntdll.pdb next to the injector is a loud artifact.
	std::wstring symbol_cache_root;
	if (!GetSymbolCacheRoot(symbol_cache_root))
	{
		symbol_cache_root = g_RootPathW;   // fall back to the module directory
	}

	try
	{
		// Lambda, not &SYMBOL_LOADER::Initialize: a member-pointer async
		// instantiation bakes the class name into mangled template symbols
		// (Fake_no_copy_callable_adapter@P8SYMBOL_LOADER@@...) that persist
		// in .rdata. The lambda's mangled name carries only this free
		// function's scope, which is ungated noise. Globals need no capture.
		sym_ntdll_native_ret = std::async(std::launch::async,
			[native_ntdll_path, symbol_cache_root]() {
				return sym_ntdll_native.Initialize(native_ntdll_path, symbol_cache_root, nullptr, false, true, false);
			});
		import_handler_ret = std::async(std::launch::async, &ResolveImports, std::ref(import_handler_error_data));
	}
	catch (...)
	{
		LOG(0, "Runtime initialization failed while launching worker threads\n");

		sym_ntdll_native.Interrupt();
		SetEvent(g_hInterruptEvent);
		SetEvent(g_hInterruptImport);

		if (sym_ntdll_native_ret.valid())
		{
			sym_ntdll_native_ret.wait();
		}
		if (import_handler_ret.valid())
		{
			import_handler_ret.wait();
		}

		return RuntimeInitializationFailed(INJ_ERR_OUT_OF_MEMORY_NEW);
	}

	InterlockedExchange(&g_RuntimeInitializationState, 2);
	LOG(0, "Runtime initialization started\n");

	return INJ_ERR_SUCCESS;
}

DWORD __stdcall ShutdownRuntime()
{
#pragma EXPORT_FUNCTION("CoreStop", __FUNCDNAME__)

	const LONG state = InterlockedCompareExchange(&g_RuntimeInitializationState, 1, 0);
	if (state == 0)
	{
		InterlockedExchange(&g_RuntimeInitializationState, 4);

		return INJ_ERR_SUCCESS;
	}
	if (state == 1)
	{
		return INJ_ERR_ALREADY_RUNNING;
	}
	if (state == 4)
	{
		return INJ_ERR_SUCCESS;
	}
	if (state == 3)
	{
		CloseRuntimeEvents();
		InterlockedExchange(&g_RuntimeInitializationState, 4);

		return INJ_ERR_SUCCESS;
	}
	if (state != 2 || InterlockedCompareExchange(&g_InjectionGate, 0, 0) != 0)
	{
		InterlockedExchange(&g_RuntimeInitializationState, 2);

		return INJ_ERR_ALREADY_RUNNING;
	}

	sym_ntdll_native.Interrupt();
	SetEvent(g_hInterruptEvent);
	SetEvent(g_hInterruptImport);

	try
	{
		if (sym_ntdll_native_ret.valid())
		{
			sym_ntdll_native_ret.wait();
		}
		if (import_handler_ret.valid())
		{
			import_handler_ret.wait();
		}
	}
	catch (...)
	{
		InterlockedExchange(&g_RuntimeInitializationState, 2);

		return INJ_ERR_INTERRUPT;
	}

	sym_ntdll_native.Cleanup();
	sym_parser.Cleanup();
	CloseRuntimeEvents();

	InterlockedExchange(&g_RuntimeInitializationState, 4);

	return INJ_ERR_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hInjMod = hDll;
		DisableThreadLibraryCalls(hDll);
	}

	// Unloading this module cannot be blocked from DllMain: the loader ignores
	// the return value for DLL_PROCESS_DETACH (and DisableThreadLibraryCalls
	// above suppresses the DLL_THREAD_* notifications). The interface avoids
	// the situation rather than fighting it - it never calls FreeLibrary on the
	// runtime; it shuts the workers down and exits the process
	// (TerminateProcess), so the module is torn down with the address space.
	return TRUE;
}
