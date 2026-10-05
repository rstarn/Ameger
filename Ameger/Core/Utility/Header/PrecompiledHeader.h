#pragma once

#ifndef _WIN64
#error This build is x64-only: 32-bit / WOW64 support has been eradicated (ManualMap + HijackThread only).
#endif

#include <Windows.h>
#include "Core/Foundation/Primitives/InjectionTypes.h"
#include "Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "Core/Foundation/Primitives/KcStrings/Core/KcStrSuite.h"

#include <atomic>

#if defined(NTDDI_VERSION) && (NTDDI_VERSION < NTDDI_WIN11)
#error The mininum requirement for this library is Windows 11.
#endif

#if __has_include(<format>)
#include <format>
#endif
#include <iomanip>
#include <sstream>
#include <string>
#include <tchar.h>

#include <fstream>
#include <shlwapi.h>

#include <ctime>
#include <chrono>
#include <map>
#include <memory>
#include <random>

#include <vector>

#include <DbgHelp.h>
#include <future>

#include <WinInet.h>
#include <Urlmon.h>

#pragma warning(disable: 4201) 
#pragma warning(disable: 4324) 
#pragma warning(disable: 6001) 
#pragma warning(disable: 6258) 
#pragma warning(disable: 28159) 

#define ReCa reinterpret_cast

#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)

#define EXPORT_FUNCTION(export_name, link_name) comment(linker, "/EXPORT:" export_name "=" link_name)

// Stealth: never embed compile-time paths or function names in .rdata.
// __FILEW__ expands to the full build-machine path per TU and would linger
// in the binary even when stripped at runtime via wcsrchr. Same for
// __FUNCTIONW__ (internal names). Error telemetry keeps Line + codes only.
#define __FILENAMEW__ (L"")

#define ALIGN_8 __declspec(align(8))
#define ALIGN ALIGN_8

#define DEBUG_INFO
#define CUSTOM_PRINT

using f_raw_print_callback = void(__stdcall *)(const char * szText);
inline std::atomic<f_raw_print_callback> g_print_raw_callback{nullptr};

void custom_print(int indention_offset, const char * format, ...);

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print);

// Stealth: runtime LOG format strings would otherwise persist as plaintext
// in .rdata (muted at runtime via QuietPrint, but on disk regardless).
// Shipped builds compile logs out entirely; define AMEGER_KEEP_RUNTIME_LOGS
// for a debug build that needs the print-callback trace.
#ifdef AMEGER_KEEP_RUNTIME_LOGS
#define LOG custom_print
#else
#define LOG(...) ((void)0)
#endif