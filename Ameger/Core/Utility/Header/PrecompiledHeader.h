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

#define __FILENAMEW__ (wcsrchr(__FILEW__, L'\\') ? wcsrchr(__FILEW__, L'\\') + 1 : __FILEW__)

#define ALIGN_8 __declspec(align(8))
#define ALIGN ALIGN_8

#define DEBUG_INFO
#define CUSTOM_PRINT

using f_raw_print_callback = void(__stdcall *)(const char * szText);
inline std::atomic<f_raw_print_callback> g_print_raw_callback{nullptr};

void custom_print(int indention_offset, const char * format, ...);

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print);

#define LOG custom_print