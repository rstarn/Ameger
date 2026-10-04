 #pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Foundation/Error.h"
#include "Core/Utility/Tools/Tools.h"
#include "Injection/ManualMapping/ManualMappingInternal.h"


namespace MMAP_NATIVE
{
	DWORD ManualMap(const INJECTION_SOURCE & DllPath, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);
}