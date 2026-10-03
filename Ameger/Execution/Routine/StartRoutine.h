#pragma once

#include "System/Information/ProcessInformation.h"
#include "Core/Utility/Tools/Tools.h"

enum class SR_REMOTE_STATE : ULONG_PTR
{
	SR_RS_ExecutionPending	= 0,
	SR_RS_Executing			= 1,
	SR_RS_ExecutionFinished	= 2
};

using f_Routine			= DWORD(__fastcall *)(void * pArg);

#define SR_REMOTE_DELAY 50

ALIGN struct SR_REMOTE_DATA
{
	ALIGN SR_REMOTE_STATE	State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	ALIGN DWORD				Ret				= 0;
	ALIGN DWORD				LastWin32Error	= 0;
	ALIGN void *			pArg			= nullptr;
	ALIGN f_Routine			pRoutine		= nullptr;
	ALIGN UINT_PTR			Buffer			= 0;
};


static_assert(sizeof(SR_REMOTE_DATA) == 48);
static_assert(offsetof(SR_REMOTE_DATA, Ret) == 8);
static_assert(offsetof(SR_REMOTE_DATA, LastWin32Error) == 16);
static_assert(offsetof(SR_REMOTE_DATA, pArg) == 24);
static_assert(offsetof(SR_REMOTE_DATA, pRoutine) == 32);
static_assert(offsetof(SR_REMOTE_DATA, Buffer) == 40);


extern "C" BYTE RemoteThreadHijackBegin[];
extern "C" BYTE RemoteThreadHijackEnd[];
extern "C" BYTE RemoteThreadReturnTarget[];
extern "C" BYTE RemoteThreadState[];


DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, LAUNCH_METHOD Method, DWORD Flags, DWORD & Out, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);

DWORD SR_HijackThread		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg,							DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);
