#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Execution/Routine/StartRoutine.h"

DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, LAUNCH_METHOD Method, DWORD Flags, DWORD & Out, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE || !pRoutine)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_ERR_INVALID_LAUNCH_METHOD;
	}

	DWORD Ret = 0;

	switch (Method)
	{
		case LAUNCH_METHOD::LM_HijackThread:
			Ret = SR_HijackThread(hTargetProc, pRoutine, pArg, Out, Timeout, Flags, SponsorThread, SponsorTid, error_data);
			break;

		default:
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			Ret = SR_ERR_INVALID_LAUNCH_METHOD;
			break;
	}

	return Ret;
}