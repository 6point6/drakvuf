#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _PEP_WORK_TYPE
{
    PepWorkActiveComplete = 0,
    PepWorkRequestIdleState = 1,
    PepWorkDevicePower = 2,
    PepWorkRequestPowerControl = 3,
    PepWorkDeviceIdle = 4,
    PepWorkCompleteIdleState = 5,
    PepWorkCompletePerfState = 6,
    PepWorkAcpiNotify = 7,
    PepWorkAcpiEvaluateControlMethodComplete = 8,
    PepWorkMax = 9
}; 