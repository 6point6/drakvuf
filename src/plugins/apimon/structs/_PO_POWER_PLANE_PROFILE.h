#pragma once

#include "WinTypes.h"


//0x8 bytes (sizeof)
struct _PO_POWER_PLANE_PROFILE
{
    ULONG ExclusivePowerMw;                                                 //0x0
    ULONG PeakPowerMw;                                                      //0x4
}; 