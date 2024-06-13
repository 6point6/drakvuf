#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _PO_FX_PERF_STATE_UNIT
{
    PoFxPerfStateUnitOther = 0,
    PoFxPerfStateUnitFrequency = 1,
    PoFxPerfStateUnitBandwidth = 2,
    PoFxPerfStateUnitMaximum = 3
}; 