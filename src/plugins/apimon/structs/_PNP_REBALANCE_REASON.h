#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _PNP_REBALANCE_REASON
{
    RebalanceReasonUnknown = 0,
    RebalanceReasonRequirementsChanged = 1,
    RebalanceReasonNewDevice = 2
}; 