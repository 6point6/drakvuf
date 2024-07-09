#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _PNP_DEVNODE_QUERY_REBALANCE_VETO_REASON
{
    DeviceQueryRebalanceSucceeded = 0,
    DeviceQueryStopFailed = 1,
    DeviceFailedGetNewResourceRequirement = 2,
    DeviceInUnexpectedState = 3,
    DeviceNotSupportQueryRebalance = 4
}; 