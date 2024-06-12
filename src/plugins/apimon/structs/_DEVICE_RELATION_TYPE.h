#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _DEVICE_RELATION_TYPE
{
    BusRelations = 0,
    EjectionRelations = 1,
    PowerRelations = 2,
    RemovalRelations = 3,
    TargetDeviceRelation = 4,
    SingleBusRelations = 5,
    TransportRelations = 6
}; 