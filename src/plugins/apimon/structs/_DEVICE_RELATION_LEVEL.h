#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _DEVICE_RELATION_LEVEL
{
    RELATION_LEVEL_REMOVE_EJECT = 0,
    RELATION_LEVEL_DEPENDENT = 1,
    RELATION_LEVEL_DIRECT_DESCENDANT = 2
}; 