#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum PROFILE_DEPARTURE_STYLE
{
    PDS_UPDATE_DEFAULT = 1,
    PDS_UPDATE_ON_REMOVE = 2,
    PDS_UPDATE_ON_INTERFACE = 3,
    PDS_UPDATE_ON_EJECT = 4
}; 