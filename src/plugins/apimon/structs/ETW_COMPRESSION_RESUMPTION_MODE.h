#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum ETW_COMPRESSION_RESUMPTION_MODE
{
    EtwCompressionModeRestart = 0,
    EtwCompressionModeNoDisable = 1,
    EtwCompressionModeNoRestart = 2
}; 