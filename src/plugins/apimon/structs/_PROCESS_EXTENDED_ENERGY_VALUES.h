#pragma once

#include "WinTypes.h"
#include "_PROCESS_ENERGY_VALUES_EXTENSION.h"
#include "_PROCESS_ENERGY_VALUES.h"

//0x1b0 bytes (sizeof)
struct _PROCESS_EXTENDED_ENERGY_VALUES
{
    struct _PROCESS_ENERGY_VALUES Base;                                     //0x0
    struct _PROCESS_ENERGY_VALUES_EXTENSION Extension;                      //0x110
}; 