#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _IO_ALLOCATION_ACTION
{
    KeepObject = 1,
    DeallocateObject = 2,
    DeallocateObjectKeepRegisters = 3
}; 