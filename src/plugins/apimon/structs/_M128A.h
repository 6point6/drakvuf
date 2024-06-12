#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _M128A
{
    ULONGLONG Low;                                                          //0x0
    LONGLONG High;                                                          //0x8
}; 