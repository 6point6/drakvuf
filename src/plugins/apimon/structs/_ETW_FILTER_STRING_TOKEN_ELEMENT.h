#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _ETW_FILTER_STRING_TOKEN_ELEMENT
{
    USHORT Length;                                                          //0x0
    WCHAR* String;                                                          //0x8
}; 