#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3
}; 