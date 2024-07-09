#pragma once

#include "WinTypes.h"
#include "_GENERAL_LOOKASIDE_POOL.h"

//0x60 bytes (sizeof)
struct _LOOKASIDE_LIST_EX
{
    struct _GENERAL_LOOKASIDE_POOL L;                                       //0x0
}; 