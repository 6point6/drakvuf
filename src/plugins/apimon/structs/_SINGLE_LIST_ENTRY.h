#pragma once

#include "WinTypes.h"
#include "_SINGLE_LIST_ENTRY.h"

//0x8 bytes (sizeof)
struct _SINGLE_LIST_ENTRY
{
    struct _SINGLE_LIST_ENTRY* Next;                                        //0x0
}; 