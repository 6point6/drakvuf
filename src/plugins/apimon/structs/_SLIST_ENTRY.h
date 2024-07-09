#pragma once

#include "WinTypes.h"
#include "_SLIST_ENTRY.h"

//0x10 bytes (sizeof)
struct _SLIST_ENTRY
{
    struct _SLIST_ENTRY* Next;                                              //0x0
}; 