#pragma once

#include "WinTypes.h"
#include "_OBJECT_DIRECTORY_ENTRY.h"

//0x18 bytes (sizeof)
struct _OBJECT_DIRECTORY_ENTRY
{
    struct _OBJECT_DIRECTORY_ENTRY* ChainLink;                              //0x0
    VOID* Object;                                                           //0x8
    ULONG HashValue;                                                        //0x10
}; 