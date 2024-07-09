#pragma once

#include "WinTypes.h"
#include "_HANDLE_TRACE_DB_ENTRY.h"
#include "_FAST_MUTEX.h"

//0xf0 bytes (sizeof)
struct _HANDLE_TRACE_DEBUG_INFO
{
    LONG RefCount;                                                          //0x0
    ULONG TableSize;                                                        //0x4
    ULONG BitMaskFlags;                                                     //0x8
    struct _FAST_MUTEX CloseCompactionLock;                                 //0x10
    ULONG CurrentStackIndex;                                                //0x48
    struct _HANDLE_TRACE_DB_ENTRY TraceDb[1];                               //0x50
}; 