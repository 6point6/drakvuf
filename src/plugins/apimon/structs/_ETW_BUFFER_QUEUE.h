#pragma once

#include "WinTypes.h"
#include "_SINGLE_LIST_ENTRY.h"

//0x10 bytes (sizeof)
struct _ETW_BUFFER_QUEUE
{
    struct _SINGLE_LIST_ENTRY* QueueTail;                                   //0x0
    struct _SINGLE_LIST_ENTRY QueueEntry;                                   //0x8
}; 