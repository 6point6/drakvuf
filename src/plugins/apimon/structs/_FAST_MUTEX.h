#pragma once

#include "WinTypes.h"
#include "_KEVENT.h"

//0x38 bytes (sizeof)
struct _FAST_MUTEX
{
    LONG Count;                                                             //0x0
    VOID* Owner;                                                            //0x8
    ULONG Contention;                                                       //0x10
    struct _KEVENT Event;                                                   //0x18
    ULONG OldIrql;                                                          //0x30
}; 