#pragma once

#include "WinTypes.h"
#include "_KDPC.h"
#include "_LIST_ENTRY.h"
#include "_ULARGE_INTEGER.h"
#include "_DISPATCHER_HEADER.h"

//0x40 bytes (sizeof)
struct _KTIMER
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    union _ULARGE_INTEGER DueTime;                                          //0x18
    struct _LIST_ENTRY TimerListEntry;                                      //0x20
    struct _KDPC* Dpc;                                                      //0x30
    USHORT Processor;                                                       //0x38
    USHORT TimerType;                                                       //0x3a
    ULONG Period;                                                           //0x3c
}; 