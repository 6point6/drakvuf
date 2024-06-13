#pragma once

#include "WinTypes.h"
#include "_PPM_VETO_ENTRY.h"
#include "_LIST_ENTRY.h"

//0x28 bytes (sizeof)
struct _PPM_VETO_ACCOUNTING
{
    volatile LONG VetoPresent;                                              //0x0
    struct _LIST_ENTRY VetoListHead;                                        //0x8
    UCHAR CsAccountingBlocks;                                               //0x18
    UCHAR BlocksDrips;                                                      //0x19
    ULONG PreallocatedVetoCount;                                            //0x1c
    struct _PPM_VETO_ENTRY* PreallocatedVetoList;                           //0x20
}; 