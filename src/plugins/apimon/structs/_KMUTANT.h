#pragma once

#include "WinTypes.h"
#include "_KTHREAD.h"
#include "_LIST_ENTRY.h"
#include "_DISPATCHER_HEADER.h"

//0x38 bytes (sizeof)
struct _KMUTANT
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY MutantListEntry;                                     //0x18
    struct _KTHREAD* OwnerThread;                                           //0x28
    union
    {
        UCHAR MutantFlags;                                                  //0x30
        struct
        {
            UCHAR Abandoned:1;                                              //0x30
            UCHAR Spare1:7;                                                 //0x30
            UCHAR Abandoned2:1;                                             //0x30
            UCHAR AbEnabled:1;                                              //0x30
            UCHAR Spare2:6;                                                 //0x30
        };
    };
    UCHAR ApcDisable;                                                       //0x31
}; 