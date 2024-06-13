#pragma once

#include "WinTypes.h"
#include "_KPROCESS.h"
#include "_LIST_ENTRY.h"

//0x30 bytes (sizeof)
struct _KAPC_STATE
{
    struct _LIST_ENTRY ApcListHead[2];                                      //0x0
    struct _KPROCESS* Process;                                              //0x20
    union
    {
        UCHAR InProgressFlags;                                              //0x28
        struct
        {
            UCHAR KernelApcInProgress:1;                                    //0x28
            UCHAR SpecialApcInProgress:1;                                   //0x28
        };
    };
    UCHAR KernelApcPending;                                                 //0x29
    union
    {
        UCHAR UserApcPendingAll;                                            //0x2a
        struct
        {
            UCHAR SpecialUserApcPending:1;                                  //0x2a
            UCHAR UserApcPending:1;                                         //0x2a
        };
    };
}; 