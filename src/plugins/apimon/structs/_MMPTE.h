#pragma once

#include "WinTypes.h"
#include "_MMPTE_HARDWARE.h"
#include "_MMPTE_SOFTWARE.h"
#include "_MMPTE_PROTOTYPE.h"
#include "_MMPTE_LIST.h"
#include "_MMPTE_SUBSECTION.h"
#include "_MMPTE_TIMESTAMP.h"
#include "_MMPTE_TRANSITION.h"

//0x8 bytes (sizeof)
struct _MMPTE
{
    union
    {
        ULONGLONG Long;                                                     //0x0
        volatile ULONGLONG VolatileLong;                                    //0x0
        struct _MMPTE_HARDWARE Hard;                                        //0x0
        struct _MMPTE_PROTOTYPE Proto;                                      //0x0
        struct _MMPTE_SOFTWARE Soft;                                        //0x0
        struct _MMPTE_TIMESTAMP TimeStamp;                                  //0x0
        struct _MMPTE_TRANSITION Trans;                                     //0x0
        struct _MMPTE_SUBSECTION Subsect;                                   //0x0
        struct _MMPTE_LIST List;                                            //0x0
    } u;                                                                    //0x0
}; 