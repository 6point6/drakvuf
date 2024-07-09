#pragma once

#include "WinTypes.h"
#include "_RTL_BALANCED_NODE.h"

//0x10 bytes (sizeof)
struct _RTL_RB_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
    union
    {
        UCHAR Encoded:1;                                                    //0x8
        struct _RTL_BALANCED_NODE* Min;                                     //0x8
    };
}; 