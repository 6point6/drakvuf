#pragma once

#include "WinTypes.h"


//0x18 bytes (sizeof)
struct _PPM_COORDINATED_SELECTION
{
    ULONG MaximumStates;                                                    //0x0
    ULONG SelectedStates;                                                   //0x4
    ULONG DefaultSelection;                                                 //0x8
    ULONG* Selection;                                                       //0x10
}; 