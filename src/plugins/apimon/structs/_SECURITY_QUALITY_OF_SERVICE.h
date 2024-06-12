#pragma once

#include "WinTypes.h"
#include "_SECURITY_IMPERSONATION_LEVEL.h"

//0xc bytes (sizeof)
struct _SECURITY_QUALITY_OF_SERVICE
{
    ULONG Length;                                                           //0x0
    enum _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;                  //0x4
    UCHAR ContextTrackingMode;                                              //0x8
    UCHAR EffectiveOnly;                                                    //0x9
}; 