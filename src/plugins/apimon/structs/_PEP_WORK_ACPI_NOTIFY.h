#pragma once

#include "WinTypes.h"
#include "POHANDLE__.h"

//0x10 bytes (sizeof)
struct _PEP_WORK_ACPI_NOTIFY
{
    struct POHANDLE__* DeviceHandle;                                        //0x0
    ULONG NotifyCode;                                                       //0x8
}; 