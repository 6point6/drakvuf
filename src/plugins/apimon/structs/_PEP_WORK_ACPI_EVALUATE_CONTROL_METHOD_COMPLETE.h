#pragma once

#include "WinTypes.h"
#include "POHANDLE__.h"
#include "_ACPI_METHOD_ARGUMENT_V1.h"

//0x28 bytes (sizeof)
struct _PEP_WORK_ACPI_EVALUATE_CONTROL_METHOD_COMPLETE
{
    struct POHANDLE__* DeviceHandle;                                        //0x0
    ULONG CompletionFlags;                                                  //0x8
    LONG MethodStatus;                                                      //0xc
    VOID* CompletionContext;                                                //0x10
    ULONGLONG OutputArgumentSize;                                           //0x18
    struct _ACPI_METHOD_ARGUMENT_V1* OutputArguments;                       //0x20
}; 