#pragma once

#include "WinTypes.h"
#include "_PO_IRP_QUEUE.h"

//0x20 bytes (sizeof)
struct _PO_IRP_MANAGER
{
    struct _PO_IRP_QUEUE DeviceIrpQueue;                                    //0x0
    struct _PO_IRP_QUEUE SystemIrpQueue;                                    //0x10
}; 