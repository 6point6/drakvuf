#pragma once

#include "WinTypes.h"
#include "_MDL.h"
#include "_EPROCESS.h"

//0x30 bytes (sizeof)
struct _MDL
{
    struct _MDL* Next;                                                      //0x0
    SHORT Size;                                                             //0x8
    SHORT MdlFlags;                                                         //0xa
    struct _EPROCESS* Process;                                              //0x10
    VOID* MappedSystemVa;                                                   //0x18
    VOID* StartVa;                                                          //0x20
    ULONG ByteCount;                                                        //0x28
    ULONG ByteOffset;                                                       //0x2c
}; 