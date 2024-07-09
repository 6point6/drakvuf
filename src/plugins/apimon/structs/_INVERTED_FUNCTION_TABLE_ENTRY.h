#pragma once

#include "WinTypes.h"
#include "_DYNAMIC_FUNCTION_TABLE.h"
#include "_IMAGE_RUNTIME_FUNCTION_ENTRY.h"

//0x18 bytes (sizeof)
struct _INVERTED_FUNCTION_TABLE_ENTRY
{
    union
    {
        struct _IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;                //0x0
        struct _DYNAMIC_FUNCTION_TABLE* DynamicTable;                       //0x0
    };
    VOID* ImageBase;                                                        //0x8
    ULONG SizeOfImage;                                                      //0x10
    ULONG SizeOfTable;                                                      //0x14
}; 