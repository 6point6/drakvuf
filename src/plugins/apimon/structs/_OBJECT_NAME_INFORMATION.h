#pragma once

#include "WinTypes.h"
#include "_UNICODE_STRING.h"

//0x10 bytes (sizeof)
struct _OBJECT_NAME_INFORMATION
{
    struct _UNICODE_STRING Name;                                            //0x0
}; 