#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _SECURITY_IMPERSONATION_LEVEL
{
    SecurityAnonymous = 0,
    SecurityIdentification = 1,
    SecurityImpersonation = 2,
    SecurityDelegation = 3
}; 