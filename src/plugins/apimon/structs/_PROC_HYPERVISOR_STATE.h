#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _PROC_HYPERVISOR_STATE
{
    ProcHypervisorNone = 0,
    ProcHypervisorPresent = 1,
    ProcHypervisorPower = 2,
    ProcHypervisorHvCounters = 3
}; 