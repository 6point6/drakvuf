#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum PPM_IDLE_BUCKET_TIME_TYPE
{
    PpmIdleBucketTimeInQpc = 0,
    PpmIdleBucketTimeIn100ns = 1,
    PpmIdleBucketTimeMaximum = 2
}; 