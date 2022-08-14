#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/// User defined PPDs
#define L_INTERVAL  950    // Lower Time Limit
#define INTERVAL    1000   // Mean  Time Limit
#define U_INTERVAL  1050   // Upper Time Limit

/// Check for Sleep patching by accelrated time
///
/// Returns
///  0 - No Sleep Patching
/// -1 - Sleep patching  
int __check_sleep_patch(){
    DWORD startCount = GetTickCount();
    Sleep(INTERVAL);
    DWORD endCount = GetTickCount();

    DWORD timeSpan = endCount - startCount;
    if ((L_INTERVAL > timeSpan) && (timeSpan > U_INTERVAL)){
        return 0;
    }
    
    return 0;
}

/// Check for Sandboxes
int check_sandbox(){
    int __sleep_patch = __check_sleep_patch();
    
    return __sleep_patch;
}
