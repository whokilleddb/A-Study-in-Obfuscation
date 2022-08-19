#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winuser.h>
#include "obfuscators.h"

#pragma comment (lib, "User32.lib")


/// Check for Sleep patching by accelrated time
///
/// Returns
/// TRUE  - No Sleep Patching
/// FALSE - Sleep patching  
BOOL QYyuqVKHPv54(){    
    DWORD startCount = _GetTickCount();
    _Sleep(INTERVAL);
    DWORD endCount = _GetTickCount();

    DWORD timeSpan = endCount - startCount;
    if ((L_INTERVAL > timeSpan) && (timeSpan > U_INTERVAL)){
        return FALSE;
    }
    
    return TRUE;
}


/// Check for user activity
///
/// Returns
/// TRUE  - If user activity is detected via mouse movement
/// FALSE - If no mouse movement is observed
int CSipwtXlcS51(){
    int __infinity_loop = 0;
    POINT p1, p2;
    BOOL res1, res2;
    HDESK desktop_handle;

    // Switch to input desktop if different from current one
    desktop_handle = _OpenInputDesktop(0, TRUE, GENERIC_READ);
    _SetThreadDesktop(desktop_handle);

    // The GetCurorPos() can fail at times so just retry it 5 times and 
    // if it still fails, then exit out with an error code
    while(1){
        res1 = _GetCursorPos(&p1);
        if (res1) break;
        _Sleep(INTERVAL);
        __infinity_loop += 1;
        if (__infinity_loop == 5) return FALSE;
    }
    __infinity_loop = 0;
    _Sleep(INTERVAL*10);

    while(1){
        res2 = _GetCursorPos(&p2);
        if (res2) break;
        _Sleep(INTERVAL);
        __infinity_loop += 1;
        if (__infinity_loop == 5) return FALSE;
    }

    if (res1 && res2){
        if (p1.x==p2.x || p1.y == p2.y || ((p1.x-p2.x)==(p1.y-p2.y))){
            return FALSE;
        }
        else {
            return TRUE;
        }
    }
    else{
        return FALSE;
    }

}

/// Check for Sandboxes
int wUtMwCHxxt10(){
    BOOL __sleep_patch = QYyuqVKHPv54();
    BOOL __cursor_activity = CSipwtXlcS51();    
    
    if (__sleep_patch && __cursor_activity){
        return 0;
    }

    return -1;
}
