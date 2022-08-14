#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winuser.h>
#pragma comment (lib, "User32.lib")

/// User defined PPDs
#define L_INTERVAL  950    // Lower Time Limit
#define INTERVAL    1000   // Mean  Time Limit
#define U_INTERVAL  1050   // Upper Time Limit

/// Check for Sleep patching by accelrated time
///
/// Returns
///  0 - No Sleep Patching
/// -1 - Sleep patching  
BOOL __check_sleep_patch(){
    DWORD startCount = GetTickCount();
    Sleep(INTERVAL);
    DWORD endCount = GetTickCount();

    DWORD timeSpan = endCount - startCount;
    if ((L_INTERVAL > timeSpan) && (timeSpan > U_INTERVAL)){
        return FALSE;
    }
    
    return TRUE;
}


int __check_cursor_activity(){
    int __infinity_loop = 0;
    POINT p1, p2;
    BOOL res1, res2;
    HDESK desktop_handle;

    // Switch to input desktop if different from current one
    desktop_handle = OpenInputDesktop(0, TRUE, GENERIC_READ);
    SetThreadDesktop(desktop_handle);


    // The GetCurorPos() can fail at times so just retry it 5 times and 
    // if it still fails, then exit out with an error code
    while(1){
        res1 = GetCursorPos(&p1);
        if (res1) break;
        Sleep(INTERVAL);
        __infinity_loop += 1;
        if (__infinity_loop == 5) return FALSE;
    }
    __infinity_loop = 0;
    Sleep(INTERVAL*10);

    while(1){
        res2 = GetCursorPos(&p2);
        if (res2) break;
        Sleep(INTERVAL);
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
int check_sandbox(){
    BOOL __sleep_patch = __check_sleep_patch();
    BOOL __cursor_activity = __check_cursor_activity();    
    
    if (__sleep_patch && __cursor_activity){
        return 0;
    }

    return -1;
}
