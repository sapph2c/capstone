#include <iostream>
#include <Windows.h>
#include <string>
#include <tchar.h>
#include <timeapi.h>

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

int main(int argc, char* argv[]) {

    // Call the AntiDebug function to check for debugging attempts.
    if (!AntiDebug()) {
        return -1;
    }

    if (argc < 3) {
        printf("Usage: %s <DLL> <PID>\n", argv[0]);
        return 1;
    }

    LPCSTR DllPath = argv[1];
    
    // Parse PID from the command-line arguments.
    DWORD pid = strtol(argv[2], NULL, 10);
    if (pid == 0) return 1;

    // Opening the Process with All Access.
    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (handle == NULL) return 1;

    // Allocate memory for the dllpath in the target process, length of the path string + null terminator.
    SIZE_T dllPathSize = strlen(DllPath) + 1;
    LPVOID pDllPath = VirtualAllocEx(handle, 0, dllPathSize, MEM_COMMIT, PAGE_READWRITE);
    if (pDllPath == NULL) {
        CloseHandle(handle);
        return 1;
    }

    // Write the path to the address of the memory we just allocated in the target process.
    if (!WriteProcessMemory(handle, pDllPath, (LPVOID)DllPath, dllPathSize, 0)) {
        VirtualFreeEx(handle, pDllPath, 0, MEM_RELEASE);
        CloseHandle(handle);
        return 1;
    }

    // Get handle to Kernel32.dll
    HMODULE hHandle = GetModuleHandleA("Kernel32.dll");
    if (hHandle == NULL) {
        VirtualFreeEx(handle, pDllPath, 0, MEM_RELEASE);
        CloseHandle(handle);
        return 1;
    }

    // Create a Remote Thread in the target process which calls LoadLibraryA with our dllpath as an argument -> program loads our dll.
    HANDLE hLoadThread = CreateRemoteThread(handle, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hHandle, "LoadLibraryA"), pDllPath, 0, 0);
    if (hLoadThread == NULL) {
        VirtualFreeEx(handle, pDllPath, 0, MEM_RELEASE);
        CloseHandle(handle);
        return 1;
    }

    // Wait for the execution of our loader thread to finish.
    WaitForSingleObject(hLoadThread, INFINITE);

    // Free the memory allocated for our DLL path.
    VirtualFreeEx(handle, pDllPath, 0, MEM_RELEASE);

    // Close handles
    CloseHandle(hLoadThread);
    CloseHandle(handle);

    return 0;
}

