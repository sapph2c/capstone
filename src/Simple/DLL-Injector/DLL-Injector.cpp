#include <iostream>
#include <Windows.h>
#include <string>

using namespace std;

// Utility function to load the DLL into the target process.
int LoadDllIntoProcess(LPCSTR DllPath, DWORD pid) {
    // Open the target process with all access rights (PROCESS_ALL_ACCESS).
    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (handle == NULL) return 1;

    // Allocate memory in the target process for storing the DLL path.
    SIZE_T dllPathSize = strlen(DllPath) + 1;
    LPVOID pDllPath = VirtualAllocEx(handle, 0, dllPathSize, MEM_COMMIT, PAGE_READWRITE);
    if (pDllPath == NULL) {
        CloseHandle(handle);
        return 1;
    }

    // Write the DLL path into the allocated memory in the target process.
    if (!WriteProcessMemory(handle, pDllPath, (LPVOID)DllPath, dllPathSize, 0)) {
        VirtualFreeEx(handle, pDllPath, 0, MEM_RELEASE);
        CloseHandle(handle);
        return 1;
    }

    // Get the handle to Kernel32.dll, which is needed for calling LoadLibraryA.
    HMODULE hHandle = GetModuleHandleA("Kernel32.dll");
    if (hHandle == NULL) {
        VirtualFreeEx(handle, pDllPath, 0, MEM_RELEASE);
        CloseHandle(handle);
        return 1;
    }

    // Create a remote thread in the target process to call LoadLibraryA and load the DLL.
    HANDLE hLoadThread = CreateRemoteThread(handle, 0, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(hHandle, "LoadLibraryA"),
        pDllPath, 0, 0);

    if (hLoadThread == NULL) {
        VirtualFreeEx(handle, pDllPath, 0, MEM_RELEASE);
        CloseHandle(handle);
        return 1;
    }

    // Wait for the remote thread to complete its execution (i.e., the DLL is loaded).
    WaitForSingleObject(hLoadThread, INFINITE);

    // Clean up: Free allocated memory and close the open handles.
    VirtualFreeEx(handle, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hLoadThread);
    CloseHandle(handle);

    return 0;
}

// Main function to parse the arguments and initiate the DLL injection process.
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <DLL> <PID>\n", argv[0]);
        return 1;
    }

    LPCSTR DllPath = argv[1];
    DWORD pid = strtol(argv[2], NULL, 10);
    if (pid == 0) return 1;

    // Try to load the DLL into the target process.
    if (!LoadDllIntoProcess(DllPath, pid)) {
        return 1;
    }

    return 0;
}
