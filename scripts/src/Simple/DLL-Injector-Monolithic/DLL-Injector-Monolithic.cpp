#include <iostream>
#include <Windows.h>
#include <string>

using namespace std;

int main(int argc, char* argv[])
{

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

