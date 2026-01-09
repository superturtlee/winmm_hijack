#include <windows.h>
#include "NsHiJack.h"
#include "../Detours/src/detours.h"
#include "XStoreAPIHooks.h"
#include "../patcher.h"

// Function pointer type for QueryApiImpl
typedef __int64(__fastcall* QueryApiImpl_t)(GUID* a1, GUID* a2, void* a3);

// Pointer to the original function
QueryApiImpl_t pOriginalQueryApiImpl = nullptr;

// Hooked function
__int64 __fastcall HookedQueryApiImpl(GUID* a1, GUID* a2, __int64* a3) {
    int ret = pOriginalQueryApiImpl(a1, a2, a3);
    if (XStoreAPI.matches(a1)) {
        XStoreAPI.performAction(*a3);
    }
    return ret;
}

// Initialize hook
BOOL InitializeHook() {
    // Get handle to xgameruntime.dll
    HMODULE hModule = GetModuleHandleA("xgameruntime.dll");
    if (hModule == nullptr) {
        return FALSE;
    }

    // Get address of QueryApiImpl
    FARPROC pQueryApiImpl = GetProcAddress(hModule, "QueryApiImpl");
    if (pQueryApiImpl == nullptr) {
        return FALSE;
    }

    // Initialize Detours hook
    pOriginalQueryApiImpl = (QueryApiImpl_t)pQueryApiImpl;
    
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG result = DetourAttach(&(PVOID&)pOriginalQueryApiImpl, HookedQueryApiImpl);
    
    if (result != NO_ERROR) {
        DetourTransactionAbort();
        return FALSE;
    }

    if (DetourTransactionCommit() != NO_ERROR) {
        return FALSE;
    }

    return TRUE;
}

// Cleanup hook
void CleanupHook() {
    if (pOriginalQueryApiImpl != nullptr) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)pOriginalQueryApiImpl, HookedQueryApiImpl);
        DetourTransactionCommit();
    }
}

// Thread function to wait for xgameruntime.dll to load
DWORD WINAPI WaitForModuleThread(LPVOID lpParam) {
    const int MAX_ATTEMPTS = 300; // 30 seconds (300 * 100ms)
    int attempts = 0;

    while (attempts < MAX_ATTEMPTS) {
        HMODULE hModule = GetModuleHandleA("xgameruntime.dll");
        if (hModule != nullptr) {
            // Small delay to ensure the module is fully initialized
            Sleep(500);
            InitializeHook();
            return 0;
        }

        Sleep(100); // Wait 100ms before checking again
        attempts++;
    }
    return 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                      )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			DisableThreadLibraryCalls(hModule);
			
			// Initialize console first
			AllocConsole();

    

    FILE* fpStdout = nullptr;
    FILE* fpStderr = nullptr;
    FILE* fpStdin = nullptr;

    freopen_s(&fpStdout, "CONOUT$", "w", stdout);
    freopen_s(&fpStderr, "CONOUT$", "w", stderr);
    freopen_s(&fpStdin, "CONIN$", "r", stdin);
			
			// Run oreui patcher (blocking, no thread)
			oreuifix();
			
			if (!NsInitDll())
				return false;

			// Initialize XStore API hooks
			initXStoreAPISet();
			
			// Try to initialize the hook immediately
			if (!InitializeHook()) {
				// Create a thread to wait for the module to load
				HANDLE hThread = CreateThread(
					nullptr,                // Default security attributes
					0,                      // Default stack size
					WaitForModuleThread,    // Thread function
					nullptr,                // No parameter
					0,                      // Start immediately
					nullptr                 // Don't need thread ID
				);
				if (hThread != nullptr) {
					CloseHandle(hThread);
				}
			}
		}
        break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		{
			CleanupHook();
		}
		break;
	}
	return TRUE;
}
