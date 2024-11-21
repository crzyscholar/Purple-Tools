#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
        	MessageBox(NULL, L"test", L"this is a test for Twhatever the fuck I'm tired", MB_ICONQUESTION | MB_OK);

         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}