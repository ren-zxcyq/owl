// ((void (*)())shellcode)(); 


/*
	Works but WinExec() is deprecated.
*/
void runCalc() {
	WinExec("calc.exe", 0);
	ExitProcess(0);
}


/*
	Not ready yet.
*/
void runCalcViaCreateProcess() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	if (!CreateProcessW(L"C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		/*
		_In_opt_ LPCWSTR lpApplicationName,
		_Inout_opt_ LPWSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCWSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOW lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation
		*/
		printf("CreateProcessW failed (%d)\r\n", GetLastError());
		return;
	}
	// Wait until process exits
	WaitForSingleObject(pi.hProcess, INFINITE);
	// Close process and thread handles
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

