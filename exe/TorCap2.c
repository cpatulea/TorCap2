#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include "resource.h"

BOOL InjectHook(HANDLE hProcess, LPCTSTR pszHookDLL)
{
	void *pDLLName, *pLoadLibraryA;
	DWORD dwWritten, dwLoadThread;
	HANDLE hThread = NULL;
	DWORD dwExitCode;

	// allocate memory for name of DLL file
	pDLLName = VirtualAllocEx(hProcess, NULL, lstrlen(pszHookDLL) + 1, MEM_COMMIT, PAGE_READWRITE);
	if(!pDLLName)
	{
		return FALSE;
	}

	// write name of DLL file
	if(!WriteProcessMemory(hProcess, pDLLName, pszHookDLL, lstrlen(pszHookDLL) + 1, &dwWritten))
	{
		goto inject_free;
	}

	// load DLL by creating a thread whose entry point is LoadLibraryA
	// note: we depend on the fact that kernel32 is loaded at the same
	//       place in all processes
	pLoadLibraryA = (void *)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");

	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pLoadLibraryA, pDLLName, 0, &dwLoadThread);
	if(!hThread)
	{
		goto inject_free;
	}

	if(WaitForSingleObject(hThread, INFINITE) == WAIT_TIMEOUT)
	{
		goto inject_free;
	}

	if(!GetExitCodeThread(hThread, &dwExitCode))
	{
		goto inject_free;
	}

	if(dwExitCode == STILL_ACTIVE)
	{
		goto inject_free;
	}

	if(!dwExitCode)
	{
		goto inject_free;
	}

	return TRUE;
inject_free:
	if(hThread)
		CloseHandle(hThread);

	// free memory
	VirtualFreeEx(hProcess, pDLLName, 0, MEM_RELEASE);

	return FALSE;
}

BOOL WINAPI MainProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	char *pszBuffer;
	int nMax;

	switch(uMsg)
	{
	case WM_INITDIALOG:
		pszBuffer = HeapAlloc(GetProcessHeap(), 0, nMax = MAX_PATH);
		GetPrivateProfileString("TorCap2", "Server", "", pszBuffer, nMax, ".\\TorCap2.ini");
		SetDlgItemText(hWnd, IDC_SERVER, pszBuffer);

		pszBuffer = HeapAlloc(GetProcessHeap(), 0, nMax = MAX_PATH);
		GetPrivateProfileString("TorCap2", "Command", "", pszBuffer, nMax, ".\\TorCap2.ini");
		SetDlgItemText(hWnd, IDC_COMMAND, pszBuffer);
		return TRUE;
	case WM_COMMAND:
		switch(wParam)
		{
			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			OPENFILENAME ofn;

			char szModule[MAX_PATH+1], *pszHookDLL;

		case MAKELONG(IDOK, BN_CLICKED):
			nMax = GetWindowTextLength(GetDlgItem(hWnd, IDC_SERVER)) + 1;
			pszBuffer = HeapAlloc(GetProcessHeap(), 0, nMax);
			GetDlgItemText(hWnd, IDC_SERVER, pszBuffer, nMax);

			SetEnvironmentVariable("TORCAP2_SOCKS", pszBuffer);
			WritePrivateProfileString("TorCap2", "Server", pszBuffer, ".\\TorCap2.ini");

			HeapFree(GetProcessHeap(), 0, pszBuffer);
			
			nMax = GetWindowTextLength(GetDlgItem(hWnd, IDC_COMMAND)) + 1;
			pszBuffer = HeapAlloc(GetProcessHeap(), 0, nMax);
			GetDlgItemText(hWnd, IDC_COMMAND, pszBuffer, nMax);

			WritePrivateProfileString("TorCap2", "Command", pszBuffer, ".\\TorCap2.ini");

			ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);

			if(!(CreateProcess(NULL, pszBuffer, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL,
				&si, &pi) && HeapFree(GetProcessHeap(), 0, pszBuffer)))
			{
				MessageBox(NULL, "Error creating process.", NULL, MB_ICONSTOP);
				return TRUE;
			}

			GetModuleFileName(GetModuleHandle(NULL), szModule, sizeof(szModule));
			GetFullPathName(szModule, sizeof(szModule), szModule, &pszHookDLL);
			lstrcpy(pszHookDLL, "TorCap2.dll");

			if(!InjectHook(pi.hProcess, szModule))
			{
				MessageBox(NULL, "Error injecting hook into process.", NULL, MB_ICONSTOP);
				TerminateProcess(pi.hProcess, 2);
				return TRUE;
			}

			if(!ResumeThread(pi.hThread))
			{
				MessageBox(NULL, "Error resuming application.", NULL, MB_ICONSTOP);
				TerminateProcess(pi.hProcess, 2);
				return TRUE;
			}

			EndDialog(hWnd, 0);
			return TRUE;
		case MAKELONG(IDCANCEL, BN_CLICKED):
			EndDialog(hWnd, 0);
			return TRUE;
		case MAKELONG(IDC_BROWSE, BN_CLICKED):
			ZeroMemory(&ofn, sizeof(ofn));

			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hWnd;
			ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
			ofn.lpstrFile = HeapAlloc(GetProcessHeap(), 0, ofn.nMaxFile = (MAX_PATH + 1));
			ofn.lpstrFile[0] = '\0';
			ofn.lpstrTitle = "Find Executable...";
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR |
				OFN_PATHMUSTEXIST;

			if(GetOpenFileName(&ofn))
				SetDlgItemText(hWnd, IDC_COMMAND, ofn.lpstrFile);

			HeapFree(GetProcessHeap(), 0, ofn.lpstrFile);
			return TRUE;
		}
		return FALSE;
	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return TRUE;
	}
	return FALSE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nShowCmd)
{
	return DialogBox(hInst, (LPCTSTR)IDD_MAIN, NULL, MainProc);
}
