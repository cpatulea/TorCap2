#define WIN32_LEAN_AND_MEAN
#define WIN32_LEANER_AND_MEANER
#define VC_EXTRALEAN
#include <windows.h>
#include <stdarg.h>
#include "Util.h"

int ForgeHook(DWORD pAddr, DWORD pAddrToJump, BYTE **Buffer, DWORD *pBufSize);
void UnforgeHook(DWORD pAddr, BYTE *Buffer, DWORD OrigSize);

#ifdef _DEBUG
HANDLE g_hOutput = INVALID_HANDLE_VALUE;
void trace(const char *fmt, ...)
{
	if(g_hOutput == INVALID_HANDLE_VALUE)
	{
		AllocConsole();
		g_hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	if(g_hOutput != INVALID_HANDLE_VALUE)
	{
		char buffer[4096];
		va_list args;
		DWORD written;

		va_start(args, fmt);
		wvsprintf(buffer, fmt, args);
		va_end(args);

		WriteFile(g_hOutput, buffer, strlen(buffer), &written, NULL);
	}
}
#endif

void Hook(struct HOOK *hk, LPCTSTR pszModule, LPCTSTR pszName, LPVOID pvNew)
{
	if(!(hk->hMod = LoadLibrary(pszModule)))
		return;

	if(!(hk->pFunction = (BYTE *)GetProcAddress(hk->hMod, pszName)))
	{
		FreeLibrary(hk->hMod);
		return;
	}

	if(!ForgeHook((DWORD)hk->pFunction, (DWORD)pvNew, &hk->pTrampoline, &hk->cbOriginal))
	{
		FreeLibrary(hk->hMod);
		return;
	}
}

void Unhook(struct HOOK *hk)
{
	UnforgeHook((DWORD)hk->pFunction, hk->pTrampoline, hk->cbOriginal);
	FreeLibrary(hk->hMod);
}
