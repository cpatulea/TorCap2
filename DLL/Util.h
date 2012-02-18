#ifndef __UTIL_H__
#define __UTIL_H__
#define WIN32_LEAN_AND_MEAN
#define WIN32_LEANER_AND_MEANER
#define VC_EXTRALEAN
#include <windows.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct HOOK
{
	HMODULE hMod;
	BYTE *pFunction;
	BYTE *pTrampoline;
	DWORD cbOriginal;
};


void trace(const char *fmt, ...);
void Hook(struct HOOK *hk, LPCTSTR pszModule, LPCTSTR pszName, LPVOID pvNew);
void Unhook(struct HOOK *hk);

#ifdef __cplusplus
}
#endif

#endif
