#include <winsock2.h>
#define _WSPIAPI_COUNTOF(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#include <ws2tcpip.h>
#include <windows.h>
#include "Util.h"
#include "Hosts.h"

//#pragma comment(linker,"/merge:.rdata=.text")

struct HOOK
	hookgethostbyname,
	hookgetaddrinfo,
	hookconnect;

struct sockaddr_in socks_sin;

#include <pshpack1.h>
struct Socks4Header {
	u_char bVn;
	u_char bCd;
	u_short wPort;
	struct in_addr dIP;
};
#include <poppack.h>

#define SOCKS_USERNAME "tor"

struct hostent FAR *WSAAPI newgethostbyname(IN const char FAR * name)
{
	struct hostent *phe = ((struct hostent FAR * (WSAAPI *)(IN const char FAR * name))
		hookgethostbyname.pTrampoline)("localhost");

	*(u_long *)phe->h_addr_list[0] = HostsLookupName(name);
			   phe->h_addr_list[1] = NULL;

	return phe;
}

int WSAAPI newgetaddrinfo(	IN const char FAR * nodename,
							IN const char FAR * servname,
							IN const struct addrinfo FAR * hints,
							OUT struct addrinfo FAR * FAR * res)
{
	int ret = ((int (WSAAPI *)(IN const char FAR * nodename,
						IN const char FAR * servname,
						IN const struct addrinfo FAR * hints,
						OUT struct addrinfo FAR * FAR * res))
		hookgetaddrinfo.pTrampoline)("localhost", servname, hints, res);
	if(ret)
		return ret;

	((struct sockaddr_in *)(*res)->ai_addr)->sin_addr.s_addr = HostsLookupName(nodename);
	(*res)->ai_next = NULL;

	return 0;
}

typedef int (WSAAPI *Pconnect)
	(IN SOCKET s, IN const struct sockaddr FAR * name, IN int namelen);

int WSAAPI newconnect(IN SOCKET s, IN const struct sockaddr FAR * name, IN int namelen)
#define SIN(name) ((struct sockaddr_in *)(name))
#define S4H(pkt) ((struct Socks4Header *)(pkt))
{
	const char *hostname;
	unsigned int hostname_size;
	void *pkt;
	u_char *p;

	if(SIN(name)->sin_addr.s_addr == 0x0100007f)
		return ((Pconnect)hookconnect.pTrampoline)(s, name, namelen);

	if(!(hostname = HostsLookupAddr(SIN(name)->sin_addr.s_addr)))
		return SOCKET_ERROR;

#ifdef _DEBUG
	trace("connect: connecting to %s:%d --> \"%s\"\n", inet_ntoa(SIN(name)->sin_addr),
		ntohs(SIN(name)->sin_port), hostname);
#endif

	hostname_size = strlen(hostname) + 1;

	do {
		((Pconnect)hookconnect.pTrampoline)(s,
			(struct sockaddr *)&socks_sin, sizeof(socks_sin));
		Sleep(100);
	} while(WSAGetLastError() != WSAEISCONN);

	pkt = HeapAlloc(GetProcessHeap(), 0, sizeof(struct Socks4Header) + sizeof(SOCKS_USERNAME) + hostname_size + 1);
	S4H(pkt)->bVn = 4;
	S4H(pkt)->bCd = 1;
	S4H(pkt)->wPort = SIN(name)->sin_port;
	S4H(pkt)->dIP.s_addr = 0x01000000;

	p = (u_char *)pkt + sizeof(struct Socks4Header);
	memcpy(p, SOCKS_USERNAME, sizeof(SOCKS_USERNAME));	p += sizeof(SOCKS_USERNAME);
	memcpy(p, hostname, hostname_size);					p += hostname_size;

	send(s, (const char *)pkt, p - (u_char *)pkt, 0);

	do {
		recv(s, (char *)pkt, sizeof(struct Socks4Header), 0);
		Sleep(100);
	} while(S4H(pkt)->bCd == 0);

	HeapFree(GetProcessHeap(), 0, pkt);
#ifdef _DEBUG
	trace("connect: received reply, passthrough starting NOW\n");
#endif
	return 0;
}

#pragma data_seg(".rdata")

BOOL WINAPI _DllMainCRTStartup(HANDLE hDllHandle, DWORD dwReason, LPVOID lpReserved)
{
	switch(dwReason)
	{
	case DLL_PROCESS_ATTACH: {
		WSADATA wsaData;
		char szSocksData[32];
		int sinsize = sizeof(socks_sin);

		if(	!WSAStartup(0x202, &wsaData) &&
			GetEnvironmentVariable("TORCAP2_SOCKS", szSocksData, sizeof(szSocksData)) &&
			!WSAStringToAddress(szSocksData, AF_INET, NULL,
				(struct sockaddr *)&socks_sin, &sinsize))
		{
			Hook(&hookgethostbyname, "ws2_32", "gethostbyname", newgethostbyname);
			Hook(&hookgetaddrinfo, "ws2_32", "getaddrinfo", newgetaddrinfo);
			Hook(&hookconnect, "ws2_32", "connect", newconnect);
#ifdef _DEBUG
			trace("hooked on %s:%d\n", inet_ntoa(socks_sin.sin_addr), ntohs(socks_sin.sin_port));
#endif
		}
		else
		{
			MessageBox(NULL, "Failed to initialize TorCap2 hook.\n", NULL, MB_ICONWARNING);
		}

		return TRUE;
	}
	case DLL_PROCESS_DETACH:
		Unhook(&hookconnect);
		Unhook(&hookgetaddrinfo);
		Unhook(&hookgethostbyname);
		return TRUE;
	default:
		return TRUE;
	}
}
