#include "Hosts.h"
#include "Util.h"

#define MAX_HOSTS 256
const char        *Hosts[MAX_HOSTS] = {0, };
const char       **Hosts_ptr = &Hosts[0];
const char * const*Hosts_end = &Hosts[MAX_HOSTS];

u_long HostsLookupName(const char *name)
{
	const char **i = Hosts;
	unsigned int namesize;
	unsigned long addr;

	for(; i < Hosts_end; ++i)
	{
		if(*i && !lstrcmpi(*i, name))
		{
#ifdef _DEBUG
			unsigned long addr = i - Hosts;
			trace("H: cache hit for \"%s\" --> %s\n", name, inet_ntoa(*(struct in_addr *)&addr));
#endif
			return i - Hosts;
		}
	}

	namesize = strlen(name) + 1;

	*Hosts_ptr = (const char *)(Hosts_ptr ?
		  HeapAlloc(GetProcessHeap(), 0,                     namesize) :
		HeapReAlloc(GetProcessHeap(), 0, (void *)*Hosts_ptr, namesize));
	memcpy((void *)*Hosts_ptr, name, namesize);

	addr = (Hosts_ptr++) - Hosts;

	if(Hosts_ptr == Hosts_end)
		Hosts_ptr = Hosts;

#ifdef _DEBUG
	trace("H: adding \"%s\" --> %s\n", name, inet_ntoa(*(struct in_addr *)&addr));
#endif

	return addr;
}

const char *HostsLookupAddr(u_long addr)
{
	if(addr >= (unsigned)(Hosts_end - Hosts))
		return NULL;

	return Hosts[addr];
}
