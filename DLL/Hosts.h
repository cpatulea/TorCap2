#ifndef __HOSTS_H__
#define __HOSTS_H__
#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

u_long HostsLookupName(const char *name);
const char *HostsLookupAddr(u_long addr);

#ifdef __cplusplus
}
#endif

#endif
