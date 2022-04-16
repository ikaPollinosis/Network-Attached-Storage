/*
    Implementation of kernel mode sockets for Windows.
    Copyright (C) 2003-2019 Bo Brantén.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntddk.h>
#include <ntstrsafe.h>
#include "ksocket.h"

u_long __cdecl inet_addr(const char *name)
{
    struct in_addr addr;

    if (inet_aton(name, &addr))
    {
        return addr.s_addr;
    }
    return INADDR_NONE;
}

int __cdecl inet_aton(const char *name, struct in_addr *addr)
{
    u_int dots, digits;
    u_long byte;

    if(!name || !addr)
    {
        return 0;
    }

    for (dots = 0, digits = 0, byte = 0, addr->s_addr = 0; *name; name++)
    {
        if (*name == '.')
        {
            addr->s_addr += byte << (8 * dots);
            if (++dots > 3 || digits == 0)
            {
                return 0;
            }
            digits = 0;
            byte = 0;
        }
        else
        {
            byte = byte * 10 + (*name - '0');
            if (++digits > 3 || *name < '0' || *name > '9' || byte > 255)
            {
                return 0;
            }
        }
    }

    if (dots != 3 || digits == 0)
    {
        return 0;
    }

    addr->s_addr += byte << (8 * dots);

    return 1;
}

// standard but not reentrant
char * __cdecl inet_ntoa(struct in_addr addr)
{
    static char buf[16];
    unsigned char *ucp = (unsigned char *)&addr;
    RtlStringCbPrintfA(buf, 16, "%u.%u.%u.%u", ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
    return buf;
}

// reentrant version of inet_ntoa
int __cdecl inet_ntoa_r(struct in_addr addr, char *buf, int buflen)
{
    unsigned char *ucp = (unsigned char *)&addr;

    if (!buf || buflen < 16)
        return -1;

    return RtlStringCbPrintfA(buf, 16, "%u.%u.%u.%u", ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
}
