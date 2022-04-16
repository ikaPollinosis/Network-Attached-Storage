/*
    Implementation of kernel mode sockets for Windows.
    Copyright (C) 2003-2015 Bo Brant�n.

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
#include "ksocket.h"

#if defined(_X86_) || defined(_IA64_) || defined(_AMD64_)
#define _LITTLE_ENDIAN TRUE
#endif

#if !defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#error Define _LITTLE_ENDIAN or _BIG_ENDIAN
#endif

static u_long bswap32(u_long x)
{
    return  ((x << 24) & 0xff000000ul) |
            ((x <<  8) & 0x00ff0000ul) |
            ((x >>  8) & 0x0000ff00ul) |
            ((x >> 24) & 0x000000fful);
}

static u_short bswap16(u_short x)
{
    return  ((x << 8) & 0xff00u) |
            ((x >> 8) & 0x00ffu);
}

u_long __cdecl htonl(u_long hostlong)
{
#if defined(_LITTLE_ENDIAN)
    return bswap32(hostlong);
#else
    return hostlong;
#endif
}

u_short __cdecl htons(u_short hostshort)
{
#if defined(_LITTLE_ENDIAN)
    return bswap16(hostshort);
#else
    return hostshort;
#endif
}

u_long __cdecl ntohl(u_long netlong)
{
#if defined(_LITTLE_ENDIAN)
    return bswap32(netlong);
#else
    return netlong;
#endif
}

u_short __cdecl ntohs(u_short netshort)
{
#if defined(_LITTLE_ENDIAN)
    return bswap16(netshort);
#else
    return netshort;
#endif
}
