#define IOCTL_DISK_CONNECT          CTL_CODE(FILE_DEVICE_DISK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_DISCONNECT       CTL_CODE(FILE_DEVICE_DISK, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#ifndef VDISK_H
#define VDISK_H

#ifndef __T
#ifdef _NTDDK_
#define __T(x)  L ## x
#else
#define __T(x)  x
#endif
#endif

#ifndef _T
#define _T(x)   __T(x)
#endif

#define DEVICE_BASE_NAME    _T("\\VDisk")
#define DEVICE_DIR_NAME     _T("\\Device")      DEVICE_BASE_NAME
#define DEVICE_NAME_PREFIX  DEVICE_DIR_NAME     _T("\\Virtual")



typedef struct _NET_DISK_INFORMATION {
    ULONG   Address;
    USHORT  Port;
    UCHAR   DriveLetter;
    USHORT  HostNameLength;
    CHAR    HostName[256];
    USHORT  FileNameLength;
    CHAR    FileName[1];
} NET_DISK_INFORMATION, * PNET_DISK_INFORMATION;

#endif