#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include "vdisk.h"

#pragma prefast( disable: 28719, "this warning only applies to drivers not applications" )		//忽略警告

int DiskMount(int DeviceNumber,PNET_DISK_INFORMATION DiskInformation){
	char VolumeName[] = "\\\\.\\ :";
	char DriveName[] = " :\\";
	char DeviceName[255];
	HANDLE Device;
	DWORD BytesReturned;

	VolumeName[4] = DiskInformation->DriveLetter;
	DriveName[0] = DiskInformation->DriveLetter;

	Device = CreateFile(
		VolumeName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
	);

	// 设备句柄无效
	if (Device != INVALID_HANDLE_VALUE)
	{
		CloseHandle(Device);
		return -1;
	}

	sprintf(DeviceName, DEVICE_NAME_PREFIX L"%u", DeviceNumber);

	// 创建符号链接，生成盘符
	if (!DefineDosDevice(
		DDD_RAW_TARGET_PATH,
		&VolumeName[4],
		DeviceName
	))
	{
		return -1;
	}

	Device = CreateFile(
		VolumeName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
	);

	if (Device == INVALID_HANDLE_VALUE)
	{
		// 句柄无效，删除符号链接
		DefineDosDevice(DDD_REMOVE_DEFINITION, &VolumeName[4], NULL);
		return -1;
	}
	
	// 系统调用，连接虚拟磁盘
	if (!DeviceIoControl(
		Device,
		IOCTL_DISK_CONNECT,
		DiskInformation,
		sizeof(NET_DISK_INFORMATION) + DiskInformation->FileNameLength - 1,
		NULL,
		0,
		&BytesReturned,
		NULL
	))
	{
		DefineDosDevice(DDD_REMOVE_DEFINITION, &VolumeName[4], NULL);
		CloseHandle(Device);
		return -1;
	}

	CloseHandle(Device);
	// 事件完成，通知系统刷新
	SHChangeNotify(SHCNE_DRIVEADD, SHCNF_PATH, DriveName, NULL);

	return 0;
}

int DiskUmount(char DriveLetter)
{
	char    VolumeName[] = "\\\\.\\ :";
	char    DriveName[] = " :\\";
	HANDLE  Device;
	DWORD   BytesReturned;

	VolumeName[4] = DriveLetter;
	DriveName[0] = DriveLetter;

	Device = CreateFile(
		VolumeName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
	);
	// 设备句柄无效
	if (Device == INVALID_HANDLE_VALUE)
	{
		PrintLastError(&VolumeName[4]);
		return -1;
	}

	// 锁定虚拟磁盘，防止IO操作
	if (!DeviceIoControl(
		Device,
		FSCTL_LOCK_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL
	))
	{
		CloseHandle(Device);
		return -1;
	}
	// 与服务器断开连接
	if (!DeviceIoControl(
		Device,
		IOCTL_DISK_DISCONNECT,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL
	))
	{
		CloseHandle(Device);
		return -1;
	}
	// 卸载磁盘
	if (!DeviceIoControl(
		Device,
		FSCTL_DISMOUNT_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL
	))
	{
		CloseHandle(Device);
		return -1;
	}
	// 解锁磁盘
	if (!DeviceIoControl(
		Device,
		FSCTL_UNLOCK_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL
	))
	{
		CloseHandle(Device);
		return -1;
	}
	// 关闭句柄
	CloseHandle(Device);
	// 删除符号链接
	if (!DefineDosDevice(
		DDD_REMOVE_DEFINITION,
		&VolumeName[4],
		NULL
	))
	{
		return -1;
	}
	// 事件完成，通知系统刷新
	SHChangeNotify(SHCNE_DRIVEREMOVED, SHCNF_PATH, DriveName, NULL);

	return 0;
}


int main(int argc, char* argv[]) {
	char* Command;		// 指令，为第一个参数
	int	DeviceCount;	// 设备号
	char* Url;			// 服务器URL
	char DriveLetter;	// 磁盘标识符
	PNET_DISK_INFORMATION DiskInformation;	// 虚拟磁盘信息
	char* FileName;		// 镜像文件名
	char* PortStr;		// 端口号
	struct hostent* Hostent;	// 主机信息
	WSADATA wsaData;	// Winsock初始化数据

	Command = argv[1];

	if (argc == 5 && !strcmp(Command, "/mount")) {
		Url = argv[3];
		DriveLetter = argv[4][0];

		// 为磁盘信息分配内存
		DiskInformation = malloc(sizeof(NET_DISK_INFORMATION) + strlen(Url));

		if (DiskInformation == NULL) {
			fprintf(stderr, "memory set failed.");
			return -1;
		}
		memset(DiskInformation, 0, sizeof(NET_DISK_INFORMATION) + strlen(Url));

		FileName = strstr(Url, "/");

		if (!FileName) {
			fprintf(stderr, "%s invalid url,check again.\n", Url);
			return -1;
		}

		strcpy(DiskInformation->FileName, FileName);
		DiskInformation->FileNameLength = (USHORT)strlen(DiskInformation->FileName);
		*FileName = '\0';

		// 从url中提取端口号
		PortStr = strstr(Url, ":");

		if (PortStr)
		{
			DiskInformation->Port = htons((USHORT)atoi(PortStr + 1));

			if (DiskInformation->Port == 0)
			{
				fprintf(stderr, "%s: invalid port.\n", PortStr + 1);
				return -1;
			}

			*PortStr = '\0';
		}
		else
		{

			// 使用默认80端口
			DiskInformation->Port = htons(80);
		}

		DiskInformation->HostNameLength = (USHORT)strlen(Url);
		if (DiskInformation->HostNameLength > 255)
		{
			// 检测url长度
			fprintf(stderr, "%s: Host name to long.\n", Url);
			return -1;
		}

		// 获取服务器地址
		strcpy(DiskInformation->HostName, Url);
		DiskInformation->Address = inet_addr(Url);

		if (DiskInformation->Address == INADDR_NONE)
		{
			if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
			{
				return -1;
			}

			Hostent = gethostbyname(Url);

			if (!Hostent)
			{
				PrintLastError(Url);
				return -1;
			}

			DiskInformation->Address = ((struct in_addr*)Hostent->h_addr)->s_addr;
		}
		DiskInformation->DriveLetter = DriveLetter;
		DeviceCount = atoi(argv[2]);
		// 挂载
		return DiskMount(DeviceCount, DiskInformation);
	}
	// 卸载虚拟磁盘
	else if (argc == 3 && !strcmp(Command, "/umount"))
	{
			DriveLetter = argv[2][0];
			return DiskUmount(DriveLetter);
	}
}