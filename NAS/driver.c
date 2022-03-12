#include <ntddk.h>			//主NT
#include <ntdddisk.h>		//磁盘驱动IOCTL
#include "vdisk.h"
#define DEVICE_NAME			L"\\Device\\VDisk"		//设备名
#define SYM_NAME			L"\\??\\VDisk"	//符号连接




NTSTATUS 
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status=STATUS_SUCCESS;
	
	//
	//驱动开始运行
	//
	DbgPrint("Sample Disk Driver Running\n");

	//
	//命名
	//
	UNICODE_STRING devicename = { 0 };
	RtlInitUnicodeString(&devicename, DEVICE_NAME);

	//
	//创建设备
	//
	PDEVICE_OBJECT pdevice = NULL;
	status = IoCreateDevice(DriverObject, 0, &devicename, FILE_DEVICE_DISK, 0, TRUE, &pdevice);//扩展大小暂设为0
	if (!NT_SUCCESS(status)) { 
		DbgPrint("=Create Device Failed:%x\n", status);
		return status;
	}

	//
	//创建符号连接
	//
	UNICODE_STRING symname = { 0 };
	RtlInitUnicodeString(&symname, SYM_NAME);
	status = IoCreateSymbolicLink(&symname, &devicename);
	if (!NT_SUCCESS(status)) {
		DbgPrint("=Create SymbolLink Failed:%x\n", status);
		IoDeleteDevice(pdevice);
		return status;
	}

	//
	//卸载函数
	//
	DriverObject->DriverUnload = VDiskUnload;

	//
	//添加虚拟设备(fdo)
	//
	//DbgPrint("Attempting to add device\n");
	//DriverObject->DriverExtension->AddDevice = VDiskAddDevice;


	//
	//实现主例程函数
	//

	DriverObject->MajorFunction[IRP_MJ_CREATE] = VDiskCreate;		//打开操作
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = VDiskClose;			//关闭操作
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = VDiskClean;			//清除操作


	return status;
}


