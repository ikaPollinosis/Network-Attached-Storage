#include <ntddk.h>			//��NT
#include <ntdddisk.h>		//��������IOCTL
#include "vdisk.h"
#define DEVICE_NAME			L"\\Device\\VDisk"		//�豸��
#define SYM_NAME			L"\\??\\VDisk"	//��������




NTSTATUS 
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status=STATUS_SUCCESS;
	
	//
	//������ʼ����
	//
	DbgPrint("Sample Disk Driver Running\n");

	//
	//����
	//
	UNICODE_STRING devicename = { 0 };
	RtlInitUnicodeString(&devicename, DEVICE_NAME);

	//
	//�����豸
	//
	PDEVICE_OBJECT pdevice = NULL;
	status = IoCreateDevice(DriverObject, 0, &devicename, FILE_DEVICE_DISK, 0, TRUE, &pdevice);//��չ��С����Ϊ0
	if (!NT_SUCCESS(status)) { 
		DbgPrint("=Create Device Failed:%x\n", status);
		return status;
	}

	//
	//������������
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
	//ж�غ���
	//
	DriverObject->DriverUnload = VDiskUnload;

	//
	//��������豸(fdo)
	//
	//DbgPrint("Attempting to add device\n");
	//DriverObject->DriverExtension->AddDevice = VDiskAddDevice;


	//
	//ʵ�������̺���
	//

	DriverObject->MajorFunction[IRP_MJ_CREATE] = VDiskCreate;		//�򿪲���
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = VDiskClose;			//�رղ���
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = VDiskClean;			//�������


	return status;
}


