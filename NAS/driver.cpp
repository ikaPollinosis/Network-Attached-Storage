#include <ntddk.h>			//main NT include
#include <ntdddisk.h>		//disk driver IOCTL
#include <vdisk.h>			//disk basic operation




NTSTATUS 
DriverEntry(IN OUT PDRIVER_OBJECT DriverObject,IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntStatus;
	
	//
	// show folks who we are
	//
	DbgPrint("DriverEntry: Sample Disk Driver\n");

	//
	// attempt to create device
	//
	DbgPrint("DriverEntry: Attempting to create device\n");
	//DriverObject->DriverExtension->AddDevice = VdiskAddDevice;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = VDiskCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = VDiskCreateClose;
}