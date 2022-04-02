#include <ntddk.h>
#include <ntifs.h>
#include <ntddvol.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <ntstrsafe.h>
#include <mountmgr.h>
#include <ntverp.h>
#include <wdmsec.h>
#include <wsk.h>
#include <tdi.h>
#include "vdisk.h"
#include "ksocket.h"

#pragma comment(lib,"ksocket.lib")


#define DEVICE_NAME_BASE			L"\\Device\\VDisk"		//�豸��

#define DEVICE_NAME_PREFIX			DEVICE_NAME_BASE  L"\\VDisk"
#define SYM_NAME					L"\\??\\VDisk"			//��������

#define PARAMETER_KEY				L"\\Parameters"

#define NUMBEROFDEVICES_VALUE		L"NumberOfDevices"

#define TOKEN_SOURCE_LENGTH 8

#define BUFFER_SIZE             (4096 * 4)

#define NET_DISK_POOL_TAG      'ksiD'

HANDLE dir_handle;

//
//��������
//
NTSTATUS
VDiskCreateDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number,
	IN DEVICE_TYPE      DeviceType
);

NTSTATUS
HttpGetHeader(
	IN ULONG                Address,
	IN USHORT               Port,
	IN PUCHAR               HostName,
	IN PUCHAR               FileName,
	OUT PIO_STATUS_BLOCK    IoStatus,
	OUT PHTTP_HEADER        HttpHeader
);

NTSTATUS
HttpGetBlock(
	IN ULONG                Address,
	IN USHORT               Port,
	IN PUCHAR               HostName,
	IN PUCHAR               FileName,
	OUT PIO_STATUS_BLOCK    IoStatus,
	OUT PHTTP_HEADER        HttpHeader
);




const WSK_CLIENT_DISPATCH WskAppDispatch = {
  MAKE_WSK_VERSION(1,0),
  0,
  NULL 
};

WSK_REGISTRATION WskRegistration;


typedef struct _HTTP_HEADER {
	LARGE_INTEGER ContentLength;
} HTTP_HEADER, * PHTTP_HEADER;




typedef struct _NET_HEADER {
	LARGE_INTEGER ContentLength;
} NET_HEADER, * PNET_HEADER;


//�豸��չ
typedef struct _DEVICE_EXTENSION {
	BOOLEAN							media_in_device;			//�Ƿ���������ý��
	HANDLE							file_handle;				//�ļ����
	FILE_STANDARD_INFORMATION		file_information;			//�ļ���Ϣ
	BOOLEAN							read_only;					//ֻ��
	PSECURITY_CONTEXT_TRACKING_MODE security_client_context;	//��ȫ��������
	LIST_ENTRY						list_head;					//irp����ͷ
	KSPIN_LOCK						list_lock;					//�����дͬ����
	KEVENT							request_event;				//�������������¼�
	PVOID							thread_pointer;				//�߳�ָ��
	BOOLEAN							terminate_thread;			//�Ƿ���ֹ�߳�
	UNICODE_STRING					device_name;
	ULONG							device_number;
	DEVICE_TYPE						device_type;
	ULONG							address;
	USHORT							port;
	PUCHAR							host_name;
	PUCHAR							file_name;
	LARGE_INTEGER					file_size;
	INT_PTR							socket;

}DEVICE_EXTENSION, * PDEVICE_EXTENSION;


//
//ɾ���豸
// 
PDEVICE_OBJECT VDiskDeleteDevice(PDEVICE_OBJECT DeviceObject) {
	PDEVICE_EXTENSION   device_extension;
	PDEVICE_OBJECT      next_device_object;
	ASSERT(DeviceObject = NULL);

	// �õ��豸��չ
	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	// �����߳���ֹ��־
	device_extension->terminate_thread = TRUE;
	// ���������¼�
	KeSetEvent(
		&device_extension->request_event,
		(KPRIORITY)0,
		FALSE
	);
	// �ȴ��̵߳Ľ���
	KeWaitForSingleObject(
		device_extension->thread_pointer,
		Executive,
		KernelMode,
		FALSE,
		NULL
	);
	ObDereferenceObject(device_extension->thread_pointer);

	if (device_extension->device_name.Buffer != NULL)
	{
		ExFreePool(device_extension->device_name.Buffer);
	}

	next_device_object = DeviceObject->NextDevice;

	IoDeleteDevice(DeviceObject);

	return next_device_object;
}



//
//����ж������
//
VOID 
VDiskUnload(PDRIVER_OBJECT DriverObject) {
	DbgPrint("Driver Unloaded\n");

	PDEVICE_OBJECT device_object;

	device_object = DriverObject->DeviceObject;
	//���豸���������ɾ��
	while (device_object) {
		device_object = VDiskDeleteDevice(device_object);
	}
	ZwClose(dir_handle);
}




//
//�������ر��豸����
//
NTSTATUS 
VDiskCreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	//PAGED_CODE();		����ʹ�õĺ�
	UNREFERENCED_PARAMETER(DeviceObject);		//�Թ�δʹ�õĲ���
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = FILE_OPENED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//
//����豸����
//
NTSTATUS 
VDiskClean(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("Disk has been cleaned\n");
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//
//��д����
//
NTSTATUS 
VDiskReadWrite(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	PDEVICE_EXTENSION device_extension;
	PIO_STACK_LOCATION io_stack;


	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	//����Ƿ������������豸
	if (!device_extension->media_in_device)
	{
		irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_NO_MEDIA_IN_DEVICE;
	}
	//��ȡirp��ǰջ�ռ�
	io_stack = IoGetCurrentIrpStackLocation(irp);
	//��0����ʱ��ֱ�ӷ��سɹ�
	if (io_stack->Parameters.Read.Length == 0)
	{
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	IoMarkIrpPending(irp);

	ExInterlockedInsertTailList(&device_extension->list_head,
		&irp->Tail.Overlay.ListEntry,
		&device_extension->list_lock
	);	//д������

	//�߳�ѭ������
	KeSetEvent(
		&device_extension->request_event,
		(KPRIORITY)0,
		FALSE
	);
	return STATUS_PENDING;

	//����Ķ�д�ڴ����߳������
}





//
//�豸��������
//
NTSTATUS VDiskDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	PDEVICE_EXTENSION device_extension;
	PIO_STACK_LOCATION io_stack;
	NTSTATUS status;
	//��ȡ��ǰ�豸��չ
	device_extension = DeviceObject->DeviceExtension;

	//��ȡ�豸ջ
	io_stack = IoGetCurrentIrpStackLocation(irp);

	//�ж��Ƿ�����������
	if (!device_extension->media_in_device && io_stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_DISK_CONNECT) {
		irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_MEDIA_IN_DEVICE;
	}

	//���ݲ�ͬ���ܺŽ����豸����
	switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
	{

		//���ӡ��Ͽ����Ӵ���
	case IOCTL_DISK_CONNECT:
	{
		if (device_extension->media_in_device)
		{
			DbgPrint("IOCTL_DISK_CONNECT: Media already connected.\n");

			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}

		if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(NET_DISK_INFORMATION))
		{
			status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
			break;
		}

		if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(NET_DISK_INFORMATION) +
			((PNET_DISK_INFORMATION)irp->AssociatedIrp.SystemBuffer)->FileNameLength -
			sizeof(UCHAR))
		{
			status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
			break;
		}

		IoMarkIrpPending(irp);

		ExInterlockedInsertTailList(
			&device_extension->list_head,
			&irp->Tail.Overlay.ListEntry,
			&device_extension->list_lock
		);

		KeSetEvent(
			&device_extension->request_event,
			(KPRIORITY)0,
			FALSE
		);

		status = STATUS_PENDING;

		break;
	}

	case IOCTL_DISK_DISCONNECT:
	{
		IoMarkIrpPending(irp);

		ExInterlockedInsertTailList(
			&device_extension->list_head,
			&irp->Tail.Overlay.ListEntry,
			&device_extension->list_lock
		);

		KeSetEvent(
			&device_extension->request_event,
			(KPRIORITY)0,
			FALSE
		);

		status = STATUS_PENDING;

		break;
	}



		//��������Ч�ԵĹ��ܺ�,ֱ�ӷ�����Ч
		case IOCTL_DISK_CHECK_VERIFY:
		case IOCTL_CDROM_CHECK_VERIFY:
		case IOCTL_STORAGE_CHECK_VERIFY:
		case IOCTL_STORAGE_CHECK_VERIFY2:
		{
			status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			break;
		}


		//��ȡ�������Թ��ܺ�
		case IOCTL_DISK_GET_DRIVE_GEOMETRY:
		case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
		{
			PDISK_GEOMETRY disk_geometry;
			ULONGLONG length;
			ULONG	sector_size = 2048;

			//�豸ջ��������С
			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DISK_GEOMETRY)) {
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			disk_geometry = (PDISK_GEOMETRY)irp->AssociatedIrp.SystemBuffer;
			length = device_extension->file_information.AllocationSize.QuadPart;
			disk_geometry->Cylinders.QuadPart = length / MM_MAXIMUM_DISK_IO_SIZE;	//����
			disk_geometry->MediaType = FixedMedia;									//ý������
			disk_geometry->TracksPerCylinder = MM_MAXIMUM_DISK_IO_SIZE / PAGE_SIZE; //ÿ�������Ĵŵ���
			disk_geometry->SectorsPerTrack = PAGE_SIZE / sector_size;				//�ŵ�������
			disk_geometry->BytesPerSector = sector_size;							//�������ֽ���


			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(DISK_GEOMETRY);

			break;
		}


		case IOCTL_DISK_GET_LENGTH_INFO:
		{
			PGET_LENGTH_INFORMATION get_length_information;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(GET_LENGTH_INFORMATION))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			get_length_information = (PGET_LENGTH_INFORMATION)irp->AssociatedIrp.SystemBuffer;

			get_length_information->Length.QuadPart = device_extension->file_size.QuadPart;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);

			break;
		}

		//��ȡ������Ϣ���ܺ�
		case IOCTL_DISK_GET_PARTITION_INFO_EX:
		{
			PPARTITION_INFORMATION_EX   partition_information_ex;
			ULONGLONG                   length;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(PARTITION_INFORMATION_EX))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			partition_information_ex = (PPARTITION_INFORMATION_EX)irp->AssociatedIrp.SystemBuffer;

			length = device_extension->file_information.AllocationSize.QuadPart;

			partition_information_ex->PartitionStyle = PARTITION_STYLE_MBR;
			partition_information_ex->StartingOffset.QuadPart = 0;
			partition_information_ex->PartitionLength.QuadPart = length;
			partition_information_ex->PartitionNumber = 0;
			partition_information_ex->RewritePartition = FALSE;
			partition_information_ex->Mbr.PartitionType = 0;
			partition_information_ex->Mbr.BootIndicator = FALSE;
			partition_information_ex->Mbr.RecognizedPartition = FALSE;
			partition_information_ex->Mbr.HiddenSectors = 1;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(PARTITION_INFORMATION_EX);

			break;
		}
		case IOCTL_DISK_GET_PARTITION_INFO:
		{
			PPARTITION_INFORMATION  partition_information;
			ULONGLONG               length;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(PARTITION_INFORMATION))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			partition_information = (PPARTITION_INFORMATION)irp->AssociatedIrp.SystemBuffer;

			length = device_extension->file_information.AllocationSize.QuadPart;

			partition_information->StartingOffset.QuadPart = 0;
			partition_information->PartitionLength.QuadPart = length;
			partition_information->HiddenSectors = 1;
			partition_information->PartitionNumber = 0;
			partition_information->PartitionType = 0;
			partition_information->BootIndicator = FALSE;
			partition_information->RecognizedPartition = FALSE;
			partition_information->RewritePartition = FALSE;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);

			break;
		}

		//�������Ƿ�Ϊֻ��
		case IOCTL_DISK_IS_WRITABLE:
		{
			if (!device_extension->read_only)
			{
				status = STATUS_SUCCESS;
			}
			else
			{
				status = STATUS_MEDIA_WRITE_PROTECTED;
			}
			irp->IoStatus.Information = 0;
			break;
		}

		case IOCTL_DISK_MEDIA_REMOVAL:

		//���ô��̷�����Ϣ
		case IOCTL_DISK_SET_PARTITION_INFO:
		{
			if (device_extension->read_only)
			{
				status = STATUS_MEDIA_WRITE_PROTECTED;
				irp->IoStatus.Information = 0;
				break;
			}

			if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
				sizeof(SET_PARTITION_INFORMATION))
			{
				status = STATUS_INVALID_PARAMETER;
				irp->IoStatus.Information = 0;
				break;
			}

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;

			break;
		}

		//��δ֪������
		default:
		{
			KdPrint((
				"FileDisk: Unknown IoControlCode %#x\n",
				io_stack->Parameters.DeviceIoControl.IoControlCode
				));

			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
		}
	}

}



//
//���Ӵ���ӳ��
//
NTSTATUS
NetDiskConnect(IN PDEVICE_OBJECT   DeviceObject,IN PIRP	irp)
{
	PDEVICE_EXTENSION       device_extension;
	PNET_DISK_INFORMATION  http_disk_information;
	HTTP_HEADER             http_header;

	PAGED_CODE();

	ASSERT(DeviceObject != NULL);
	ASSERT(irp != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	http_disk_information = (PNET_DISK_INFORMATION)irp->AssociatedIrp.SystemBuffer;

	device_extension->address = http_disk_information->Address;

	device_extension->port = http_disk_information->Port;

	device_extension->host_name = ExAllocatePoolWithTag(NonPagedPool, http_disk_information->HostNameLength + 1, NET_DISK_POOL_TAG);

	if (device_extension->host_name == NULL)
	{
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		return irp->IoStatus.Status;
	}

	RtlCopyMemory(
		device_extension->host_name,
		http_disk_information->HostName,
		http_disk_information->HostNameLength
	);

	device_extension->host_name[http_disk_information->HostNameLength] = '\0';

	device_extension->file_name = ExAllocatePoolWithTag(NonPagedPool, http_disk_information->FileNameLength + 1, NET_DISK_POOL_TAG);

	if (device_extension->file_name == NULL)
	{
		if (device_extension->host_name != NULL)
		{
			ExFreePool(device_extension->host_name);
			device_extension->host_name = NULL;
		}

		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		return irp->IoStatus.Status;
	}

	RtlCopyMemory(
		device_extension->file_name,
		http_disk_information->FileName,
		http_disk_information->FileNameLength
	);

	device_extension->file_name[http_disk_information->FileNameLength] = '\0';

	HttpGetHeader(
		device_extension->address,
		device_extension->port,
		device_extension->host_name,
		device_extension->file_name,
		&irp->IoStatus,
		&http_header
	);

	if (!NT_SUCCESS(irp->IoStatus.Status))
	{
		DbgPrint("retrying get header\n");
		HttpGetHeader(
			device_extension->address,
			device_extension->port,
			device_extension->host_name,
			device_extension->file_name,
			&irp->IoStatus,
			&http_header
		);
	}

	if (!NT_SUCCESS(irp->IoStatus.Status))
	{
		DbgPrint("HttpDisk: get header failed\n");

		if (device_extension->host_name != NULL)
		{
			ExFreePool(device_extension->host_name);
			device_extension->host_name = NULL;
		}

		if (device_extension->file_name != NULL)
		{
			ExFreePool(device_extension->file_name);
			device_extension->file_name = NULL;
		}

		return irp->IoStatus.Status;
	}

	device_extension->file_size.QuadPart = http_header.ContentLength.QuadPart;

	device_extension->media_in_device = TRUE;

	return irp->IoStatus.Status;
}



//
//�Ͽ�����ӳ��
//
NTSTATUS
NetDiskDisconnect(IN PDEVICE_OBJECT DeviceObject,IN PIRP irp)
{
	PDEVICE_EXTENSION device_extension;

	PAGED_CODE();

	ASSERT(DeviceObject != NULL);
	ASSERT(irp != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	device_extension->media_in_device = FALSE;

	if (device_extension->host_name != NULL)
	{
		ExFreePool(device_extension->host_name);
		device_extension->host_name = NULL;
	}

	if (device_extension->file_name != NULL)
	{
		ExFreePool(device_extension->file_name);
		device_extension->file_name = NULL;
	}

	if (device_extension->socket != -1)
	{
		close(device_extension->socket);
		device_extension->socket = -1;
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	return STATUS_SUCCESS;
}

	



//
//��д�߳�
//
VOID VDiskThread(PVOID Context) {
	PDEVICE_OBJECT      device_object;
	PDEVICE_EXTENSION   device_extension;
	PLIST_ENTRY         request;
	PIRP                irp;
	PIO_STACK_LOCATION  io_stack;

	ASSERT(Context != NULL);

	device_object = (PDEVICE_OBJECT)Context;

	device_extension = (PDEVICE_EXTENSION)device_object->DeviceExtension;

	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);


	for (;;)
	{
		//�ȴ������¼�����

		KeWaitForSingleObject(&device_extension->request_event, Executive, KernelMode, FALSE, NULL);

		if (device_extension->terminate_thread)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		//�������Ƴ�����ڵ㣬�������д����
		while ((request = ExInterlockedRemoveHeadList(&device_extension->list_head, &device_extension->list_lock)) != NULL)
		{
			irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

			io_stack = IoGetCurrentIrpStackLocation(irp);

			switch (io_stack->MajorFunction)
			{
				//ʹ��KSocket���ṩ��TDI������ļ�
			case IRP_MJ_READ:
				HttpGetBlock(
					&device_extension->socket,
					device_extension->address,
					device_extension->port,
					device_extension->host_name,
					device_extension->file_name,
					&io_stack->Parameters.Read.ByteOffset,
					io_stack->Parameters.Read.Length,
					&irp->IoStatus,
					MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority)
				);
				if (!NT_SUCCESS(irp->IoStatus.Status))
				{
					DbgPrint("VDisk: retrying get block: offset=%I64u length=%u\n", io_stack->Parameters.Read.ByteOffset.QuadPart, io_stack->Parameters.Read.Length);
					HttpGetBlock(
						&device_extension->socket,
						device_extension->address,
						device_extension->port,
						device_extension->host_name,
						device_extension->file_name,
						&io_stack->Parameters.Read.ByteOffset,
						io_stack->Parameters.Read.Length,
						&irp->IoStatus,
						MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority)
					);
					if (!NT_SUCCESS(irp->IoStatus.Status))
					{
						DbgPrint("VDisk: get block failed\n");
					}
				}
				break;



			case IRP_MJ_WRITE:
				irp->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
				irp->IoStatus.Information = 0;
				break;

			case IRP_MJ_DEVICE_CONTROL:
				switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
				{
				case IOCTL_DISK_CONNECT:
					irp->IoStatus.Status = HttpDiskConnect(device_object, irp);
					break;

				case IOCTL_DISK_DISCONNECT:
					irp->IoStatus.Status = HttpDiskDisconnect(device_object, irp);
					break;

				default:
					irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
				}
				break;

				//����������
				IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
			}
		}
	}
}




//
//�����豸
//
VDiskCreateDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number,
	IN DEVICE_TYPE      DeviceType
)
{
	UNICODE_STRING		device_name;
	NTSTATUS			status;
	PDEVICE_OBJECT		device_object;
	PDEVICE_EXTENSION	device_extension;
	HANDLE				thread_handle;
	UNICODE_STRING		sddl;

	ASSERT(DriverObject != NULL);

	device_name.Buffer = (PWCHAR)ExAllocatePoolWithTag(PagedPool, MAXIMUM_FILENAME_LENGTH * 2, NET_DISK_POOL_TAG);

	if (device_name.Buffer == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	device_name.Length = 0;
	device_name.MaximumLength = MAXIMUM_FILENAME_LENGTH * 2;

	RtlUnicodeStringPrintf(&device_name, DEVICE_NAME_PREFIX L"%u", Number);

	RtlInitUnicodeString(&sddl, _T("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;BU)"));


	status = IoCreateDeviceSecure(
		DriverObject,
		sizeof(DEVICE_EXTENSION),
		&device_name,
		DeviceType,
		0,
		FALSE,
		&sddl,
		NULL,
		&device_object
	);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_name.Buffer);
		return status;
	}
	device_object->Flags |= DO_DIRECT_IO;

	device_extension = (PDEVICE_EXTENSION)device_object->DeviceExtension;

	device_extension->media_in_device = FALSE;

	device_extension->device_name.Length = device_name.Length;
	device_extension->device_name.MaximumLength = device_name.MaximumLength;
	device_extension->device_name.Buffer = device_name.Buffer;
	device_extension->device_number = Number;
	device_extension->device_type = DeviceType;

	device_extension->host_name = NULL;

	device_extension->file_name = NULL;

	device_extension->socket = -1;

	device_object->Characteristics |= FILE_READ_ONLY_DEVICE;

	InitializeListHead(&device_extension->list_head);

	KeInitializeSpinLock(&device_extension->list_lock);

	KeInitializeEvent(
		&device_extension->request_event,
		SynchronizationEvent,
		FALSE
	);

	device_extension->terminate_thread = FALSE;

	status = PsCreateSystemThread(
		&thread_handle,
		(ACCESS_MASK)0L,
		NULL,
		NULL,
		NULL,
		VDiskThread,
		device_object
	);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device_object);
		ExFreePool(device_name.Buffer);
		return status;
	}

	status = ObReferenceObjectByHandle(
		thread_handle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&device_extension->thread_pointer,
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		ZwClose(thread_handle);

		device_extension->terminate_thread = TRUE;

		KeSetEvent(
			&device_extension->request_event,
			(KPRIORITY)0,
			FALSE
		);

		IoDeleteDevice(device_object);

		ExFreePool(device_name.Buffer);

		return status;
	}

	ZwClose(thread_handle);

	return STATUS_SUCCESS;

}





NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING              parameter_path;
	RTL_QUERY_REGISTRY_TABLE    query_table[2];
	ULONG                       n_devices;
	NTSTATUS                    status;
	UNICODE_STRING              device_dir_name;
	OBJECT_ATTRIBUTES           object_attributes;
	ULONG                       n;
	USHORT                      n_created_devices;

	//
	//������ʼ����
	//
	DbgPrint("Sample Disk Driver Running\n");

	NTSTATUS status = STATUS_SUCCESS;

	parameter_path.Length = 0;

	parameter_path.MaximumLength = RegistryPath->Length + sizeof(PARAMETER_KEY);

	parameter_path.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, parameter_path.MaximumLength, NET_DISK_POOL_TAG);

	if (parameter_path.Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;		//��������Դ����
	}

	RtlCopyUnicodeString(&parameter_path, RegistryPath);

	RtlAppendUnicodeToString(&parameter_path, PARAMETER_KEY);

	RtlZeroMemory(&query_table[0], sizeof(query_table));

	query_table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
	query_table[0].Name = NUMBEROFDEVICES_VALUE;
	query_table[0].EntryContext = &n_devices;

	status = RtlQueryRegistryValues(
		RTL_REGISTRY_ABSOLUTE,
		parameter_path.Buffer,
		&query_table[0],
		NULL,
		NULL
	);

	ExFreePool(parameter_path.Buffer);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Query registry failed, using default values.\n");
		n_devices = 4;
	}

	RtlInitUnicodeString(&device_dir_name, DEVICE_NAME_BASE);

	InitializeObjectAttributes(
		&object_attributes,
		&device_dir_name,
		OBJ_PERMANENT,
		NULL,
		NULL
	);

	status = ZwCreateDirectoryObject(
		&dir_handle,
		DIRECTORY_ALL_ACCESS,
		&object_attributes
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	ZwMakeTemporaryObject(dir_handle);

	for (n = 0, n_created_devices = 0; n < n_devices; n++)
	{
		status = VDiskCreateDevice(DriverObject, n, FILE_DEVICE_DISK);

		if (NT_SUCCESS(status))
		{
			n_created_devices++;
		}
	}

	for (n = 0; n < n_devices; n++)
	{
		status = VDiskCreateDevice(DriverObject, n, FILE_DEVICE_CD_ROM);

		if (NT_SUCCESS(status))
		{
			n_created_devices++;
		}
	}

	if (n_created_devices == 0)
	{
		ZwClose(dir_handle);
		return status;
	}





	/*


	WSK_CLIENT_NPI wskClientNpi;

	//
	//����
	//
	UNICODE_STRING devicename = { 0 };
	RtlInitUnicodeString(&devicename, DEVICE_NAME);

	WSK_CLIENT_NPI wskClientNpi;
	//
	//ע��wskӦ�ó���
	//
	wskClientNpi.ClientContext = NULL;
	wskClientNpi.Dispatch = &WskAppDispatch;
	status = WskRegister(&wskClientNpi, &WskRegistration);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Register Wsk Failed:%x\n", status);
		return status;
	}

	//
	//�����׽���
	//
	status = WskAppWorkerRoutine();
	if (!NT_SUCCESS(status)) {
		DbgPrint("Create Socket Failed:%x\n", status);
		return status;
	}


	//
	//��Ŀ�꽨������
	//
	SOCKADDR_IN addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(800);
	addr.sin_addr.s_addr = inet_addr("192.168.43.59");

	status = ConnectSocket(socketcontext.Socket, (PSOCKADDR)&addr);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Connect to Server Failed:%x\n", status);
		return status;
	}

	//
	//�����豸
	//
	PDEVICE_OBJECT pdevice = NULL;
	status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION),
		&devicename, FILE_DEVICE_DISK, 0, FALSE, &pdevice);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Create Device Failed:%x\n", status);
		return status;
	}

	//
	//����ϵͳ�߳�
	//
	HANDLE thread_handle;
	status = PsCreateSystemThread(&thread_handle, (ACCESS_MASK)0L, NULL, NULL, NULL, VDiskThread, pdevice);

	//
	//������������
	//
	UNICODE_STRING symname = { 0 };
	RtlInitUnicodeString(&symname, SYM_NAME);
	status = IoCreateSymbolicLink(&symname, &devicename);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Create SymbolLink Failed:%x\n", status);
		IoDeleteDevice(pdevice);
		return status;
	}

	*/
	//
	//�������̷ַ�
	//
	DriverObject->MajorFunction[IRP_MJ_CREATE] = VDiskCreateClose;		//�򿪲���
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = VDiskCreateClose;		//�رղ���
	DriverObject->MajorFunction[IRP_MJ_READ] = VDiskReadWrite;			//������
	DriverObject->MajorFunction[IRP_MJ_WRITE] = VDiskReadWrite;			//д����
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VDiskDeviceControl;	//�豸����

	//
	//ж������
	//
	DriverObject->DriverUnload = VDiskUnload;


	return status;
}