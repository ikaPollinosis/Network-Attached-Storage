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


#define DEVICE_NAME_BASE			L"\\Device\\VDisk"		//设备名

#define DEVICE_NAME_PREFIX			DEVICE_NAME_BASE  L"\\VDisk"
#define SYM_NAME					L"\\??\\VDisk"			//符号连接

#define PARAMETER_KEY				L"\\Parameters"

#define NUMBEROFDEVICES_VALUE		L"NumberOfDevices"

#define TOKEN_SOURCE_LENGTH 8

#define BUFFER_SIZE             (4096 * 4)

#define NET_DISK_POOL_TAG      'ksiD'

HANDLE dir_handle;

//
//例程声明
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


//设备扩展
typedef struct _DEVICE_EXTENSION {
	BOOLEAN							media_in_device;			//是否连接物理媒介
	HANDLE							file_handle;				//文件句柄
	FILE_STANDARD_INFORMATION		file_information;			//文件信息
	BOOLEAN							read_only;					//只读
	PSECURITY_CONTEXT_TRACKING_MODE security_client_context;	//安全性上下文
	LIST_ENTRY						list_head;					//irp链表头
	KSPIN_LOCK						list_lock;					//链表读写同步锁
	KEVENT							request_event;				//处理链表请求事件
	PVOID							thread_pointer;				//线程指针
	BOOLEAN							terminate_thread;			//是否终止线程
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
//删除设备
// 
PDEVICE_OBJECT VDiskDeleteDevice(PDEVICE_OBJECT DeviceObject) {
	PDEVICE_EXTENSION   device_extension;
	PDEVICE_OBJECT      next_device_object;
	ASSERT(DeviceObject = NULL);

	// 得到设备扩展
	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	// 设置线程终止标志
	device_extension->terminate_thread = TRUE;
	// 设置启动事件
	KeSetEvent(
		&device_extension->request_event,
		(KPRIORITY)0,
		FALSE
	);
	// 等待线程的结束
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
//驱动卸载例程
//
VOID 
VDiskUnload(PDRIVER_OBJECT DriverObject) {
	DbgPrint("Driver Unloaded\n");

	PDEVICE_OBJECT device_object;

	device_object = DriverObject->DeviceObject;
	//若设备存在则进行删除
	while (device_object) {
		device_object = VDiskDeleteDevice(device_object);
	}
	ZwClose(dir_handle);
}




//
//创建、关闭设备例程
//
NTSTATUS 
VDiskCreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	//PAGED_CODE();		调试使用的宏
	UNREFERENCED_PARAMETER(DeviceObject);		//略过未使用的参数
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = FILE_OPENED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//
//清除设备例程
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
//读写例程
//
NTSTATUS 
VDiskReadWrite(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	PDEVICE_EXTENSION device_extension;
	PIO_STACK_LOCATION io_stack;


	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	//检查是否连接了物理设备
	if (!device_extension->media_in_device)
	{
		irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_NO_MEDIA_IN_DEVICE;
	}
	//获取irp当前栈空间
	io_stack = IoGetCurrentIrpStackLocation(irp);
	//读0长的时候直接返回成功
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
	);	//写入链表

	//线程循环运行
	KeSetEvent(
		&device_extension->request_event,
		(KPRIORITY)0,
		FALSE
	);
	return STATUS_PENDING;

	//具体的读写在处理线程中完成
}





//
//设备控制例程
//
NTSTATUS VDiskDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	PDEVICE_EXTENSION device_extension;
	PIO_STACK_LOCATION io_stack;
	NTSTATUS status;
	//获取当前设备扩展
	device_extension = DeviceObject->DeviceExtension;

	//获取设备栈
	io_stack = IoGetCurrentIrpStackLocation(irp);

	//判断是否加载虚拟磁盘
	if (!device_extension->media_in_device && io_stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_DISK_CONNECT) {
		irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_MEDIA_IN_DEVICE;
	}

	//根据不同功能号进行设备控制
	switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
	{

		//连接、断开连接处理
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



		//检查磁盘有效性的功能号,直接返回有效
		case IOCTL_DISK_CHECK_VERIFY:
		case IOCTL_CDROM_CHECK_VERIFY:
		case IOCTL_STORAGE_CHECK_VERIFY:
		case IOCTL_STORAGE_CHECK_VERIFY2:
		{
			status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			break;
		}


		//获取物理属性功能号
		case IOCTL_DISK_GET_DRIVE_GEOMETRY:
		case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
		{
			PDISK_GEOMETRY disk_geometry;
			ULONGLONG length;
			ULONG	sector_size = 2048;

			//设备栈缓冲区过小
			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DISK_GEOMETRY)) {
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			disk_geometry = (PDISK_GEOMETRY)irp->AssociatedIrp.SystemBuffer;
			length = device_extension->file_information.AllocationSize.QuadPart;
			disk_geometry->Cylinders.QuadPart = length / MM_MAXIMUM_DISK_IO_SIZE;	//磁柱
			disk_geometry->MediaType = FixedMedia;									//媒介类型
			disk_geometry->TracksPerCylinder = MM_MAXIMUM_DISK_IO_SIZE / PAGE_SIZE; //每个磁柱的磁道数
			disk_geometry->SectorsPerTrack = PAGE_SIZE / sector_size;				//磁道扇区数
			disk_geometry->BytesPerSector = sector_size;							//扇区的字节数


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

		//获取分区信息功能号
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

		//检测磁盘是否为只读
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

		//设置磁盘分区信息
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

		//对未知操作码
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
//连接磁盘映像
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
//断开磁盘映像
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
//读写线程
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
		//等待处理事件请求

		KeWaitForSingleObject(&device_extension->request_event, Executive, KernelMode, FALSE, NULL);

		if (device_extension->terminate_thread)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		//利用锁移除链表节点，并处理读写请求
		while ((request = ExInterlockedRemoveHeadList(&device_extension->list_head, &device_extension->list_lock)) != NULL)
		{
			irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

			io_stack = IoGetCurrentIrpStackLocation(irp);

			switch (io_stack->MajorFunction)
			{
				//使用KSocket中提供的TDI程序读文件
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

				//最后完成请求
				IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
			}
		}
	}
}




//
//创建设备
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
	//驱动开始运行
	//
	DbgPrint("Sample Disk Driver Running\n");

	NTSTATUS status = STATUS_SUCCESS;

	parameter_path.Length = 0;

	parameter_path.MaximumLength = RegistryPath->Length + sizeof(PARAMETER_KEY);

	parameter_path.Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, parameter_path.MaximumLength, NET_DISK_POOL_TAG);

	if (parameter_path.Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;		//缓冲区资源不足
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
	//命名
	//
	UNICODE_STRING devicename = { 0 };
	RtlInitUnicodeString(&devicename, DEVICE_NAME);

	WSK_CLIENT_NPI wskClientNpi;
	//
	//注册wsk应用程序
	//
	wskClientNpi.ClientContext = NULL;
	wskClientNpi.Dispatch = &WskAppDispatch;
	status = WskRegister(&wskClientNpi, &WskRegistration);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Register Wsk Failed:%x\n", status);
		return status;
	}

	//
	//创建套接字
	//
	status = WskAppWorkerRoutine();
	if (!NT_SUCCESS(status)) {
		DbgPrint("Create Socket Failed:%x\n", status);
		return status;
	}


	//
	//与目标建立连接
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
	//创建设备
	//
	PDEVICE_OBJECT pdevice = NULL;
	status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION),
		&devicename, FILE_DEVICE_DISK, 0, FALSE, &pdevice);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Create Device Failed:%x\n", status);
		return status;
	}

	//
	//生成系统线程
	//
	HANDLE thread_handle;
	status = PsCreateSystemThread(&thread_handle, (ACCESS_MASK)0L, NULL, NULL, NULL, VDiskThread, pdevice);

	//
	//创建符号连接
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
	//进行例程分发
	//
	DriverObject->MajorFunction[IRP_MJ_CREATE] = VDiskCreateClose;		//打开操作
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = VDiskCreateClose;		//关闭操作
	DriverObject->MajorFunction[IRP_MJ_READ] = VDiskReadWrite;			//读操作
	DriverObject->MajorFunction[IRP_MJ_WRITE] = VDiskReadWrite;			//写操作
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VDiskDeviceControl;	//设备控制

	//
	//卸载例程
	//
	DriverObject->DriverUnload = VDiskUnload;


	return status;
}