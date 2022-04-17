#include <ntifs.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <mountmgr.h>
#include <ntddvol.h>
#include <ntddscsi.h>
#include "ksocket.h"
#include "vdisk.h"

#ifndef _PREFAST_
#pragma warning(disable:4068)
#endif // !_PREFAST_

#define NET_DISK_POOL_TAG      'ksiD'

#define PARAMETER_KEY				L"\\Parameters"

#define NUMBEROFDEVICES_VALUE		L"NumberOfDevices"

#define DEFAULT_NUMBEROFDEVICES 4

#define TOC_DATA_TRACK			0x04

#define BUFFER_SIZE             (4096 * 4)


HANDLE dir_handle;



typedef struct _NET_HEADER {
	LARGE_INTEGER ContentLength;
} NET_HEADER, * PNET_HEADER;



//设备扩展
typedef struct _DEVICE_EXTENSION {
	BOOLEAN							media_in_device;			//是否连接物理媒介
	UNICODE_STRING					device_name;				//设备名
	ULONG							device_number;				//设备号
	DEVICE_TYPE						device_type;				//设备类型
	ULONG							address;					//IP地址
	USHORT							port;						//端口
	PUCHAR							host_name;					//主机名
	PUCHAR							file_name;					//磁盘映像文件名
	LARGE_INTEGER					file_size;					//映像大小
	INT_PTR							socket;						//设备对应的套接字
	LIST_ENTRY						list_head;					//irp链表头
	KSPIN_LOCK						list_lock;					//链表读写自旋锁
	KEVENT							request_event;				//处理链表请求事件
	PVOID							thread_pointer;				//线程指针
	BOOLEAN							terminate_thread;			//是否终止线程
}DEVICE_EXTENSION, * PDEVICE_EXTENSION;

#ifdef _PREFAST_
DRIVER_INITIALIZE DriverEntry;
__drv_dispatchType(IRP_MJ_CREATE) __drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH VDiskCreateClose;
__drv_dispatchType(IRP_MJ_READ) __drv_dispatchType(IRP_MJ_WRITE) DRIVER_DISPATCH VDiskReadWrite;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH VDiskDeviceControl;
KSTART_ROUTINE VDiskThread;
DRIVER_UNLOAD VDiskUnload;
#endif // _PREFAST_


//
// 例程声明
//

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT   DriverObject,
	IN PUNICODE_STRING  RegistryPath
);

NTSTATUS
VDiskCreateDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number,
	IN DEVICE_TYPE      DeviceType
);


VOID
VDiskUnload(
	IN PDRIVER_OBJECT   DriverObject
);

PDEVICE_OBJECT
VDiskDeleteDevice(
	IN PDEVICE_OBJECT   DeviceObject
);

NTSTATUS
VDiskCreateClose(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
VDiskReadWrite(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);


NTSTATUS
VDiskDeviceControl(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);


VOID
VDiskThread(
	IN PVOID            Context
);

NTSTATUS
NetDiskConnect(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
NetDiskDisconnect(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);


NTSTATUS
HttpGetHeader(
	IN ULONG                Address,
	IN USHORT               Port,
	IN PUCHAR               HostName,
	IN PUCHAR               FileName,
	OUT PIO_STATUS_BLOCK    IoStatus,
	OUT PNET_HEADER         HttpHeader
);

NTSTATUS
HttpGetBlock(
	IN INT_PTR* Socket,
	IN ULONG                Address,
	IN USHORT               Port,
	IN PUCHAR               HostName,
	IN PUCHAR               FileName,
	IN PLARGE_INTEGER       Offset,
	IN ULONG                Length,
	OUT PIO_STATUS_BLOCK    IoStatus,
	OUT PVOID               SystemBuffer
);




__int64 __cdecl _atoi64(const char*);

#pragma code_seg("INIT")

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
		n_devices = DEFAULT_NUMBEROFDEVICES;
	}

	RtlInitUnicodeString(&device_dir_name, DEVICE_DIR_NAME);

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
	if (DeviceType == FILE_DEVICE_CD_ROM)
	{
		RtlUnicodeStringPrintf(&device_name, DEVICE_NAME_PREFIX L"Cd" L"%u", Number);
	}
	else
	{
		RtlUnicodeStringPrintf(&device_name, DEVICE_NAME_PREFIX L"Disk" L"%u", Number);
	}

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

	// 初始化中断请求链表头
	InitializeListHead(&device_extension->list_head);

	// 初始化自旋锁
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

#pragma code_seg("PAGE")


//
//驱动卸载例程
//
VOID
VDiskUnload(PDRIVER_OBJECT DriverObject) {
	DbgPrint("Driver Unloading\n");

	PDEVICE_OBJECT device_object;
	PAGED_CODE();
	device_object = DriverObject->DeviceObject;
	//若设备存在则进行删除
	while (device_object) {
		device_object = VDiskDeleteDevice(device_object);
	}
	ZwClose(dir_handle);
}

//
//删除设备
// 
PDEVICE_OBJECT VDiskDeleteDevice(PDEVICE_OBJECT DeviceObject) {
	PDEVICE_EXTENSION   device_extension;
	PDEVICE_OBJECT      next_device_object;

	PAGED_CODE();

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

#pragma prefast( suppress: 28175, "allowed in unload" )

	next_device_object = DeviceObject->NextDevice;

	IoDeleteDevice(DeviceObject);

	return next_device_object;
}


#pragma code_seg()





//
//创建、关闭设备例程
//
NTSTATUS 
VDiskCreateClose(
	IN PDEVICE_OBJECT DeviceObject, 
	IN PIRP irp
	)
{

	UNREFERENCED_PARAMETER(DeviceObject);		//略过未使用的参数

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = FILE_OPENED;

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
	
	

	// 写入链表
	ExInterlockedInsertTailList(&device_extension->list_head,
		&irp->Tail.Overlay.ListEntry,
		// 链表加锁，插入节点并解锁
		&device_extension->list_lock
	);

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


		// 写入链表
		ExInterlockedInsertTailList(
			&device_extension->list_head,
			&irp->Tail.Overlay.ListEntry,
			// 链表加锁，插入节点并解锁
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


		// 写入链表
		ExInterlockedInsertTailList(
			&device_extension->list_head,
			&irp->Tail.Overlay.ListEntry,
			// 链表加锁，插入节点并解锁
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
			ULONG	sector_size;

			//设备栈缓冲区过小
			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DISK_GEOMETRY)) {
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			disk_geometry = (PDISK_GEOMETRY)irp->AssociatedIrp.SystemBuffer;
			length = device_extension->file_size.QuadPart;

			if (device_extension->device_type != FILE_DEVICE_CD_ROM)
			{
				sector_size = 512;
			}
			else
			{
				sector_size = 2048;
			}

			disk_geometry->Cylinders.QuadPart = length / sector_size / 32 / 2;	// 磁柱
			disk_geometry->MediaType = FixedMedia;	 								// 媒介类型
			disk_geometry->TracksPerCylinder = 2; // 每个磁柱的磁道数
			disk_geometry->SectorsPerTrack = 32;				// 磁道扇区数
			disk_geometry->BytesPerSector = sector_size;							// 扇区的字节数


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

		// 获取分区信息功能号

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

			length = device_extension->file_size.QuadPart;

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

			length = device_extension->file_size.QuadPart;

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
		

		//检测磁盘是否为只读
		case IOCTL_DISK_IS_WRITABLE:
		{
			status = STATUS_MEDIA_WRITE_PROTECTED;
			irp->IoStatus.Information = 0;
			break;
		}

		case IOCTL_DISK_MEDIA_REMOVAL:


		case IOCTL_CDROM_READ_TOC:
		{
			PCDROM_TOC cdrom_toc;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(CDROM_TOC))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			cdrom_toc = (PCDROM_TOC)irp->AssociatedIrp.SystemBuffer;

			RtlZeroMemory(cdrom_toc, sizeof(CDROM_TOC));

			cdrom_toc->FirstTrack = 1;
			cdrom_toc->LastTrack = 1;
			cdrom_toc->TrackData[0].Control = TOC_DATA_TRACK;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(CDROM_TOC);

			break;
		}

		case IOCTL_CDROM_GET_LAST_SESSION:
		{
			PCDROM_TOC_SESSION_DATA cdrom_toc_s_d;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(CDROM_TOC_SESSION_DATA))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			cdrom_toc_s_d = (PCDROM_TOC_SESSION_DATA)irp->AssociatedIrp.SystemBuffer;

			RtlZeroMemory(cdrom_toc_s_d, sizeof(CDROM_TOC_SESSION_DATA));

			cdrom_toc_s_d->FirstCompleteSession = 1;
			cdrom_toc_s_d->LastCompleteSession = 1;
			cdrom_toc_s_d->TrackData[0].Control = TOC_DATA_TRACK;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(CDROM_TOC_SESSION_DATA);

			break;
		}


		// 设置磁盘分区信息
		case IOCTL_DISK_SET_PARTITION_INFO:
		{

			status = STATUS_MEDIA_WRITE_PROTECTED;
			irp->IoStatus.Information = 0;
			break;
		}

		// 磁盘验证
		case IOCTL_DISK_VERIFY:
		{
			PVERIFY_INFORMATION verify_information;

			if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
				sizeof(VERIFY_INFORMATION))
			{
				status = STATUS_INVALID_PARAMETER;
				irp->IoStatus.Information = 0;
				break;
			}

			verify_information = (PVERIFY_INFORMATION)irp->AssociatedIrp.SystemBuffer;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = verify_information->Length;

			break;
		}

		// 获取设备号
		case IOCTL_STORAGE_GET_DEVICE_NUMBER:
		{
			PSTORAGE_DEVICE_NUMBER number;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(STORAGE_DEVICE_NUMBER))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			number = (PSTORAGE_DEVICE_NUMBER)irp->AssociatedIrp.SystemBuffer;

			number->DeviceType = device_extension->device_type;
			number->DeviceNumber = device_extension->device_number;
			number->PartitionNumber = (ULONG)-1;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(STORAGE_DEVICE_NUMBER);

			break;
		}


		case IOCTL_STORAGE_GET_HOTPLUG_INFO:
		{
			PSTORAGE_HOTPLUG_INFO info;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(STORAGE_HOTPLUG_INFO))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			info = (PSTORAGE_HOTPLUG_INFO)irp->AssociatedIrp.SystemBuffer;

			info->Size = sizeof(STORAGE_HOTPLUG_INFO);
			info->MediaRemovable = 0;
			info->MediaHotplug = 0;
			info->DeviceHotplug = 0;
			info->WriteCacheEnableOverride = 0;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(STORAGE_HOTPLUG_INFO);

			break;
		}


		case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
		{
			PVOLUME_GET_GPT_ATTRIBUTES_INFORMATION attr;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			attr = (PVOLUME_GET_GPT_ATTRIBUTES_INFORMATION)irp->AssociatedIrp.SystemBuffer;

			attr->GptAttributes = 0;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION);

			break;
		}


		case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
		{
			PVOLUME_DISK_EXTENTS ext;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(VOLUME_DISK_EXTENTS))
			{
				status = STATUS_INVALID_PARAMETER;
				irp->IoStatus.Information = 0;
				break;
			}
			
			
			ext = (PVOLUME_DISK_EXTENTS)irp->AssociatedIrp.SystemBuffer;

			ext->NumberOfDiskExtents = 1;
			ext->Extents[0].DiskNumber = device_extension->device_number;
			ext->Extents[0].StartingOffset.QuadPart = 0;
			ext->Extents[0].ExtentLength.QuadPart = device_extension->file_size.QuadPart;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(VOLUME_DISK_EXTENTS);

			break;
		}

		case IOCTL_DISK_IS_CLUSTERED:
		{
			PBOOLEAN clus;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(BOOLEAN))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				irp->IoStatus.Information = 0;
				break;
			}

			clus = (PBOOLEAN)irp->AssociatedIrp.SystemBuffer;

			*clus = FALSE;

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(BOOLEAN);

			break;
		}

		case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
		{
			PMOUNTDEV_NAME name;

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				sizeof(MOUNTDEV_NAME))
			{
				status = STATUS_INVALID_PARAMETER;
				irp->IoStatus.Information = 0;
				break;
			}

			name = (PMOUNTDEV_NAME)irp->AssociatedIrp.SystemBuffer;
			name->NameLength = device_extension->device_name.Length * sizeof(WCHAR);

			if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
				name->NameLength + sizeof(USHORT))
			{
				status = STATUS_BUFFER_OVERFLOW;
				irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
				break;
			}

			RtlCopyMemory(name->Name, device_extension->device_name.Buffer, name->NameLength);

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = name->NameLength + sizeof(USHORT);

			break;
		}

		case IOCTL_CDROM_READ_TOC_EX:
		{
			KdPrint(("HttpDisk: unhandled ioctl IOCTL_CDROM_READ_TOC_EX\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}
		case IOCTL_DISK_GET_MEDIA_TYPES:
		{
			KdPrint(("HttpDisk: unhandled ioctl IOCTL_DISK_GET_MEDIA_TYPES\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}
		case 0x66001b:
		{
			KdPrint(("HttpDisk: unhandled ioctl FT_BALANCED_READ_MODE\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}
		case IOCTL_SCSI_GET_CAPABILITIES:
		{
			KdPrint(("HttpDisk: unhandled ioctl IOCTL_SCSI_GET_CAPABILITIES\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}
		case IOCTL_SCSI_PASS_THROUGH:
		{
			KdPrint(("HttpDisk: unhandled ioctl IOCTL_SCSI_PASS_THROUGH\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}
		case IOCTL_STORAGE_GET_MEDIA_TYPES_EX:
		{
			KdPrint(("HttpDisk: unhandled ioctl IOCTL_STORAGE_GET_MEDIA_TYPES_EX\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}
		case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:
		{
			KdPrint(("HttpDisk: unhandled ioctl IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}
		case IOCTL_STORAGE_QUERY_PROPERTY:
		{
			KdPrint(("HttpDisk: unhandled ioctl IOCTL_STORAGE_QUERY_PROPERTY\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}

		case IOCTL_VOLUME_QUERY_ALLOCATION_HINT:
		{
			KdPrint(("HttpDisk: unhandled ioctl IOCTL_VOLUME_QUERY_ALLOCATION_HINT\n"));
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
		}


		// 对未知操作码
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

	if (status != STATUS_PENDING)
	{
		irp->IoStatus.Status = status;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	return status;

}

#pragma code_seg("PAGE")

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

		//关闭自旋锁，移除链表节点，再打开自旋锁并处理读写请求
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
					irp->IoStatus.Status = NetDiskConnect(device_object, irp);
					break;

				case IOCTL_DISK_DISCONNECT:
					irp->IoStatus.Status = NetDiskDisconnect(device_object, irp);
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
//连接磁盘映像
//
NTSTATUS
NetDiskConnect(IN PDEVICE_OBJECT   DeviceObject,IN PIRP	irp)
{
	PDEVICE_EXTENSION       device_extension;
	PNET_DISK_INFORMATION  http_disk_information;
	NET_HEADER             http_header;

	PAGED_CODE();

	ASSERT(DeviceObject != NULL);
	ASSERT(irp != NULL);

	//设置服务器地址和端口
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
	//获取资源信息
	HttpGetHeader(
		device_extension->address,
		device_extension->port,
		device_extension->host_name,
		device_extension->file_name,
		&irp->IoStatus,
		&http_header
	);

	//获取资源信息失败，重试
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

	//失败，显示错误并释放资源
	if (!NT_SUCCESS(irp->IoStatus.Status))
	{
		DbgPrint("get header failed\n");

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
	
	//释放资源
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
//使用Http协议获取资源信息
//
NTSTATUS
HttpGetHeader(
	IN ULONG                Address,
	IN USHORT               Port,
	IN PUCHAR               HostName,
	IN PUCHAR               FileName,
	OUT PIO_STATUS_BLOCK    IoStatus,
	OUT PNET_HEADER        HttpHeader
)
{
	INT_PTR             kSocket;
	struct sockaddr_in  toAddr;
	int                 status, nSent, nRecv;
	char* request, * buffer, * pStr;

	PAGED_CODE();

	ASSERT(HostName != NULL);
	ASSERT(FileName != NULL);
	ASSERT(IoStatus != NULL);
	ASSERT(HttpHeader != NULL);

	request = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, NET_DISK_POOL_TAG);

	if (request == NULL)
	{
		IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		return IoStatus->Status;
	}

	buffer = ExAllocatePoolWithTag(PagedPool, BUFFER_SIZE, NET_DISK_POOL_TAG);

	if (buffer == NULL)
	{
		ExFreePool(request);
		IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		return IoStatus->Status;
	}

	kSocket = socket(AF_INET, SOCK_STREAM, 0);

	if (kSocket == -1)
	{
		KdPrint(("get header : socket() returned - 1\n"));
		ExFreePool(request);
		ExFreePool(buffer);
		IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		return IoStatus->Status;
	}

	toAddr.sin_family = AF_INET;
	toAddr.sin_port = Port;
	toAddr.sin_addr.s_addr = Address;

	status = connect(kSocket, (struct sockaddr*)&toAddr, sizeof(toAddr));

	if (status < 0)
	{
		KdPrint(("get header: connect() error: %#x\n", status));
		ExFreePool(request);
		ExFreePool(buffer);
		close(kSocket);
		IoStatus->Status = status;
		return IoStatus->Status;
	}

	//创建Http请求
	RtlStringCbPrintfA(
		request,
		PAGE_SIZE,
		"HEAD %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nUser-Agent: HttpDisk/10.2\r\nConnection: close\r\n\r\n",
		FileName,
		HostName
	);

	//发送Http请求
	nSent = send(kSocket, request, (int)strlen(request), 0);

	if (nSent < 0)
	{
		//发送失败，释放资源
		KdPrint(("get header: send() error: %#x\n", nSent));
		ExFreePool(request);
		ExFreePool(buffer);
		close(kSocket);
		IoStatus->Status = nSent;
		return IoStatus->Status;
	}
	if (nSent < (int)strlen(request))
	{
		//请求没有正确发送
		KdPrint(("get header: send() did not complete: %d < %d\n", nSent, (int)strlen(request)));
	}

	//接收服务器的返回报文
	nRecv = recv(kSocket, buffer, BUFFER_SIZE, 0);

	if (nRecv <= 0)
	{
		if (nRecv == 0)
		{
			//服务器连接断开，没有收到返回
			KdPrint(("get header: server disconnected\n"));
			IoStatus->Status = STATUS_NO_SUCH_FILE;
		}
		else
		{
			//接收错误
			KdPrint(("get header: recv() error: %#x\n", nRecv));
			IoStatus->Status = nRecv;
		}
		//接收报文失败，释放资源
		ExFreePool(request);
		ExFreePool(buffer);
		close(kSocket);
		return IoStatus->Status;
	}

	close(kSocket);

	buffer[BUFFER_SIZE - 1] = '\0';

	KdPrint(("get header HTTP response:\n"
		"-----------------------------------\n"
		"%.*s"
		"-----------------------------------\n",
		nRecv - 2, buffer
		));

	if (_strnicmp(buffer, "HTTP/1.1 200 OK", 15))
	{
		//收到的回复不成功
		if (_strnicmp(buffer, "HTTP/1.1 404 Not Found", 22))
		{
			//除404文件不存在的其他错误
			KdPrint(("get header error: other error than \'file not found\'\n"));
		}
		else
		{
			//404文件不存在
			KdPrint(("get header: file not found\n"));
		}
		ExFreePool(request);
		ExFreePool(buffer);
		IoStatus->Status = STATUS_NO_SUCH_FILE;
		return IoStatus->Status;
	}

	pStr = strstr(buffer, "Content-Length:");

	if (pStr == NULL || pStr + 16 >= buffer + BUFFER_SIZE)
	{
		KdPrint(("get header error: field \'Content-Length\' not found\n"));
		ExFreePool(request);
		ExFreePool(buffer);
		IoStatus->Status = STATUS_NO_SUCH_FILE;
		return IoStatus->Status;
	}

	HttpHeader->ContentLength.QuadPart = _atoi64(pStr + 16);

	if (HttpHeader->ContentLength.QuadPart == 0)
	{
		KdPrint(("get header error: field \'Content-Length\' not interpreted correctly\n"));
		ExFreePool(request);
		ExFreePool(buffer);
		IoStatus->Status = STATUS_NO_SUCH_FILE;
		return IoStatus->Status;
	}

	ExFreePool(request);
	ExFreePool(buffer);

	IoStatus->Status = STATUS_SUCCESS;
	IoStatus->Information = 0;

	return STATUS_SUCCESS;
}





//
//使用Http协议获取磁盘块
//
NTSTATUS
HttpGetBlock(
	IN INT_PTR				*Socket,
	IN ULONG                Address,
	IN USHORT               Port,
	IN PUCHAR               HostName,
	IN PUCHAR               FileName,
	IN PLARGE_INTEGER       Offset,
	IN ULONG                Length,
	OUT PIO_STATUS_BLOCK    IoStatus,
	OUT PVOID               SystemBuffer
)
{
	struct sockaddr_in  toAddr;
	int                 status, nSent, nRecv;
	unsigned int        dataLen;
	char* request, * buffer, * pDataPart;

	PAGED_CODE();

	//检测参数是否为空
	ASSERT(Socket != NULL);
	ASSERT(HostName != NULL);
	ASSERT(FileName != NULL);
	ASSERT(Offset != NULL);
	ASSERT(IoStatus != NULL);
	ASSERT(SystemBuffer != NULL);

	IoStatus->Information = 0;

	request = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, NET_DISK_POOL_TAG);

	if (request == NULL)
	{
		IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		return IoStatus->Status;
	}

	buffer = ExAllocatePoolWithTag(PagedPool, BUFFER_SIZE + 1, NET_DISK_POOL_TAG);

	if (buffer == NULL)
	{
		ExFreePool(request);
		IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		return IoStatus->Status;
	}


	//创建HTTP请求报文
	RtlStringCbPrintfA(
		request,
		PAGE_SIZE,
		"GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%I64u-%I64u\r\nAccept: */*\r\nUser-Agent: HttpDisk/10.2\r\n\r\n",
		FileName,
		HostName,
		Offset->QuadPart,
		Offset->QuadPart + Length - 1
	);

	//创建套接字
	if (*Socket == -1)
	{
		*Socket = socket(AF_INET, SOCK_STREAM, 0);
		if (*Socket == -1)
		{
			KdPrint(("get block: socket() returned -1\n"));
			ExFreePool(request);
			ExFreePool(buffer);
			IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			return IoStatus->Status;
		}

		toAddr.sin_family = AF_INET;
		toAddr.sin_port = Port;
		toAddr.sin_addr.s_addr = Address;


		//连接Http服务器
		status = connect(*Socket, (struct sockaddr*)&toAddr, sizeof(toAddr));

		if (status < 0)
		{
			KdPrint(("get block: connect() error: %#x\n", status));
			ExFreePool(request);
			ExFreePool(buffer);
			close(*Socket);
			*Socket = -1;
			IoStatus->Status = status;
			return IoStatus->Status;
		}
	}

	//向服务器发送请求报文，请求对应的块
	nSent = send(*Socket, request, (int)strlen(request), 0);

	if (nSent < 0)
	{
		//发送失败，重试
		KdPrint(("get block: send() error: %#x, retrying send()\n", nSent));

		close(*Socket);

		*Socket = socket(AF_INET, SOCK_STREAM, 0);

		if (*Socket == -1)
		{
			//套接字出错
			KdPrint(("get block: socket() returned -1\n"));
			ExFreePool(request);
			ExFreePool(buffer);
			IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			return IoStatus->Status;
		}

		toAddr.sin_family = AF_INET;
		toAddr.sin_port = Port;
		toAddr.sin_addr.s_addr = Address;
		//重新连接
		status = connect(*Socket, (struct sockaddr*)&toAddr, sizeof(toAddr));

		if (status < 0)
		{
			//连接状态出错
			KdPrint(("get block: connect() error: %#x\n", status));
			ExFreePool(request);
			ExFreePool(buffer);
			close(*Socket);
			*Socket = -1;
			IoStatus->Status = status;
			return IoStatus->Status;
		}

		nSent = send(*Socket, request, (int)strlen(request), 0);

		if (nSent < 0)
		{
			//发送失败
			KdPrint(("get block: send() error: %#x, returning\n", nSent));
			ExFreePool(request);
			ExFreePool(buffer);
			close(*Socket);
			*Socket = -1;
			IoStatus->Status = nSent;
			return IoStatus->Status;
		}
	}
	if (nSent < (int)strlen(request))
	{
		//请求没有正确发送
		KdPrint(("get block: send() did not complete: %d < %d\n", nSent, (int)strlen(request)));
	}
	//接收服务器的回复报文
	nRecv = recv(*Socket, buffer, BUFFER_SIZE, 0);

	if (nRecv <= 0)
	{
		if (nRecv == 0)
		{
			//服务器连接断开
			KdPrint(("get block: server disconnected, retrying both send() and recv()\n"));
		}
		else
		{
			//报文接受出错
			KdPrint(("get block: recv() error: %#x, retrying both send() and recv()\n", nRecv));
		}

		
		close(*Socket);

		*Socket = socket(AF_INET, SOCK_STREAM, 0);

		if (*Socket == -1)
		{
			KdPrint(("get block: socket() returned -1\n"));
			ExFreePool(request);
			ExFreePool(buffer);
			IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			return IoStatus->Status;
		}

		toAddr.sin_family = AF_INET;
		toAddr.sin_port = Port;
		toAddr.sin_addr.s_addr = Address;

		status = connect(*Socket, (struct sockaddr*)&toAddr, sizeof(toAddr));

		if (status < 0)
		{
			KdPrint(("get block: connect() error: %#x\n", status));
			ExFreePool(request);
			ExFreePool(buffer);
			close(*Socket);
			*Socket = -1;
			IoStatus->Status = status;
			return IoStatus->Status;
		}

		nSent = send(*Socket, request, (int)strlen(request), 0);

		if (nSent < 0)
		{
			KdPrint(("get block: send() error: %#x\n", nSent));
			ExFreePool(request);
			ExFreePool(buffer);
			close(*Socket);
			*Socket = -1;
			IoStatus->Status = nSent;
			return IoStatus->Status;
		}
		if (nSent < (int)strlen(request))
		{
			KdPrint(("get block: send() did not complete: %d < %d\n", nSent, (int)strlen(request)));
		}

		nRecv = recv(*Socket, buffer, BUFFER_SIZE, 0);

		if (nRecv <= 0)
		{
			if (nRecv == 0)
			{
				KdPrint(("get block: server disconnected, returning\n"));
			}
			else
			{
				KdPrint(("get block: recv() error: %#x, returning\n", nRecv));
			}
			ExFreePool(request);
			ExFreePool(buffer);
			close(*Socket);
			*Socket = -1;
			IoStatus->Status = nRecv;
			return IoStatus->Status;
		}
	}


	//检查接收到的报文

	buffer[BUFFER_SIZE] = '\0';

	if (_strnicmp(buffer, "HTTP/1.1 206 Partial Content", 28))
	{	
		//未正确接收对应的块
		//对应块不存在
		KdPrint(("get block error: field \'206 Partial Content\' not found\n"));
		ExFreePool(request);
		ExFreePool(buffer);
		close(*Socket);
		*Socket = -1;
		IoStatus->Status = STATUS_UNSUCCESSFUL;
		return IoStatus->Status;
	}

	pDataPart = strstr(buffer, "\r\n\r\n") + 4;

	if (pDataPart == NULL || pDataPart < buffer || pDataPart > buffer + BUFFER_SIZE)
	{
		//接收到的Http响应报文无效
		KdPrint(("get block error: invalid HTTP response\n"));
		ExFreePool(request);
		ExFreePool(buffer);
		close(*Socket);
		*Socket = -1;
		IoStatus->Status = STATUS_UNSUCCESSFUL;
		return IoStatus->Status;
	}

	dataLen = nRecv - (unsigned int)(pDataPart - buffer);

	if (dataLen > Length || pDataPart + dataLen > buffer + BUFFER_SIZE)
	{
		//收到的数据长度大于要求的长度，或大于缓冲区，长度不合要求
		//数据无效
		KdPrint(("get block error: invalid data length in HTTP response\n"));
		ExFreePool(request);
		ExFreePool(buffer);
		close(*Socket);
		*Socket = -1;
		IoStatus->Status = STATUS_UNSUCCESSFUL;
		return IoStatus->Status;
	}

	if (dataLen > 0)
	{
		RtlCopyMemory(
			SystemBuffer,
			pDataPart,
			dataLen
		);
	}

	while (dataLen < Length)
	{
		//循环接收数据
		nRecv = recv(*Socket, buffer, ((Length - dataLen) > BUFFER_SIZE) ? BUFFER_SIZE : (Length - dataLen), 0);
		if (nRecv <= 0)
		{
			if (nRecv == 0)
			{
				//服务器中途断开连接
				KdPrint(("get block: server disconnected in receive loop\n"));
			}
			else
			{
				//接收的数据出错
				KdPrint(("get block: recv() error in receive loop: %#x\n", nRecv));
			}
			close(*Socket);
			*Socket = -1;
			break;
		}
		if (dataLen + nRecv > Length || nRecv > BUFFER_SIZE)
		{
			//接收到不合要求的数据长度
			KdPrint(("get block: invalid data length in receive loop: %u,%u,%u\n", dataLen, nRecv, Length));
			close(*Socket);
			*Socket = -1;
			break;
		}
		RtlCopyMemory(
			(PVOID)((PUCHAR)SystemBuffer + dataLen),
			buffer,
			nRecv
		);
		dataLen += nRecv;
	}

	if (dataLen != Length)
	{
		//收到的数据长度不符合预期
		DbgPrint("get block: received=%u expected=%u\n", dataLen, Length);
	}

	ExFreePool(request);
	ExFreePool(buffer);
	IoStatus->Status = STATUS_SUCCESS;
	IoStatus->Information = dataLen;
	return IoStatus->Status;
}

#pragma code_seg() 