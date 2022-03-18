//#include <vdisk.h>
#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <ntverp.h>
#include <wdmsec.h>

#define DEVICE_NAME			L"\\Device\\VDisk"		//设备名
#define SYM_NAME			L"\\??\\VDisk"			//符号连接

#define TOKEN_SOURCE_LENGTH 8



//设置自定义功能号
#define IOCTL_FILE_DISK_OPEN_FILE   CTL_CODE(FILE_DEVICE_DISK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_FILE_DISK_CLOSE_FILE  CTL_CODE(FILE_DEVICE_DISK, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_FILE_DISK_QUERY_FILE  CTL_CODE(FILE_DEVICE_DISK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)


//
//网络指令结构体，使用TDI实现内核级网络通信
//
struct CDISK {
	ULONG CDType;	//标识指令具体类型
	ULONG Start;	//块的起始扇区号
	ULONG Counts;	//块的扇区数
	ULONG Time;		//指令发出时间	
};


typedef enum _TOKEN_TYPE {
	TokenPrimary = 1,
	TokenImpersonation
} TOKEN_TYPE;

typedef struct _TOKEN_SOURCE {
	CCHAR   SourceName[TOKEN_SOURCE_LENGTH];
	LUID    SourceIdentifier;
} TOKEN_SOURCE, * PTOKEN_SOURCE;



typedef struct _TOKEN_CONTROL {
	LUID            TokenId;
	LUID            AuthenticationId;
	LUID            ModifiedId;
	TOKEN_SOURCE    TokenSource;
} TOKEN_CONTROL, * PTOKEN_CONTROL;


//安全性上下文
typedef struct _SECURITY_CLIENT_CONTEXT {
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	PACCESS_TOKEN               ClientToken;
	BOOLEAN                     DirectlyAccessClientToken;
	BOOLEAN                     DirectAccessEffectiveOnly;
	BOOLEAN                     ServerIsRemote;
	TOKEN_CONTROL               ClientTokenControl;
} SECURITY_CLIENT_CONTEXT, * PSECURITY_CLIENT_CONTEXT;

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
}DEVICE_EXTENSION, * PDEVICE_EXTENSION;


//
//删除设备
//
VOID VDiskDeleteDevice(PDEVICE_OBJECT pdevice) {
	PDEVICE_EXTENSION   device_extension;
	PDEVICE_OBJECT      next_device_object;
	// 得到设备扩展
	device_extension = (PDEVICE_EXTENSION)pdevice->DeviceExtension;
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
	IoDeleteDevice(pdevice);
}



//
//驱动卸载例程
//
VOID VDiskUnload(PDRIVER_OBJECT pdriver) {
	DbgPrint("Driver Unloaded\n");

	//若设备存在则进行删除
	if (pdriver->DeviceObject) {
		VDiskDeleteDevice(pdriver->DeviceObject);
		UNICODE_STRING symname = { 0 };
		RtlInitUnicodeString(&symname, L"\\??\\VDisk");
		IoDeleteSymbolicLink(&symname);
	}
}




//
//创建、关闭设备例程
//
NTSTATUS VDiskCreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	//PAGED_CODE();		调试使用的宏
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = FILE_OPENED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//
//清除设备例程
//
NTSTATUS VDiskClean(PDEVICE_OBJECT DeviceObject, PIRP irp) {
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
NTSTATUS VDiskReadWrite(PDEVICE_OBJECT DeviceObject, PIRP irp) {
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

	ExInterlockedInsertTailList(&device_extension->list_head, &irp->Tail.Overlay.ListEntry, &device_extension->list_lock);	//写入链表

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

	//判断是否加载物理媒介，没有则返回，但排除自定义的加载媒介功能号
	if (!device_extension->media_in_device && io_stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_FILE_DISK_OPEN_FILE) {
		irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_MEDIA_IN_DEVICE;
	}

	//根据不同功能号进行设备控制
	switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
	{
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
//读写线程
//
VOID VDiskThread(PVOID Context) {
	PDEVICE_OBJECT      device_object;
	PDEVICE_EXTENSION   device_extension;
	PLIST_ENTRY         request;
	PIRP                irp;
	PIO_STACK_LOCATION  io_stack;
	PUCHAR              system_buffer;
	PUCHAR              buffer;

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
		while (request = ExInterlockedRemoveHeadList(&device_extension->list_head, &device_extension->list_lock))
		{
			irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

			io_stack = IoGetCurrentIrpStackLocation(irp);

			switch (io_stack->MajorFunction)
			{
				//使用ZwReadFile读文件
			case IRP_MJ_READ:
				ZwReadFile(device_extension->file_handle, NULL, NULL, NULL, &irp->IoStatus,
					MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority),
					io_stack->Parameters.Read.Length, &io_stack->Parameters.Read.ByteOffset, NULL);
				break;


			case IRP_MJ_WRITE:
				if ((io_stack->Parameters.Write.ByteOffset.QuadPart + io_stack->Parameters.Write.Length) >
					device_extension->file_information.AllocationSize.QuadPart)
				{
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
					irp->IoStatus.Information = 0;
					break;
				}
				ZwWriteFile(device_extension->file_handle, NULL, NULL, NULL,
					&irp->IoStatus, MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority),
					io_stack->Parameters.Write.Length, &io_stack->Parameters.Write.ByteOffset, NULL);
				break;


			default:
				irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
			}

			//最后完成请求
			IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
		}
	}
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

	NTSTATUS status = STATUS_SUCCESS;

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