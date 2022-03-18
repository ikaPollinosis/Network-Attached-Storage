//#include <vdisk.h>
#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <ntverp.h>
#include <wdmsec.h>

#define DEVICE_NAME			L"\\Device\\VDisk"		//�豸��
#define SYM_NAME			L"\\??\\VDisk"			//��������

#define TOKEN_SOURCE_LENGTH 8



//�����Զ��幦�ܺ�
#define IOCTL_FILE_DISK_OPEN_FILE   CTL_CODE(FILE_DEVICE_DISK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_FILE_DISK_CLOSE_FILE  CTL_CODE(FILE_DEVICE_DISK, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_FILE_DISK_QUERY_FILE  CTL_CODE(FILE_DEVICE_DISK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)


//
//����ָ��ṹ�壬ʹ��TDIʵ���ں˼�����ͨ��
//
struct CDISK {
	ULONG CDType;	//��ʶָ���������
	ULONG Start;	//�����ʼ������
	ULONG Counts;	//���������
	ULONG Time;		//ָ���ʱ��	
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


//��ȫ��������
typedef struct _SECURITY_CLIENT_CONTEXT {
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	PACCESS_TOKEN               ClientToken;
	BOOLEAN                     DirectlyAccessClientToken;
	BOOLEAN                     DirectAccessEffectiveOnly;
	BOOLEAN                     ServerIsRemote;
	TOKEN_CONTROL               ClientTokenControl;
} SECURITY_CLIENT_CONTEXT, * PSECURITY_CLIENT_CONTEXT;

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
}DEVICE_EXTENSION, * PDEVICE_EXTENSION;


//
//ɾ���豸
//
VOID VDiskDeleteDevice(PDEVICE_OBJECT pdevice) {
	PDEVICE_EXTENSION   device_extension;
	PDEVICE_OBJECT      next_device_object;
	// �õ��豸��չ
	device_extension = (PDEVICE_EXTENSION)pdevice->DeviceExtension;
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
	IoDeleteDevice(pdevice);
}



//
//����ж������
//
VOID VDiskUnload(PDRIVER_OBJECT pdriver) {
	DbgPrint("Driver Unloaded\n");

	//���豸���������ɾ��
	if (pdriver->DeviceObject) {
		VDiskDeleteDevice(pdriver->DeviceObject);
		UNICODE_STRING symname = { 0 };
		RtlInitUnicodeString(&symname, L"\\??\\VDisk");
		IoDeleteSymbolicLink(&symname);
	}
}




//
//�������ر��豸����
//
NTSTATUS VDiskCreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	//PAGED_CODE();		����ʹ�õĺ�
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = FILE_OPENED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//
//����豸����
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
//��д����
//
NTSTATUS VDiskReadWrite(PDEVICE_OBJECT DeviceObject, PIRP irp) {
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

	ExInterlockedInsertTailList(&device_extension->list_head, &irp->Tail.Overlay.ListEntry, &device_extension->list_lock);	//д������

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

	//�ж��Ƿ��������ý�飬û���򷵻أ����ų��Զ���ļ���ý�鹦�ܺ�
	if (!device_extension->media_in_device && io_stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_FILE_DISK_OPEN_FILE) {
		irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_NO_MEDIA_IN_DEVICE;
	}

	//���ݲ�ͬ���ܺŽ����豸����
	switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
	{
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
//��д�߳�
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
		//�ȴ������¼�����

		KeWaitForSingleObject(&device_extension->request_event, Executive, KernelMode, FALSE, NULL);

		if (device_extension->terminate_thread)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		//�������Ƴ�����ڵ㣬�������д����
		while (request = ExInterlockedRemoveHeadList(&device_extension->list_head, &device_extension->list_lock))
		{
			irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

			io_stack = IoGetCurrentIrpStackLocation(irp);

			switch (io_stack->MajorFunction)
			{
				//ʹ��ZwReadFile���ļ�
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

			//����������
			IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
		}
	}
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

	NTSTATUS status = STATUS_SUCCESS;

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