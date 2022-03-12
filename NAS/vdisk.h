

/*
typedef struct _CONTROLLER_DATA {
    PDEVICE_OBJECT DeviceObject;
    PUCHAR ControllerAddress;             // base addr of controller registers
    PUCHAR ControlPortAddress;
    BOOLEAN ControllerAddressMapped;      // mapped addrs of controllers
    BOOLEAN ControllerPortMapped;
    CCHAR ResettingController;            // >0 while controller is being reset
    CCHAR ControlFlags;                   // OR into CONTROL_PORT
    BOOLEAN InterruptRequiresDpc;         // ISR need to queue DPC
    LONG BusyCountDown;                   // counter for busy disk
    PKINTERRUPT InterruptObject;          // only one needed per controller
} CONTROLLER_DATA;

typedef CONTROLLER_DATA* PCONTROLLER_DATA;


typedef CONTROLLER_DATA* PCONTROLLER_DATA;
typedef struct _VDSK_DEV_EXT {
    PARTITION_INFORMATION Pi;             // Partition info (MUST BE FIRST FIELD).
    PVOID Partition0;                     // Pointer to self (MUST BE SECOND FIELD).
    ULONG PartitionOrdinal;               // Order partition appears on disk.
                                          // (MUST BE THIRD FIELD)
    PDEVICE_OBJECT NextPartition;         // Pointer to next parititions object
                                          // MUST BE FOURTH FIELD
    PCONTROLLER_DATA ControllerData;     // ptr to disk's controller
    PDEVICE_OBJECT DeviceObject;          // ptr to this disk's object
    ULONG DiskNumber;                     // The index for this disk.  This is
                                          // corresponds to the value for the
                                          // harddiskcount in the
                                          // ioconfiguration record.
    ULONG FirstSectorOfRequest;           // start sector of whole request
                                          // used as the sort key for removing
                                          // requests from the device queue
    ULONG FirstSectorOfTransfer;          // start sector for current transfer
    ULONG RemainingRequestLength;         // # of sectors left in current op
    ULONG TotalTransferLength;            // length of current transfer
    ULONG RemainingTransferLength;        // length left in current transfer
    ULONG SequenceNumber;                 // Sequence number that is incremented
                                          // on every new irp for this device.
    HANDLE DirectoryHandle;               // handle to disk's device directory
    PCCHAR CurrentAddress;                // working address in user's buffer
    USHORT BytesPerSector;                // disk-specific values
    USHORT SectorsPerTrack;               // ...
    USHORT PretendSectorsPerTrack;        // ...
    USHORT NumberOfCylinders;             // ...
    USHORT PretendNumberOfCylinders;      // ...
    USHORT TracksPerCylinder;             // ...
    USHORT PretendTracksPerCylinder;      // ...
    USHORT WritePrecomp;                  // ...
    USHORT BytesPerInterrupt;             // ...
    CCHAR ByteShiftToSector;              // ...
    CCHAR ReadCommand;                    // ...
    CCHAR WriteCommand;                   // ...
    CCHAR VerifyCommand;                  // ...
    CCHAR OperationType;                  // current command (ie IRP_MJ_READ)
    UCHAR DeviceUnit;                     // which disk we are to the controller
    CCHAR IrpRetryCount;                  // count of retries by driver
    BOOLEAN PacketIsBeingRetried;         // if packet is being retried
} VDSK_DEV_EXT, * PVDSK_DEV_EXT;





//
// If the hardware state gets messed up, we'll retry the current packet.
// This says how many times we'll retry before giving up and returning
// an error.  Note that the hardware invisibly retries 8 times.
//
#define MAXIMUM_IRP_RETRY_COUNT 10
//
// Longest transfer supported by this driver
//
#define MAXIMUM_TRANSFER_LENGTH 65536



NTSTATUS
VDiskAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT pdo) {
	NTSTATUS status;
	PDEVICE_OBJECT fdo;
	status = IoCreateDevice(DriverObject,sizeof(VDSK_DEV_EXT), NULL, FILE_DEVICE_DISK, 0, FALSE, &fdo);
	if (NT_SUCCESS(status))return status;
    VDSK_DEV_EXT vd = (VDSK_DEV_EXT)fdo->DeviceExtension;
    PCONFIGURATION_INFORMATION ConfigInfo = IoGetConfigurationInformation();
    if (!NT_SUCCESS(status))ConfigInfo->DiskCount++;
    status = IoRegisterDeviceInterface(pdo, &myWDM_GUID, NULL, &vd->ifSymLinkName);
    vd->NextStackDevice = (fdo, pdo);
    return STATUS_SUCCESS;
}

NTSTATUS
VDiskCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    //
    // Complete the irp with no increase in priority
    //

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    //
    // return the success
    //

    return STATUS_SUCCESS;
}


*/

//
//驱动卸载函数
//
VOID VDiskUnload(PDRIVER_OBJECT pdriver) {
    DbgPrint("Driver Unloaded\n");
    if (pdriver->DeviceObject) {
        IoDeleteDevice(pdriver->DeviceObject);
        UNICODE_STRING symname = { 0 };
        RtlInitUnicodeString(&symname, "\\??\\VDisk");
        IoDeleteSymbolicLink(&symname);
    }
}


//
//打开设备回调函数
//
NTSTATUS VDiskCreate(PDEVICE_OBJECT DeviceObject, PIRP pirp) {
    NTSTATUS status = STATUS_SUCCESS;
    DbgPrint("Disk has been opened\n");
    pirp->IoStatus.Status = status;
    pirp->IoStatus.Information = 0;
    IoCompleteRequest(pirp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
//关闭设备回调函数
//
NTSTATUS VDiskClose(PDEVICE_OBJECT DeviceObject, PIRP pirp) {
    NTSTATUS status = STATUS_SUCCESS;
    DbgPrint("Disk has been closed\n");
    pirp->IoStatus.Status = status;
    pirp->IoStatus.Information = 0;
    IoCompleteRequest(pirp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
//清除设备回调函数
//
NTSTATUS VDiskClean(PDEVICE_OBJECT DeviceObject, PIRP pirp) {
    NTSTATUS status = STATUS_SUCCESS;
    DbgPrint("Disk has been cleaned\n");
    pirp->IoStatus.Status = status;
    pirp->IoStatus.Information = 0;
    IoCompleteRequest(pirp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

