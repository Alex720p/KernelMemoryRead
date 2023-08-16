#include "memory.hpp"
#include "common.hpp"

void driver_unload(_In_ PDRIVER_OBJECT driver);
NTSTATUS io_create_close(_In_ PDEVICE_OBJECT device, _In_ PIRP irp);
NTSTATUS io_device_control(_In_ PDEVICE_OBJECT device, _In_ PIRP irp);

struct globals_t {
	PEPROCESS g_process = nullptr;
};

globals_t globals;

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	UNICODE_STRING symbolic_name = RTL_CONSTANT_STRING(L"\\??\\reader");
	UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\reader");
	NTSTATUS status = STATUS_SUCCESS;
	
	PDEVICE_OBJECT device;
	status = IoCreateDevice(driver, NULL, &device_name, FILE_DEVICE_UNKNOWN, NULL, FALSE, &device);
	if (!NT_SUCCESS(status))
			return status;

	status = IoCreateSymbolicLink(&symbolic_name, &device_name);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(device);
		return status;
	}

	driver->MajorFunction[IRP_MJ_CREATE] = driver->MajorFunction[IRP_MJ_CLOSE] = io_create_close;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = io_device_control;
	driver->DriverUnload = driver_unload;

	return STATUS_SUCCESS;
}



void driver_unload(_In_ PDRIVER_OBJECT driver) {
	UNICODE_STRING symbolic_name = RTL_CONSTANT_STRING(L"\\??\\reader");
	IoDeleteSymbolicLink(&symbolic_name);
	IoDeleteDevice(driver->DeviceObject);
	//todo: unreference EPROCESS on each change
}

NTSTATUS io_create_close(_In_ PDEVICE_OBJECT device, _In_ PIRP irp) {
	UNREFERENCED_PARAMETER(device);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS io_device_control(_In_ PDEVICE_OBJECT device, _In_ PIRP irp) {

	UNREFERENCED_PARAMETER(device);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;
	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_READER_INITIALIZE:
		{
			irp->IoStatus.Information = 0;
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(InitializeRequest)) {
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			InitializeRequest* buffer = reinterpret_cast<InitializeRequest*>(irp->AssociatedIrp.SystemBuffer);
			PEPROCESS ptr_to_peprocess = nullptr;
			status = Memory::find_process(buffer->proc_name, buffer->proc_name_size, &ptr_to_peprocess);
			if (!ptr_to_peprocess)
				break;

			globals.g_process = ptr_to_peprocess;
			break;
		}
		case IOCTL_READER_READ_BUFFERED:
		{
			irp->IoStatus.Information = 0;
			if (globals.g_process == nullptr) {
				status = STATUS_REQUEST_ABORTED;
				break;
			}

			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ReadRequest)) {
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			ReadRequest* buffer = reinterpret_cast<ReadRequest*>(irp->AssociatedIrp.SystemBuffer);
			if (stack->Parameters.DeviceIoControl.OutputBufferLength < buffer->size) {
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			
			PRKAPC_STATE apc_state = reinterpret_cast<PRKAPC_STATE>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC_STATE), DRIVER_TAG));
			if (apc_state == NULL) {
				status = STATUS_REQUEST_ABORTED;
				break;
			}
			
			SIZE_T copy_size = buffer->size;

			KeStackAttachProcess(globals.g_process, apc_state);
			__try {
				RtlMoveMemory(buffer, reinterpret_cast<void*>(buffer->address), copy_size);  //in context of targeted program 
			}
			__except(EXCEPTION_EXECUTE_HANDLER) {
				KdPrint(("Reader: Error, tried to read invalid memory \n"));
				//TODO: change to invalid status
			}

			KeUnstackDetachProcess(apc_state);
			ExFreePool(apc_state);

			irp->IoStatus.Information = copy_size;
			break;
		}
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
		}

	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}