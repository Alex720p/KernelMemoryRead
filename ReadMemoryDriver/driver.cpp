#include "memory.hpp"
#include "common.hpp"

void driver_unload(_In_ PDRIVER_OBJECT driver);
NTSTATUS io_create_close(_In_ PDEVICE_OBJECT device, _In_ PIRP irp);
NTSTATUS io_device_control(_In_ PDEVICE_OBJECT device, _In_ PIRP irp);

Memory g_memory;
//TODO: read the patchguard article

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
	g_memory.deference_process();
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
			status = g_memory.process_context_attach(buffer->proc_name, buffer->proc_name_size);

			break;
		}
		case IOCTL_READER_READ_BUFFERED:
		{
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ReadRequest)) {
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			ReadRequest* buffer = reinterpret_cast<ReadRequest*>(irp->AssociatedIrp.SystemBuffer);
			SIZE_T out_buffer_size = stack->Parameters.DeviceIoControl.OutputBufferLength;
			SIZE_T bytes_read;
			status = g_memory.read_memory(buffer->address, buffer->size, buffer, out_buffer_size, &bytes_read);
			irp->IoStatus.Information = bytes_read;

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