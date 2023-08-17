#include "memory.hpp"

NTSTATUS Memory::get_process_context(_In_ WCHAR* proc_name, _In_ ULONG proc_name_size) {

	static UNICODE_STRING func_name = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	static PVOID func_addr = MmGetSystemRoutineAddress(&func_name); 

	if (!func_addr)
		return STATUS_FAIL_CHECK;

	ZwQuerySystemInformationPrototype ZwQuerySystemInformation = reinterpret_cast<ZwQuerySystemInformationPrototype>(func_addr);

	ULONG return_length = 0;
	documented::SYSTEM_PROCESS_INFORMATION dummy = { 0 };
	documented::PSYSTEM_PROCESS_INFORMATION curr_proc_info;
	NTSTATUS status = ZwQuerySystemInformation(undocumented::SystemProcessInformation, &dummy, sizeof(dummy), &return_length);
	do {
		ULONG buffer_size = return_length + 0x1000; //note: 0x1000 is arbitrary, it gives a margin if the buffer size needed increases between calls
		curr_proc_info = reinterpret_cast<documented::SYSTEM_PROCESS_INFORMATION*>(ExAllocatePool2(POOL_FLAG_PAGED, static_cast<SIZE_T>(buffer_size), DRIVER_TAG));
		if (curr_proc_info == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = ZwQuerySystemInformation(undocumented::SystemProcessInformation, curr_proc_info, buffer_size, &return_length);
		if (!NT_SUCCESS(status))
			ExFreePool(curr_proc_info);
		
	} while (!NT_SUCCESS(status));


	bool found = false;
	PVOID buffer_start = reinterpret_cast<PVOID>(curr_proc_info);
	documented::PSYSTEM_PROCESS_INFORMATION next_proc_info = reinterpret_cast<documented::PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<DWORD64>(curr_proc_info) + curr_proc_info->NextEntryOffset); //first entry seems to always be empty
	do {
		curr_proc_info = next_proc_info;
		UNICODE_STRING image_name = curr_proc_info->ImageName;
		if (!_wcsnicmp(proc_name, image_name.Buffer, proc_name_size)) {
			PEPROCESS old = this->process;
			status = PsLookupProcessByProcessId(curr_proc_info->UniqueProcessId, &this->process);
			if (NT_SUCCESS(status)) {
				found = true;
				if (old != this->process && old)
					ObDereferenceObject(old);
			}

			break;
		}
		next_proc_info = reinterpret_cast<documented::PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<DWORD64>(curr_proc_info) + curr_proc_info->NextEntryOffset);
	} while (curr_proc_info->NextEntryOffset != NULL);

	ExFreePool(buffer_start);

	if (found)
		return STATUS_SUCCESS;
	else
		return STATUS_NOT_FOUND;
}

NTSTATUS Memory::read_memory(_In_ DWORD64 addr, _In_ SIZE_T size, _Out_ PVOID buffer, _In_ SIZE_T buffer_size, _Out_ SIZE_T* bytes_read) {
	if (!this->process)
		return STATUS_REQUEST_ABORTED;
	
	if (!buffer)
		return STATUS_INVALID_PARAMETER_3;

	if (buffer_size < size)
		return STATUS_INVALID_BUFFER_SIZE;

	if (!bytes_read)
		return STATUS_INVALID_PARAMETER_5;

	PRKAPC_STATE apc_state = reinterpret_cast<PRKAPC_STATE>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC_STATE), DRIVER_TAG));
	if (!apc_state)
		return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS status;
	KeStackAttachProcess(this->process, apc_state);
	__try {
		RtlMoveMemory(buffer, reinterpret_cast<void*>(addr), size);  //in context of targeted program 
		*bytes_read = size;
		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KdPrint(("Reader: Error, tried to read invalid memory \n"));
		status = STATUS_ACCESS_VIOLATION;
		*bytes_read = 0;
	}

	KeUnstackDetachProcess(apc_state);
	ExFreePool(apc_state);
	return status;
}
