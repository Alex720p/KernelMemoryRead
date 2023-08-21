#include "memory.hpp"

#pragma warning(push)
#pragma warning(disable: 6001)
NTSTATUS Memory::read_physical_memory(_In_ DWORD64 physical_addr, _In_ SIZE_T read_size, _Out_ PVOID buffer, _Out_ PSIZE_T bytes_read) {
	if (!buffer)
		return STATUS_INVALID_PARAMETER;

	MM_COPY_ADDRESS copy_addr = { reinterpret_cast<PVOID>(physical_addr) };
	return MmCopyMemory(buffer, copy_addr, read_size, MM_COPY_MEMORY_PHYSICAL, bytes_read);
}
#pragma warning(pop)

NTSTATUS Memory::process_context_attach(_In_ WCHAR* proc_name, _In_ ULONG proc_name_size) {

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

NTSTATUS Memory::read_memory(_In_ DWORD64 addr, _In_ SIZE_T size, _Out_ PVOID buffer, _In_ SIZE_T buffer_size, _Out_ PSIZE_T bytes_read) {
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

NTSTATUS Memory::read_memory_2(_In_ DWORD64 virtual_addr, _In_ SIZE_T read_size, _Out_ PVOID buffer, _Out_ PSIZE_T bytes_read) {
	if (!this->process)
		return STATUS_REQUEST_ABORTED;

	if (!read_size || !buffer || !bytes_read)
		return STATUS_INVALID_PARAMETER;


	DWORD64 cr3 = *reinterpret_cast<DWORD64*>(reinterpret_cast<DWORD64>(this->process) + DIRECTORY_TABLE_BASE_OFFSET);

	SIZE_T max_phys_addr = 0;
	int cpu_info[4];
	__cpuid(cpu_info, CPUID_ID_HIGHEST_EXTENDED_FUNCTION_IMPLEMENTED);	
	if (cpu_info[0] < CPUID_ID_MAXPHYSADDR)
		cpu_info[0] = 36; //saw in multiple places this was the value to assume in the case we can't query MAXPHYADDR (not entirely sure of validity though)
	else
		__cpuid(cpu_info, CPUID_ID_MAXPHYSADDR);

	max_phys_addr = cpu_info[0] & MAKE_BINARY_MASK(MAX_PHYS_ADDR_LENGTH);


	//address translation
	DWORD64 pml4_table_addr = cr3 & (MAKE_BINARY_MASK(max_phys_addr - PHYSICAL_INFO_START) << PHYSICAL_INFO_START);
	DWORD64 pml4_offset = ((virtual_addr >> LINEAR_ADDRESS_PLM4_START) & MAKE_BINARY_MASK(LINEAR_ADDRESS_PML4_LENGTH)) * LINEAR_ADDRESS_OFFSET_SIZE;

	DWORD64 directory_field;
	SIZE_T read;
	NTSTATUS status = this->read_physical_memory(pml4_table_addr + pml4_offset, sizeof(DWORD64), &directory_field, &read);
	if (!NT_SUCCESS(status))
		return status;

	if (!IS_PRESENT(directory_field))
		return STATUS_REQUEST_ABORTED;

	DWORD64 directory_addr = directory_field & (MAKE_BINARY_MASK(max_phys_addr - PHYSICAL_INFO_START) << PHYSICAL_INFO_START);
	DWORD64 directory_offset = ((virtual_addr >> LINEAR_ADDRESS_DIRECTORY_START) & MAKE_BINARY_MASK(LINEAR_ADDRESS_DIRECTORY_LENGTH)) * LINEAR_ADDRESS_OFFSET_SIZE;
	DWORD64 page_directory_field;
	status = this->read_physical_memory(directory_addr + directory_offset, sizeof(DWORD64), &page_directory_field, &read);
	if (!NT_SUCCESS(status))
		return status;

	if (!IS_PRESENT(page_directory_field))
		return STATUS_REQUEST_ABORTED;

	if (IS_1GB_PAGE(page_directory_field)) {
		DWORD64 page = page_directory_field & (MAKE_BINARY_MASK(PHYSICAL_1GB_ADDRESS_LENGTH(max_phys_addr)) << PHYSICAL_1GB_ADDRESS_START);
		DWORD64 page_offset = virtual_addr & MAKE_BINARY_MASK(LINEAR_ADDRESS_1GB_PAGE_OFFSET_LENGTH);
		return this->read_physical_memory(page + page_offset, read_size, buffer, bytes_read);
	}

	DWORD64 page_directory_addr = page_directory_field & (MAKE_BINARY_MASK(max_phys_addr - PHYSICAL_INFO_START) << PHYSICAL_INFO_START);
	DWORD64 page_directory_offset = ((virtual_addr >> LINEAR_ADDRESS_PAGE_DIRECTORY_START) & MAKE_BINARY_MASK(LINEAR_ADDRESS_PAGE_DIRECTORY_LENGTH)) * LINEAR_ADDRESS_OFFSET_SIZE;
	DWORD64 page_table_field;
	status = this->read_physical_memory(page_directory_addr + page_directory_offset, sizeof(DWORD64), &page_table_field, &read);
	if (!NT_SUCCESS(status))
		return status;

	if (!IS_PRESENT(page_table_field))
		return STATUS_REQUEST_ABORTED;

	if (IS_2MB_PAGE(page_table_field)) {
		DWORD64 page = page_table_field & (MAKE_BINARY_MASK(PHYSICAL_2MB_ADDRESS_LENGTH(max_phys_addr)) << PHYSICAL_2MB_ADDRESS_START);
		DWORD64 page_offset = virtual_addr & MAKE_BINARY_MASK(LINEAR_ADDRESS_2MB_PAGE_OFFSET_LENGTH);
		return this->read_physical_memory(page + page_offset, read_size, buffer, bytes_read);
	}

	DWORD64 page_table_addr = page_table_field & (MAKE_BINARY_MASK(PHYSICAL_PAGE_TABLE_ADDRESS_LENGTH(max_phys_addr)) << PHYSICAL_PAGE_TABLE_ADDRESS_START);
	DWORD64 page_table_offset = ((virtual_addr >> LINEAR_ADDRESS_PAGE_TABLE_START) & MAKE_BINARY_MASK(LINEAR_ADDRESS_PAGE_TABLE_LENGTH)) * LINEAR_ADDRESS_OFFSET_SIZE;
	DWORD64 page;
	status = this->read_physical_memory(page_table_addr + page_table_offset, sizeof(DWORD64), &page, &read);
	if (!NT_SUCCESS(status))
		return status;

	if (!IS_PRESENT(page))
		return STATUS_REQUEST_ABORTED;

	page = page & (MAKE_BINARY_MASK(PHYSICAL_4KB_ADDRESS_LENGTH(max_phys_addr)) << PHYSICAL_4KB_ADDRESS_START);
	DWORD64 page_offset = (virtual_addr  & MAKE_BINARY_MASK(LINEAR_ADDRESS_4KB_PAGE_OFFSET_LENGTH));
	return this->read_physical_memory(page + page_offset, read_size, buffer, bytes_read);
} //todo: debug this :)))))


