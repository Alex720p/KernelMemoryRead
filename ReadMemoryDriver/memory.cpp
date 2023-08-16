#include "memory.hpp"

NTSTATUS Memory::find_process(_In_ WCHAR* proc_name, _In_ ULONG proc_name_size, _Out_ PEPROCESS* proc) {

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
			status = PsLookupProcessByProcessId(curr_proc_info->UniqueProcessId, proc);
			if (NT_SUCCESS(status))
				found = true;

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