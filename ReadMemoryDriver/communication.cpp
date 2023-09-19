#include "communication.hpp"

#pragma warning(push)
#pragma warning(disable:26495)
Communication::Communication(_In_ WCHAR* client_proc_name, _In_ ULONG proc_name_size) {
	NTSTATUS status = this->memory.store_process_context(client_proc_name, proc_name_size);
	if (NT_SUCCESS(status)) {
		DWORD64 first_recurring_response_buffer;
		status = this->memory.allocate_virtual_memory_in_um(DEFAULT_RECURRING_RESPONSE_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE, &first_recurring_response_buffer);
		if (NT_SUCCESS(status)) {
			this->recurring_response_buffers = reinterpret_cast<PRESPONSE_BUFFER>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(RESPONSE_BUFFER), DRIVER_TAG));
			if (this->recurring_response_buffers) {
				this->recurring_response_buffers->buffer_addr = first_recurring_response_buffer;
				InitializeListHead(&this->recurring_response_buffers->list_entry);

				DWORD64 client_init_buffer;
				status = this->memory.find_pattern_um(0, MAXDWORD64, PATTERN_1, PATTERN_1_MASK, 0, &client_init_buffer);
				if (NT_SUCCESS(status)) {
					this->response_buffers = nullptr;
					this->first_client_request_buffer = *reinterpret_cast<DWORD64*>(client_init_buffer + sizeof(DWORD64)); //getting the base addr of the first request buffer from client (located just after the pattern)
					this->class_valid_state = true; //class succesfully initialized
				}
			}
		}
			
	}
}
#pragma warning(pop)

NTSTATUS Communication::allocate_new_recurring_response_buffer() {
	DWORD64 next_recurring_response_buffer;
	NTSTATUS status = this->memory.allocate_virtual_memory_in_um(DEFAULT_RECURRING_RESPONSE_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE, &next_recurring_response_buffer);
	if (!NT_SUCCESS(status))
		return status;

	LIST_ENTRY* head_entry = &this->recurring_response_buffers->list_entry;
	PRESPONSE_BUFFER response_buffer = reinterpret_cast<PRESPONSE_BUFFER>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(RESPONSE_BUFFER), DRIVER_TAG));
	if (!response_buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	response_buffer->buffer_addr = next_recurring_response_buffer;

	InsertTailList(head_entry, &response_buffer->list_entry);
	return STATUS_SUCCESS;
}

NTSTATUS Communication::fulfil_recurring_reads() {	
	PRESPONSE_BUFFER recurring_entry = this->recurring_response_buffers;
	DWORD64 client_requests_entry = this->first_client_request_buffer;
	DWORD64 client_requests_buffer = reinterpret_cast<DWORD64>(ExAllocatePool2(POOL_FLAG_NON_PAGED, REGISTER_RECURRING_READS_BUFFER_SIZE, DRIVER_TAG));
	if (!client_requests_buffer)
		return STATUS_INSUFFICIENT_RESOURCES;


	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T bytes_read = 0;
	do {
		status = this->memory.read_memory_2(client_requests_entry, VIRTUAL_PAGE_SIZE, &client_requests_buffer, &bytes_read);
		if (!NT_SUCCESS(status))
			break;
		
	
		client_requests_buffer = *reinterpret_cast<DWORD64*>(client_requests_buffer + sizeof(DWORD64));
	} while (client_requests_buffer);

	return status;
}