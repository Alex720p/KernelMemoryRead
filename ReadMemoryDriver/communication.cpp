#include "communication.hpp"

#pragma warning(push)
#pragma warning(disable:26495)
Communication::Communication(_In_ WCHAR* client_proc_name, _In_ ULONG proc_name_size) {
	NTSTATUS status = this->memory.store_process_context(client_proc_name, proc_name_size);
	if (NT_SUCCESS(status)) {
		DWORD64 first_recurring_response_buffer;
		status = this->memory.allocate_virtual_memory_in_um(DEFAULT_RECURRING_RESPONSE_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE, &first_recurring_response_buffer);
		if (NT_SUCCESS(status)) {
			this->recurring_response_buffers = reinterpret_cast<ResponseBuffer*>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ResponseBuffer), DRIVER_TAG));
			if (this->recurring_response_buffers) {
				this->recurring_response_buffers->buffer_addr = first_recurring_response_buffer;
				InitializeListHead(&this->recurring_response_buffers->list_entry);

				this->response_buffers = nullptr;
				this->class_valid_state = true; //class succesfully initialized
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
	ResponseBuffer* response_buffer = reinterpret_cast<ResponseBuffer*>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ResponseBuffer), DRIVER_TAG));
	if (!response_buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	response_buffer->buffer_addr = next_recurring_response_buffer;

	InsertTailList(head_entry, &response_buffer->list_entry);
	return STATUS_SUCCESS;
}

void Communication::fulfil_recurring_reads() {	
}