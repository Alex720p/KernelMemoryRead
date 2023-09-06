#include "memory.hpp"

//note: class will be kept 'simple'
#define VIRTUAL_PAGE_SIZE 4096

#define DEFAULT_RECURRING_RESPONSE_BUFFER_SIZE 4*VIRTUAL_PAGE_SIZE

struct ResponseBuffer {
	LIST_ENTRY list_entry;
	DWORD64 buffer_addr;
};

class Communication {
private:
	bool class_valid_state = false; //this solution is not ideal, but having a static class maker makes the cleanup anoying

	Memory memory;

	ResponseBuffer* recurring_response_buffers; //will always point to the fist element of the list
	ResponseBuffer* response_buffers; //will always point to the fist element of the list
	NTSTATUS allocate_new_recurring_response_buffer();
public:
	Communication(_In_ WCHAR* client_proc_name, _In_ ULONG proc_name_size);

	void fulfil_recurring_reads();
	bool is_class_valid() { return this->class_valid_state; }
	~Communication() {}
};