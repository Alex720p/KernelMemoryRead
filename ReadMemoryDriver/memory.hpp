#pragma once

#include "documented.hpp"
#include "undocumented.hpp"


#define DRIVER_TAG 'redr'
typedef NTSTATUS(*ZwQuerySystemInformationPrototype) (_In_ undocumented::SYSTEM_INFORMATION_CLASS, _Inout_ PVOID, _In_ ULONG, _Out_opt_ PULONG);


struct Memory {
private:
	PEPROCESS process = nullptr;
public:

	void deference_process() {
		if (this->process)
			ObDereferenceObject(this->process);
	}

	/*
	non case sentitive search
	non ideal since it increases the object reference count. Other way could have been to walk the EPROCESS list but not a stable solution (no ref count in this case)
	
	*/
	NTSTATUS get_process_context(_In_ WCHAR* proc_name, _In_ ULONG proc_name_size);
	/*
	the buffer(for now) comes from the SystemBuffer attributed by the io manager
	the buffer should also be in kernel memory (not in context of ioctl user thread)
	*/
	NTSTATUS read_memory(_In_ DWORD64 addr, _In_ SIZE_T size, _Out_ PVOID buffer, _In_ SIZE_T buffer_size, _Out_ SIZE_T* bytes_read);

};