#pragma once

#include <intrin.h>

#include "documented.hpp"
#include "undocumented.hpp"



#define DRIVER_TAG 'redr'
#define MAKE_BINARY_MASK(length) ((1L << (length + 1)) - 1)

#define CPUID_ID_HIGHEST_EXTENDED_FUNCTION_IMPLEMENTED 0x80000000
#define CPUID_ID_MAXPHYSADDR 0x80000008

#define DIRECTORY_TABLE_BASE_OFFSET 0x28 //win 22H2
#define GET_PLM4
typedef NTSTATUS(*ZwQuerySystemInformationPrototype) (_In_ undocumented::SYSTEM_INFORMATION_CLASS, _Inout_ PVOID, _In_ ULONG, _Out_opt_ PULONG);

//TODO: add a function to check for windows version

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
	note: name is a bit misleading, we're not attaching to the process, rather storing the EPROCESS structure we'll use for the reads
	*/
	NTSTATUS process_context_attach(_In_ WCHAR* proc_name, _In_ ULONG proc_name_size);

	/*wrapper for physical read with MmCopyMemory
	  note: buffer has to be in non paged memory
	*/
	NTSTATUS read_physical_memory(_In_ DWORD64 physical_addr, _In_ SIZE_T read_size, _Out_ PVOID buffer, _Out_ SIZE_T* bytes_read);

	/*
	the buffer(for now) comes from the SystemBuffer attributed by the io manager
	the buffer should also be in kernel memory (not in context of ioctl user thread)
	*/
	NTSTATUS read_memory(_In_ DWORD64 addr, _In_ SIZE_T size, _Out_ PVOID buffer, _In_ SIZE_T buffer_size, _Out_ SIZE_T* bytes_read);

	/*https://www.unknowncheats.me/forum/general-programming-and-reversing/523359-introduction-physical-memory.html translation process explained :)
	  todo: find a way to read mem that has been paged out ? check way to get it from disk or just use MmProbeAndLockPages/Unlock
	  buffer has to be in non paged memory
	*/
	//
	// NTSTATUS read_memory_2(_In_ DWORD64 virutal_addr, _In_ SIZE_T size, _Out_ PVOID buffer, _Out_ SIZE_T* bytes_read);

};