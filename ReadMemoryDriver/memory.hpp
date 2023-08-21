#pragma once

#include <intrin.h>

#include "documented.hpp"
#include "undocumented.hpp"


#pragma warning (disable: 4554) //false positive
#define DRIVER_TAG 'redr'
#define MAKE_BINARY_MASK(length) ((1LL << length) - 1)

//functions ID for cpuid calls
#define CPUID_ID_HIGHEST_EXTENDED_FUNCTION_IMPLEMENTED 0x80000000
#define CPUID_ID_MAXPHYSADDR 0x80000008
#define MAX_PHYS_ADDR_LENGTH 8

//'physical' addresses lengths
#define PHYSICAL_INFO_START 12
#define IS_PRESENT(field) (field & 1L)
#define IS_1GB_PAGE(field) ((field >> 7) & 1)
#define IS_2MB_PAGE(field) ((field >> 7) & 1) //same for 1GB and 2MB, i'm declaring both for code readability

#define PHYSICAL_PAGE_TABLE_ADDRESS_START 12
#define PHYSICAL_PAGE_TABLE_ADDRESS_LENGTH(max_phys_addr) (max_phys_addr - PHYSICAL_4KB_ADDRESS_START)

#define PHYSICAL_1GB_ADDRESS_START 30
#define PHYSICAL_1GB_ADDRESS_LENGTH(max_phys_addr) (max_phys_addr - PHYSICAL_1GB_ADDRESS_START)

#define PHYSICAL_2MB_ADDRESS_START 22
#define PHYSICAL_2MB_ADDRESS_LENGTH(max_phys_addr) (max_phys_addr - PHYSICAL_2MB_ADDRESS_START)

#define PHYSICAL_4KB_ADDRESS_START 12
#define PHYSICAL_4KB_ADDRESS_LENGTH(max_phys_addr) (max_phys_addr - PHYSICAL_4KB_ADDRESS_START)


//Linear (virtual) addresses offsets and lengths
#define LINEAR_ADDRESS_PLM4_START 39	
#define LINEAR_ADDRESS_PML4_LENGTH 9

#define LINEAR_ADDRESS_DIRECTORY_START 30	
#define LINEAR_ADDRESS_DIRECTORY_LENGTH 9

#define LINEAR_ADDRESS_PAGE_DIRECTORY_START 21	
#define LINEAR_ADDRESS_PAGE_DIRECTORY_LENGTH 9

#define LINEAR_ADDRESS_PAGE_TABLE_START 12	
#define LINEAR_ADDRESS_PAGE_TABLE_LENGTH 9

#define LINEAR_ADDRESS_1GB_PAGE_OFFSET_LENGTH 30 //all 3 starts at 0 so no need to gave a START define
#define LINEAR_ADDRESS_2MB_PAGE_OFFSET_LENGTH 21
#define LINEAR_ADDRESS_4KB_PAGE_OFFSET_LENGTH 12 

#define LINEAR_ADDRESS_OFFSET_SIZE 8

//PEPROCESS offsets
#define DIRECTORY_TABLE_BASE_OFFSET 0x28 //win 22H2
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
	NTSTATUS read_memory_2(_In_ DWORD64 virtual_addr, _In_ SIZE_T size, _Out_ PVOID buffer, _Out_ SIZE_T* bytes_read);

};