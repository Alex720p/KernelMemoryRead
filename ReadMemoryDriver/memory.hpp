#pragma once

#include "documented.hpp"
#include "undocumented.hpp"


#define DRIVER_TAG 'redr'

class Memory {
private:
	typedef NTSTATUS(*ZwQuerySystemInformationPrototype) (_In_ undocumented::SYSTEM_INFORMATION_CLASS, _Inout_ PVOID, _In_ ULONG, _Out_opt_ PULONG);
public:
	/*
	non case sentitive search
	non ideal since it increases the object reference count. Other way could have been to walk the EPROCESS list but not a stable solution (no ref count in this case)
	*/
	static NTSTATUS find_process(_In_ WCHAR* proc_name, _In_ ULONG proc_name_size, _Out_ PEPROCESS proc); 
};