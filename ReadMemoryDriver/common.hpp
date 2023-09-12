#pragma once
#include <ntddk.h>

//for 'shared' memory communication
#define PATTERN_1 0xAABBCCDDEEFFAABB
#define PATTERN_2 0xBBAAFFEEDDCCBBAA //will be used to find ReadMemoryClient


//for io
//commons for driver and client

#define READER_DEVICE 0x8000


#define IOCTL_READER_INITIALIZE CTL_CODE(READER_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READER_READ_BUFFERED CTL_CODE(READER_DEVICE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
//todo: implement METHOD_OUT_DIRECT for larger reads


//common structs
struct InitializeRequest {
	WCHAR* proc_name;
	ULONG proc_name_size;
};


struct ReadRequest {
	DWORD64 address;
	ULONG size;
};

//for 'shared memory' communications
struct RecurringReadRequest {
	DWORD64 read_addr;
	SIZE_T read_size;
	unsigned long interval;
};




