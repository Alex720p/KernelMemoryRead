#pragma once
#include <ntddk.h>

//commons for driver and client

#define READER_DEVICE 0x8000

#define IOCTL_READER_READ_BUFFERED CTL_CODE(READER_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
//todo: implement METHOD_OUT_DIRECT for larger reads


//common structs
struct ReadRequest {
	DWORD64 address;
	ULONG size;
};