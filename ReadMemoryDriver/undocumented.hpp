#pragma once
#include <ntifs.h>

//contains some semi-documented/'undocumented' structures
namespace undocumented {
    //https://github.com/conix-security/zer0m0n/blob/master/src/driver/include/nt/structures/SYSTEM_INFORMATION_CLASS.h
    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation = 0,
        SystemProcessorInformation = 1,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemPathInformation = 4,
        SystemProcessInformation = 5,
        SystemCallCountInformation = 6,
        SystemDeviceInformation = 7,
        SystemProcessorPerformanceInformation = 8,
        SystemFlagsInformation = 9,
        SystemCallTimeInformation = 10,
        SystemModuleInformation = 11,
        SystemLocksInformation = 12,
        SystemStackTraceInformation = 13,
        SystemPagedPoolInformation = 14,
        SystemNonPagedPoolInformation = 15,
        SystemHandleInformation = 16,
        SystemObjectInformation = 17,
        SystemPageFileInformation = 18,
        SystemVdmInstemulInformation = 19,
        SystemVdmBopInformation = 20,
        SystemFileCacheInformation = 21,
        SystemPoolTagInformation = 22,
        SystemInterruptInformation = 23,
        SystemDpcBehaviorInformation = 24,
        SystemFullMemoryInformation = 25,
        SystemLoadGdiDriverInformation = 26,
        SystemUnloadGdiDriverInformation = 27,
        SystemTimeAdjustmentInformation = 28,
        SystemSummaryMemoryInformation = 29,
        SystemMirrorMemoryInformation = 30,
        SystemPerformanceTraceInformation = 31,
        SystemObsolete0 = 32,
        SystemExceptionInformation = 33,
        SystemCrashDumpStateInformation = 34,
        SystemKernelDebuggerInformation = 35,
        SystemContextSwitchInformation = 36,
        SystemRegistryQuotaInformation = 37,
        SystemExtendServiceTableInformation = 38,
        SystemPrioritySeperation = 39,
        SystemVerifierAddDriverInformation = 40,
        SystemVerifierRemoveDriverInformation = 41,
        SystemProcessorIdleInformation = 42,
        SystemLegacyDriverInformation = 43,
        SystemCurrentTimeZoneInformation = 44,
        SystemLookasideInformation = 45,
        SystemTimeSlipNotification = 46,
        SystemSessionCreate = 47,
        SystemSessionDetach = 48,
        SystemSessionInformation = 49,
        SystemRangeStartInformation = 50,
        SystemVerifierInformation = 51,
        SystemVerifierThunkExtend = 52,
        SystemSessionProcessInformation = 53,
        SystemLoadGdiDriverInSystemSpace = 54,
        SystemNumaProcessorMap = 55,
        SystemPrefetcherInformation = 56,
        SystemExtendedProcessInformation = 57,
        SystemRecommendedSharedDataAlignment = 58,
        SystemComPlusPackage = 59,
        SystemNumaAvailableMemory = 60,
        SystemProcessorPowerInformation = 61,
        SystemEmulationBasicInformation = 62,
        SystemEmulationProcessorInformation = 63,
        SystemExtendedHandleInformation = 64,
        SystemLostDelayedWriteInformation = 65,
        SystemBigPoolInformation = 66,
        SystemSessionPoolTagInformation = 67,
        SystemSessionMappedViewInformation = 68,
        SystemHotpatchInformation = 69,
        SystemObjectSecurityMode = 70,
        SystemWatchdogTimerHandler = 71,
        SystemWatchdogTimerInformation = 72,
        SystemLogicalProcessorInformation = 73,
        SystemWow64SharedInformation = 74,
        SystemRegisterFirmwareTableInformationHandler = 75,
        SystemFirmwareTableInformation = 76,
        SystemModuleInformationEx = 77,
        SystemVerifierTriageInformation = 78,
        SystemSuperfetchInformation = 79,
        SystemMemoryListInformation = 80,
        SystemFileCacheInformationEx = 81,
        MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

    } SYSTEM_INFORMATION_CLASS;

    //semi-documented on msdn
    //rest from https://www.unknowncheats.me/forum/anti-cheat-bypass/424340-enumerate-processes-process.html (orig. from process hacker github)
    //only valid for x64 architecture
    typedef struct _SYSTEM_PROCESS_INFORMATION
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
        ULONG HardFaultCount; // since WIN7
        ULONG NumberOfThreadsHighWatermark; // since WIN7
        ULONGLONG CycleTime; // since WIN7
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;
        /*HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;*/
    } SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


    typedef struct _RTL_BALANCED_NODE {
        PVOID left_child;
        PVOID right_child;
        unsigned __int64 parent; //just make off the 4 bits of least weight to get the parent value
    } RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

    typedef struct _MMVAD_SHORT {
        RTL_BALANCED_NODE node;
        __int16 start_vpn;
        __int16 end_vpn;
        char starting_vpn_high;
        char ending_vpn_high;
        char commit_charge_high;
        char spare_NT64vad;
        __int16 reference_count;
        __int8 push_lock; //_EX_PUSH_LOCK type
        __int32 u; //MMVAD_FLAGS
        __int32 u1; //MMVAD_FLAGS1
        __int32 u5;
    } MMVAD_SHORT, *PMMVAD_SHORT;

    //bitfield
    typedef struct _MMVAD_FLAGS {
        __int32 lock : 1;
        __int32 lock_contended : 1;
        __int32 delete_in_progress : 1;
        __int32 no_change : 1;
        __int32 vad_type : 3;
        __int32 protection : 5;
        __int32 preffered_node : 7;
        __int32 page_size : 2;
        __int32 private_memory : 1;
    } MMVAD_FLAGS;

    //bitfield
    typedef struct _MMVAD_FLAGS1 {
        __int32 commit_charge : 31;
        __int32 mem_commit : 1;
    } MMVAD_FLAGS1;
}