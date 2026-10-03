#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#pragma region nt (un)defines

#ifndef NT_FAIL
#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifdef memmove
#undef memmove
#endif

#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif

#define STATUS_SUCCESS				0x00000000
#define STATUS_UNSUCCESSFUL			0xC0000001
#define STATUS_NOT_IMPLEMENTED		0xC0000002
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_APISET_NOT_HOSTED	0xC0000481

typedef LONG KPRIORITY;

#define KUSER_SHARED_DATA (DWORD)0x7FFE0000
#define P_KUSER_SHARED_DATA_COOKIE ReCa<DWORD *>(KUSER_SHARED_DATA + 0x0330)

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 ) 

#pragma endregion

#pragma region enums

typedef enum class _PROCESSINFOCLASS
{
	ProcessBasicInformation			= 0
} PROCESSINFOCLASS;

typedef enum class _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation		= 5,
	SystemExtendedHandleInformation	= 64
} SYSTEM_INFORMATION_CLASS;

typedef enum class _THREADINFOCLASS
{
	ThreadBasicInformation			= 0
} THREADINFOCLASS;

typedef enum class _KTHREAD_STATE : UCHAR
{
	Running = 0x02,
	Waiting = 0x05
} KTHREAD_STATE;

typedef enum class _KWAIT_REASON : UCHAR
{
	WrQueue = 0x0F
} KWAIT_REASON;


typedef enum _LDR_DDAG_STATE : int
{
	LdrModulesMerged					= -5,
	LdrModulesInitError					= -4,
	LdrModulesSnapError					= -3,
	LdrModulesUnloaded					= -2,
	LdrModulesUnloading					= -1,
	LdrModulesPlaceHolder				= 0,
	LdrModulesMapping					= 1,
	LdrModulesMapped					= 2,
	LdrModulesWaitingForDependencies	= 3,
	LdrModulesSnapping					= 4,
	LdrModulesSnapped					= 5,
	LdrModulesCondensed					= 6,
	LdrModulesReadyToInit				= 7,
	LdrModulesInitializing				= 8,
	LdrModulesReadyToRun				= 9
} LDR_DDAG_STATE, * PLDR_DDAG_STATE;

typedef enum _LDR_DLL_LOAD_REASON : int
{
	LoadReasonUnknown						= -1,
	LoadReasonStaticDependency				= 0,
	LoadReasonStaticForwarderDependency		= 1,
	LoadReasonDynamicForwarderDependency	= 2,
	LoadReasonDelayloadDependency			= 3,
	LoadReasonDynamicLoad					= 4,
	LoadReasonAsImageLoad					= 5,
	LoadReasonAsDataLoad					= 6,
	LoadReasonEnclavePrimary				= 7, 
	LoadReasonEnclaveDependency				= 8,
	LoadReasonPatchImage					= 9
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage		= 0,
    LdrHotPatchNotApplied		= 1,
    LdrHotPatchAppliedReverse	= 2,
    LdrHotPatchAppliedForward	= 3,
    LdrHotPatchFailedToPatch	= 4,
    LdrHotPatchStateMax			= 5
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

#pragma endregion

struct AMEGER_PEB;

typedef struct _ANSI_STRING
{
	USHORT	Length;
	USHORT	MaxLength;
	char *	szBuffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _UNICODE_STRING
{
	WORD		Length;
	WORD		MaxLength;
	wchar_t *	szBuffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _AMEGER_RTL_BALANCED_NODE
{
	union
	{
		struct _AMEGER_RTL_BALANCED_NODE * Children[2];
		struct
		{
			struct _AMEGER_RTL_BALANCED_NODE * Left;
			struct _AMEGER_RTL_BALANCED_NODE * Right;
		};
	};

	ULONG_PTR ParentValue;
} AMEGER_RTL_BALANCED_NODE, * PAMEGER_RTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE
{
	AMEGER_RTL_BALANCED_NODE * Root;
	AMEGER_RTL_BALANCED_NODE * Min;
} RTL_RB_TREE, * PRTL_RB_TREE;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PVOID		TebBaseAddress;
	CLIENT_ID	ClientId;
	KAFFINITY	AffinityMask;
	KPRIORITY	Priority;
	KPRIORITY	BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	AMEGER_PEB	*	pPEB;
	ULONG_PTR	AffinityMask;
	LONG		BasePriority;
	HANDLE		UniqueProcessId;
	HANDLE		InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER	KernelTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	CreateTime;
	ULONG			WaitTime;
	PVOID			StartAddress;
	CLIENT_ID		ClientId;
	KPRIORITY		Priority;
	LONG			BasePriority;
	ULONG			ContextSwitches;
	KTHREAD_STATE	ThreadState;
	KWAIT_REASON	WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG			NextEntryOffset;
	ULONG			NumberOfThreads;
	LARGE_INTEGER	WorkingSetPrivateSize;
	ULONG			HardFaultCount;
	ULONG			NumberOfThreadsHighWatermark;
	ULONGLONG		CycleTime;
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ImageName;
	KPRIORITY		BasePriority;
	HANDLE			UniqueProcessId;
	HANDLE			InheritedFromUniqueProcessId;
	ULONG			HandleCount;
	ULONG			SessionId;
	ULONG_PTR		UniqueProcessKey;
	SIZE_T			PeakVirtualSize;
	SIZE_T			VirtualSize;
	ULONG			PageFaultCount;
	SIZE_T 			PeakWorkingSetSize;
	SIZE_T			WorkingSetSize;
	SIZE_T			QuotaPeakPagedPoolUsage;
	SIZE_T 			QuotaPagedPoolUsage;
	SIZE_T 			QuotaPeakNonPagedPoolUsage;
	SIZE_T 			QuotaNonPagedPoolUsage;
	SIZE_T 			PagefileUsage;
	SIZE_T 			PeakPagefileUsage;
	SIZE_T 			PrivatePageCount;
	LARGE_INTEGER	ReadOperationCount;
	LARGE_INTEGER	WriteOperationCount;
	LARGE_INTEGER	OtherOperationCount;
	LARGE_INTEGER 	ReadTransferCount;
	LARGE_INTEGER	WriteTransferCount;
	LARGE_INTEGER	OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG				Length;
	HANDLE				RootDirectory;
	UNICODE_STRING *	ObjectName;
	ULONG				Attributes;
	PVOID				SecurityDescriptor;
	PVOID				SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS	Status;
		PVOID		Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _AMEGER_PEB_LDR_DATA
{
	ULONG		Length;
	BYTE		Initialized;
	HANDLE		SsHandle;
	LIST_ENTRY	InLoadOrderModuleListHead;
	LIST_ENTRY	InMemoryOrderModuleListHead;
	LIST_ENTRY	InInitializationOrderModuleListHead;
	PVOID		EntryInProgress;
	BYTE		ShutdownInProgress;
	HANDLE		ShutdownThreadId;
} AMEGER_PEB_LDR_DATA, * PAMEGER_PEB_LDR_DATA;

static_assert(sizeof(CLIENT_ID) == 16);
static_assert(sizeof(UNICODE_STRING) == 16);
static_assert(sizeof(ANSI_STRING) == 16);
static_assert(sizeof(AMEGER_RTL_BALANCED_NODE) == 24);
static_assert(sizeof(RTL_RB_TREE) == 16);
static_assert(sizeof(OBJECT_ATTRIBUTES) == 48);
static_assert(sizeof(IO_STATUS_BLOCK) == 16);
static_assert(sizeof(AMEGER_PEB_LDR_DATA) == 88);
static_assert(offsetof(AMEGER_PEB_LDR_DATA, InLoadOrderModuleListHead) == 16);
static_assert(offsetof(AMEGER_PEB_LDR_DATA, InMemoryOrderModuleListHead) == 32);
static_assert(offsetof(AMEGER_PEB_LDR_DATA, InInitializationOrderModuleListHead) == 48);

struct AMEGER_PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;

	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsedLargePages			: 1;
			UCHAR IsProtectedProcess			: 1;
			UCHAR IsImageDynamicallyRelocated	: 1;
			UCHAR SkipPatchingUser32Forwarders	: 1;
			UCHAR IsPackagedProcess				: 1;
			UCHAR IsAppContainer				: 1;
			UCHAR IsProtectedProcessLight		: 1;
			UCHAR IsLongPathAwareProcess		: 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;

	AMEGER_PEB_LDR_DATA * Ldr;

	PVOID					*	ProcessParameters;
	PVOID						SubSystemData;
	HANDLE						ProcessHeap;
	RTL_CRITICAL_SECTION	*	FastPebLock;
	PVOID						AtlThunkSListPtr;
	PVOID						IFEOKey;

	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob					: 1;
			ULONG ProcessInitializing			: 1;
			ULONG ProcessUsingVEH				: 1;
			ULONG ProcessUsingVCH				: 1;
			ULONG ProcessUsingFTH				: 1;
			ULONG ProcessPreviouslyThrottled	: 1;
			ULONG ProcessCurrentlyThrottled		: 1;
			ULONG ProcessImagesHotPatched		: 1;
			ULONG ReservedBits0					: 24;
		};
	};

	union


	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};

	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;

	UCHAR Padding2[4];

	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;

	union
	{
		PVOID HotpatchInformation;
		PVOID SparePvoid0;
		PVOID SharedData;
	};

	PVOID * ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG_PTR HeapSegmentReserve;
	ULONG_PTR HeapSegmentCommit;
	ULONG_PTR HeapDeCommitTotalFreeThreshold;
	ULONG_PTR HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID * ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	UCHAR Padding3[4];

	RTL_CRITICAL_SECTION * LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;

	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
};

static_assert(sizeof(AMEGER_PEB) == 296);
static_assert(offsetof(AMEGER_PEB, Mutant) == 8);
static_assert(offsetof(AMEGER_PEB, ImageBaseAddress) == 16);
static_assert(offsetof(AMEGER_PEB, Ldr) == 24);
static_assert(offsetof(AMEGER_PEB, ProcessParameters) == 32);
static_assert(offsetof(AMEGER_PEB, ProcessHeap) == 48);
static_assert(offsetof(AMEGER_PEB, CrossProcessFlags) == 80);
static_assert(offsetof(AMEGER_PEB, TlsExpansionCounter) == 112);
static_assert(offsetof(AMEGER_PEB, LoaderLock) == 272);
static_assert(offsetof(AMEGER_PEB, OSBuildNumber) == 288);

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD * Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	struct _SINGLE_LIST_ENTRY * Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef struct _LDRP_UNICODE_STRING_BUNDLE
{
	UNICODE_STRING	String;
	WCHAR			StaticBuffer[128];
} LDRP_UNICODE_STRING_BUNDLE, * PLDRP_UNICODE_STRING_BUNDLE;

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY
{
	IMAGE_RUNTIME_FUNCTION_ENTRY *	ExceptionDirectory;
	PVOID							ImageBase;
	ULONG							ImageSize;
	ULONG							ExceptionDirectorySize;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _RTL_INVERTED_FUNCTION_TABLE
{
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	UCHAR Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY Entries[ANYSIZE_ARRAY];
} RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;

typedef union _LDR_SEARCH_PATH
{
	BOOLEAN NoPath : 1;
	wchar_t * szSearchPath;
} LDR_SEARCH_PATH, * PLDR_SEARCH_PATH;

typedef struct _LDRP_PATH_SEARCH_CONTEXT
{
	wchar_t *	DllSearchPathOut;
	void	*	Unknown_0[3];
	wchar_t *	OriginalFullDllName;
	void	*	unknown_1[7];
	ULONG64		unknown_2[4];
} LDRP_PATH_SEARCH_CONTEXT, * PLDRP_PATH_SEARCH_CONTEXT;

typedef union _LDRP_LOAD_CONTEXT_FLAGS
{
	ULONG32 Flags;
	struct
	{
		ULONG32 Redirected					: 1;
		ULONG32 Static						: 1;
		ULONG32 BaseNameOnly				: 1;
		ULONG32 HasFullPath					: 1;
		ULONG32 KnownDll					: 1;
		ULONG32 SystemImage					: 1;
		ULONG32 ExecutableImage				: 1;
		ULONG32 AppContainerImage			: 1;
		ULONG32 CallInit					: 1;
		ULONG32 UserAllocated				: 1;
		ULONG32 SearchOnlyFirstPathSegment	: 1;
		ULONG32 RedirectedByAPISet			: 1;
	};
} LDRP_LOAD_CONTEXT_FLAGS, * PLDRP_LOAD_CONTEXT_FLAGS;


typedef struct _TLS_ENTRY
{
	LIST_ENTRY				TlsEntryLinks;
	IMAGE_TLS_DIRECTORY		TlsDirectory;
	PVOID 					ModuleEntry;
	SIZE_T					TlsIndex;
} TLS_ENTRY, * PTLS_ENTRY;

static_assert(sizeof(TLS_ENTRY) == 72);

