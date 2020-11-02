#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <fltkernel.h> 
#include <ntstatus.h>

#include <ntstrsafe.h>
#pragma comment(lib,"FltMgr.lib")

#define DEVICE_NAME  L"\\Device\\P_temp"
#define   LINK_PATH  L"\\??\\ppD_code"

#define TERMINATE_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x888,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SUPEND_CODE  CTL_CODE(FILE_DEVICE_UNKNOWN,0x970,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define RESUME_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x881,METHOD_BUFFERED,FILE_ANY_ACCESS)/*恢复进程*/
#define FORBID_DRIVER_CODE  CTL_CODE(FILE_DEVICE_UNKNOWN,0x911,METHOD_BUFFERED,FILE_ANY_ACCESS)/*禁止驱动文件加载*/
#define RECOVERY_DRIVER_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x912,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FORBID_PROCESS_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x913,METHOD_BUFFERED,FILE_ANY_ACCESS)/*禁止进程创建*/
#define RECOVERY_PROCESS_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x914,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define DELETE_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x915,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define GETPROCESS_PId_CODE  CTL_CODE(FILE_DEVICE_UNKNOWN,0x916,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define PROCESSPROCECT_CODE  CTL_CODE(FILE_DEVICE_UNKNOWN,0x917,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define Write_code  CTL_CODE(FILE_DEVICE_UNKNOWN,0x923,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define  Read_code   CTL_CODE(FILE_DEVICE_UNKNOWN,0x924,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define Module_code CTL_CODE(FILE_DEVICE_UNKNOWN,0x925,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define Delete_code CTL_CODE(FILE_DEVICE_UNKNOWN,0x918,METHOD_BUFFERED,FILE_ANY_ACCESS)/*char类型的*/

NTKERNELAPI  PCHAR  PsGetProcessImageFileName(_In_ PEPROCESS process);

NTKERNELAPI  NTSTATUS PsSuspendProcess(_In_ PEPROCESS process);/*暂停进程	*/
															 
NTKERNELAPI  NTSTATUS PsResumeProcess(PEPROCESS Process);/*恢复进程*/

NTKERNELAPI PVOID PsGetProcessPeb(PEPROCESS Process);

NTKERNELAPI PEPROCESS IoThreadToProcess(IN PETHREAD Thread);

#define MAX_PATH 255
/**/
#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  

#define PROCESS_VM_WRITE          0x0020
#define PROCESS_ALL_ACCESS_THREAD        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | THREAD_ALL_ACCESS|0xFFFF)
/**/
#define WINXP  51
#define WINXP2600 212600

#define WIN7   61
#define WIN77600 617600
#define WIN77601 617601

#define WIN8   62
#define WIN89200 629200

#define WIN81  63
#define WIN819600  639600

#define WIN10  100
#define WIN1010240 10010240
#define WIN1010586 10010586
#define WIN1014393 10014393

#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')

#define REGISTRY_POOL_TAG 'lxw'

NTSTATUS  NTAPI  ZwQuerySystemInformation(IN ULONG SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);

NTSTATUS CreateDervice(PDRIVER_OBJECT driverObject);
NTSTATUS DispatchRead(PDEVICE_OBJECT device, IRP *p);
NTSTATUS DispatchControl(PDEVICE_OBJECT device, IRP *p);


typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientIs;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   ThreadState;
	KWAIT_REASON            WaitReason;
}SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES
{
	ULONG                           NextEntryDelta;    //链表下一个结构和上一个结构的偏移
	ULONG                           ThreadCount;
	ULONG                           Reserved[6];
	LARGE_INTEGER                   CreateTime;
	LARGE_INTEGER                   UserTime;
	

	UNICODE_STRING                  ProcessName;     //进程名字
	KPRIORITY                       BasePriority;
	ULONG                           ProcessId;      //进程的pid号
	ULONG                           InheritedFromProcessId;
	ULONG                           HandleCount;
	ULONG                           Reserved2[2];
	VM_COUNTERS                     VmCounters;
	IO_COUNTERS                     IoCounters; //windows 2000 only  
	struct _SYSTEM_THREADS          Threads[1];
}SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	ULONG Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID	EntryInProgress;
	ULONG	ShutdownInProgress;
	PVOID	ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

/*写*/
typedef struct WRITEPROCESS
{
	ULONG Pid;
	unsigned long long Address;/*地址*/
	VOID *Data;
}*PWRITEPROCESS, UWRITEPROCESS;

/*读*/
typedef struct PROCESS_READ
{
	ULONG Pid;/*Pid*/
	unsigned long long Address;/*地址*/
}*PPROCESS_READ, UPROCESS_READ;

/*取模块地址*/
typedef struct Module
{
	ULONG Pid;
	CHAR ModuleName[100];
}UMODULE, *PMODULE;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY    InLoadOrderLinks;
	LIST_ENTRY    InMemoryOrderLinks;
	LIST_ENTRY    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY    ForwarderLinks;
	LIST_ENTRY    ServiceTagLinks;
	LIST_ENTRY    StaticLinks;
	PVOID            ContextInformation;
	ULONG            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _MYPEB
{
	union
	{
		struct dummy00
		{
			UCHAR InheritedAddressSpace;
			UCHAR ReadImageFileExecOptions;
			UCHAR BeingDebugged;
			UCHAR BitField;
		};
		PVOID dummy01;
	};

	PVOID Mutant;
	PVOID ImageBaseAddress;
	PVOID Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} MYPEB, *PMYPEB;

typedef int(*LDE_DISASM)(void *p, int dw);
LDE_DISASM LDE;

VOID  ForibidImage(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);

KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

BOOLEAN  RemoveDriverFile(PVOID Image);

BOOLEAN RemoveDLLFile(PVOID ImageBase);

NTSTATUS Dispath_Attach(PDEVICE_OBJECT device, IRP *p);

ULONG64 GetProcessModuleHandle(ULONG pid, PUNICODE_STRING ModuleName);

NTSTATUS KeTerminateProcess(ULONG Pid);

VOID  ForibidProcess(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);

void MyTheadProc(PVOID context);

void MyModuleProc(PVOID context);/**/

NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath);

NTSTATUS KeSetRegeditValue(PUNICODE_STRING Regeditpath, WCHAR New_path[]);/*设置驱动自启动*/


NTSTATUS KeCopyFile(PCWSTR FilePath/*起始文件的目录*/, PCWSTR CopyFilePath/*要复制的文件的目录*/);

/*通过进程名字获取到进程Pid*/
HANDLE PsGetProcessPid(WCHAR * ProcessName);

/*获取系统版本*/
inline unsigned KeGetVersoin();

PVOID ReadProcessMemroy(ULONG Pid, unsigned long long Address);

VOID  WriteProcessMemroy(ULONG Pid, unsigned long long  Address, VOID * Data);

NTSTATUS RegistryCallback(IN PVOID CallbackContext, IN PVOID Argument1, IN PVOID Argument2);/*注册表回调*/

BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PUNICODE_STRING pPartialRegistryPath, PVOID pRegistryObject);

NTSTATUS PsProcectProcess(_In_ PDRIVER_OBJECT driver);

OB_PREOP_CALLBACK_STATUS  PsProtectProcessEx(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

OB_PREOP_CALLBACK_STATUS  PsProtectThreadEx(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

ULONG GetPatchSize2(PUCHAR Address)
{
	ULONG LenCount = 0, Len = 0;
	while (LenCount <= 14)        //至少需要14字节
	{
		Len = LDE(Address, 64);
		Address = Address + Len;
		LenCount = LenCount + Len;
	}
	return LenCount;
}




FLT_PREOP_CALLBACK_STATUS NPPreCreate
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);
/**/
FLT_POSTOP_CALLBACK_STATUS NPPostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
 }

FLT_POSTOP_CALLBACK_STATUS NPPostWrite
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS NPPreWrite
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS NPPreRead
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS NPPreSetInformation
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS NPPostSetInformation
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
};

FLT_POSTOP_CALLBACK_STATUS NPPostRead
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
};

NTSTATUS         InitializeMiniReg(PUNICODE_STRING  pdriver_regpath);